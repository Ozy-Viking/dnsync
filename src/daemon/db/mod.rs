//! Daemon-specific SQLite state storage using Diesel + r2d2.
//!
//! No DNS logic lives here — this module is purely responsible for persisting
//! daemon health snapshots, job status, and append-only job run history.

pub mod migrations;
pub mod models;
pub mod schema;
pub mod store;

use std::path::Path;

use diesel::r2d2::{ConnectionManager, Pool};
use diesel::sqlite::SqliteConnection;

/// A single-writer connection pool for the daemon state database.
pub type DbPool = Pool<ConnectionManager<SqliteConnection>>;

/// Open or create the SQLite state database at `path` and return a pooled connection.
///
/// Runs the schema migrations before returning; the included migration SQL enables
/// SQLite WAL mode when the database file is first created so the first connection
/// applies that setting.
///
/// # Examples
///
/// ```text
/// let pool = daemon::db::open(std::path::Path::new("state.db")).unwrap();
/// let conn = pool.get().unwrap();
/// // use `conn` with Diesel queries...
/// ```
pub fn open(path: &Path) -> Result<DbPool, String> {
    // Ensure the parent directory exists.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("could not create state db directory: {e}"))?;
    }

    let url = path.to_str().ok_or("state_db path is not valid UTF-8")?;

    let manager = ConnectionManager::<SqliteConnection>::new(url);

    // max_size=1: SQLite is a single-writer database; WAL handles concurrent
    // readers from outside the process.
    let pool = Pool::builder()
        .max_size(1)
        .build(manager)
        .map_err(|e| format!("could not open state db '{}': {e}", path.display()))?;

    let mut conn = pool
        .get()
        .map_err(|e| format!("could not get db connection: {e}"))?;

    migrations::run_migrations(&mut conn).map_err(|e| format!("migration failed: {e}"))?;

    Ok(pool)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::db::models::{DaemonHealthRow, JobRunRow, JobStatusRow};
    use crate::daemon::db::schema::{daemon_health, job_runs, job_status};
    use diesel::prelude::*;

    /// Creates and opens a temporary file-backed SQLite database and returns its connection pool.
    ///
    /// The database file is placed in a per-process subdirectory of the system temporary directory
    /// and named with a UUID to avoid collisions. A file-backed database is used instead of
    /// `:memory:` so multiple r2d2 connections share the same database.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let pool = open_test_db();
    /// // use `pool` for tests that need a fresh, file-backed SQLite database
    /// ```
    fn open_test_db() -> DbPool {
        let dir = std::env::temp_dir().join(format!("dnsync-db-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Use a unique name per test invocation via a random suffix from uuid.
        let path = dir.join(format!("test-{}.sqlite", uuid::Uuid::new_v4().as_simple()));
        open(&path).expect("test db should open")
    }

    fn sample_health_row() -> DaemonHealthRow {
        DaemonHealthRow {
            id: 1,
            daemon_id: "daemon-abc".to_string(),
            started_at: "2026-01-01T00:00:00Z".to_string(),
            last_heartbeat_at: "2026-01-01T00:01:00Z".to_string(),
            daemon_state: "live".to_string(),
            overall_health: "healthy".to_string(),
            last_health_change_at: "2026-01-01T00:00:00Z".to_string(),
            last_error_summary: None,
            jobs_total: 3,
            jobs_enabled: 3,
            jobs_healthy: 3,
            jobs_degraded: 0,
            jobs_running: 0,
        }
    }

    /// Creates a sample `JobStatusRow` populated with typical test values.
    ///
    /// The returned row has `job_id` set to the provided value, `job_kind` set to `"sync"`,
    /// `current_state` set to `"healthy"`, `enabled` set to `1`, `consecutive_failures` set to `0`,
    /// and all timestamp and error fields set to `None`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let row = sample_job_status_row("job-1");
    /// assert_eq!(row.job_id, "job-1");
    /// assert_eq!(row.job_kind, "sync");
    /// assert_eq!(row.current_state, "healthy");
    /// assert_eq!(row.consecutive_failures, 0);
    /// assert!(row.last_started_at.is_none());
    /// ```
    fn sample_job_status_row(job_id: &str) -> JobStatusRow {
        JobStatusRow {
            job_id: job_id.to_string(),
            job_kind: "sync".to_string(),
            enabled: 1,
            current_state: "healthy".to_string(),
            last_started_at: None,
            last_finished_at: None,
            last_success_at: None,
            last_failure_at: None,
            last_error_summary: None,
            consecutive_failures: 0,
            last_run_id: None,
        }
    }

    fn sample_job_run_row(run_id: &str, job_id: &str) -> JobRunRow {
        JobRunRow {
            run_id: run_id.to_string(),
            job_id: job_id.to_string(),
            job_kind: "sync".to_string(),
            trigger_kind: "scheduled".to_string(),
            started_at: "2026-01-01T00:00:00Z".to_string(),
            finished_at: Some("2026-01-01T00:00:05Z".to_string()),
            outcome: Some("success".to_string()),
            error_summary: None,
            duration_ms: Some(5000),
        }
    }

    // ── open ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_open_creates_db_and_tables() {
        // Simply opening the DB should succeed and not panic.
        let _pool = open_test_db();
    }

    // ── daemon_health ─────────────────────────────────────────────────────────

    #[test]
    fn test_upsert_and_read_daemon_health() {
        let pool = open_test_db();
        let mut conn = pool.get().unwrap();

        let row = sample_health_row();

        diesel::insert_into(daemon_health::table)
            .values(&row)
            .on_conflict(daemon_health::id)
            .do_update()
            .set(&row)
            .execute(&mut conn)
            .expect("insert daemon_health");

        let fetched: DaemonHealthRow = daemon_health::table
            .find(1)
            .first(&mut conn)
            .expect("read daemon_health");

        assert_eq!(fetched.daemon_id, "daemon-abc");
        assert_eq!(fetched.overall_health, "healthy");
        assert_eq!(fetched.jobs_total, 3);
        assert_eq!(fetched.last_error_summary, None);
    }

    #[test]
    fn test_upsert_daemon_health_updates_existing() {
        let pool = open_test_db();
        let mut conn = pool.get().unwrap();

        let row = sample_health_row();
        diesel::insert_into(daemon_health::table)
            .values(&row)
            .on_conflict(daemon_health::id)
            .do_update()
            .set(&row)
            .execute(&mut conn)
            .expect("first insert");

        // Update to degraded.
        let updated = DaemonHealthRow {
            overall_health: "degraded".to_string(),
            jobs_degraded: 1,
            jobs_healthy: 2,
            ..row
        };
        diesel::insert_into(daemon_health::table)
            .values(&updated)
            .on_conflict(daemon_health::id)
            .do_update()
            .set(&updated)
            .execute(&mut conn)
            .expect("upsert daemon_health");

        let fetched: DaemonHealthRow = daemon_health::table
            .find(1)
            .first(&mut conn)
            .expect("read daemon_health after update");

        assert_eq!(fetched.overall_health, "degraded");
        assert_eq!(fetched.jobs_degraded, 1);
        assert_eq!(fetched.jobs_healthy, 2);
    }

    // ── job_status ────────────────────────────────────────────────────────────

    #[test]
    fn test_insert_and_read_job_status() {
        let pool = open_test_db();
        let mut conn = pool.get().unwrap();

        let row = sample_job_status_row("job-1");
        diesel::insert_into(job_status::table)
            .values(&row)
            .execute(&mut conn)
            .expect("insert job_status");

        let fetched: JobStatusRow = job_status::table
            .find("job-1")
            .first(&mut conn)
            .expect("read job_status");

        assert_eq!(fetched.job_id, "job-1");
        assert_eq!(fetched.job_kind, "sync");
        assert_eq!(fetched.current_state, "healthy");
        assert_eq!(fetched.consecutive_failures, 0);
    }

    #[test]
    fn test_upsert_job_status_updates_on_conflict() {
        let pool = open_test_db();
        let mut conn = pool.get().unwrap();

        let row = sample_job_status_row("job-2");
        diesel::insert_into(job_status::table)
            .values(&row)
            .execute(&mut conn)
            .expect("first insert job_status");

        let updated = JobStatusRow {
            consecutive_failures: 3,
            current_state: "degraded".to_string(),
            ..row
        };
        diesel::insert_into(job_status::table)
            .values(&updated)
            .on_conflict(job_status::job_id)
            .do_update()
            .set(&updated)
            .execute(&mut conn)
            .expect("upsert job_status");

        let fetched: JobStatusRow = job_status::table
            .find("job-2")
            .first(&mut conn)
            .expect("read updated job_status");

        assert_eq!(fetched.consecutive_failures, 3);
        assert_eq!(fetched.current_state, "degraded");
    }

    // ── job_runs ──────────────────────────────────────────────────────────────

    #[test]
    fn test_insert_job_run_and_query_by_job_id() {
        let pool = open_test_db();
        let mut conn = pool.get().unwrap();

        let run1 = sample_job_run_row("run-1", "job-x");
        let run2 = sample_job_run_row("run-2", "job-x");
        let run3 = sample_job_run_row("run-3", "job-y"); // different job

        diesel::insert_into(job_runs::table)
            .values(&run1)
            .execute(&mut conn)
            .unwrap();
        diesel::insert_into(job_runs::table)
            .values(&run2)
            .execute(&mut conn)
            .unwrap();
        diesel::insert_into(job_runs::table)
            .values(&run3)
            .execute(&mut conn)
            .unwrap();

        let results: Vec<JobRunRow> = job_runs::table
            .filter(job_runs::job_id.eq("job-x"))
            .load(&mut conn)
            .expect("query job_runs");

        assert_eq!(results.len(), 2);
        let ids: Vec<&str> = results.iter().map(|r| r.run_id.as_str()).collect();
        assert!(ids.contains(&"run-1"));
        assert!(ids.contains(&"run-2"));
    }

    // ── WAL mode ──────────────────────────────────────────────────────────────

    #[derive(diesel::QueryableByName, Debug)]
    struct PragmaRow {
        #[diesel(sql_type = diesel::sql_types::Text)]
        journal_mode: String,
    }

    #[test]
    fn test_wal_mode_is_enabled() {
        let pool = open_test_db();
        let mut conn = pool.get().unwrap();

        let result: Vec<PragmaRow> = diesel::sql_query("PRAGMA journal_mode")
            .load(&mut conn)
            .expect("pragma query");

        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].journal_mode, "wal",
            "expected WAL mode, got: {}",
            result[0].journal_mode
        );
    }
}
