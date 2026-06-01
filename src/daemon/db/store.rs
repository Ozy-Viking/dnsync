//! `DaemonStateStore` — high-level read/write facade over [`DbPool`].
//!
//! All methods are synchronous (intended to be called via `spawn_blocking`
//! from an async context). No DNS logic lives here.

use diesel::prelude::*;
use tracing::{debug, instrument};

use super::DbPool;
use super::models::{DaemonHealthRow, JobRunRow, JobStatusRow};
use super::schema::{daemon_health, job_runs, job_status};

/// A thin façade over a [`DbPool`] that handles persisting daemon health
/// snapshots, per-job status, and append-only job run history.
pub struct DaemonStateStore {
    pool: DbPool,
}

impl DaemonStateStore {
    /// Constructs a DaemonStateStore that wraps the provided database connection pool.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Obtain a DbPool (example placeholder) and create the store.
    /// let pool = /* obtain DbPool */ unimplemented!();
    /// let _store = DaemonStateStore::new(pool);
    /// ```
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Upserts the daemon health singleton row (id = 1).
    ///
    /// Inserts the provided `row` into the `daemon_health` table or updates the existing singleton record with the same id.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, `Err(String)` containing an error message if acquiring a DB connection or executing the query fails.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let store = DaemonStateStore::new(pool);
    /// let row = DaemonHealthRow { id: 1, daemon_state: "Running".into(), overall_health: "Good".into(), /* ... */ };
    /// store.save_daemon_health(row).unwrap();
    /// ```
    #[instrument(level = "debug", skip(self, row), fields(daemon_state = %row.daemon_state, overall_health = %row.overall_health))]
    pub fn save_daemon_health(&self, row: DaemonHealthRow) -> Result<(), String> {
        debug!(daemon_state = %row.daemon_state, overall_health = %row.overall_health, "DB write: save_daemon_health");
        let mut conn = self.pool.get().map_err(|e| format!("db pool error: {e}"))?;

        diesel::insert_into(daemon_health::table)
            .values(&row)
            .on_conflict(daemon_health::id)
            .do_update()
            .set(&row)
            .execute(&mut conn)
            .map_err(|e| format!("save_daemon_health failed: {e}"))?;

        debug!("DB write: save_daemon_health succeeded");
        Ok(())
    }

    /// Insert or update a job status row using the row's `job_id` as the unique key.
    ///
    /// On success the database will contain the provided `JobStatusRow`; on conflict the existing
    /// row for the same `job_id` is replaced with the provided values.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let store = open_test_store();
    /// let row = sample_job_status("example-job");
    /// store.save_job_status(row).expect("save should succeed");
    /// ```
    ///
    /// Returns `Ok(())` on success, `Err(String)` with a human-readable message on failure.
    #[instrument(level = "debug", skip(self, row), fields(job_id = %row.job_id, current_state = %row.current_state))]
    pub fn save_job_status(&self, row: JobStatusRow) -> Result<(), String> {
        debug!(job_id = %row.job_id, current_state = %row.current_state, consecutive_failures = row.consecutive_failures, "DB write: save_job_status");
        let mut conn = self.pool.get().map_err(|e| format!("db pool error: {e}"))?;

        diesel::insert_into(job_status::table)
            .values(&row)
            .on_conflict(job_status::job_id)
            .do_update()
            .set(&row)
            .execute(&mut conn)
            .map_err(|e| format!("save_job_status failed: {e}"))?;

        debug!(job_id = %row.job_id, "DB write: save_job_status succeeded");
        Ok(())
    }

    /// Inserts a job run into the immutable per-job run history.
    ///
    /// This performs an insert-only append of `row` into the `job_runs` table.
    /// The run history is treated as immutable; conflicts are not handled.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // `store` must be an initialized `DaemonStateStore` and `JobRunRow` must be available in scope.
    /// let row = JobRunRow {
    ///     run_id: "run-1".into(),
    ///     job_id: "job-a".into(),
    ///     started_at: chrono::Utc::now(),
    ///     outcome: Some("success".into()),
    ///     duration_ms: Some(150),
    ///     // fill other fields as required by `JobRunRow`
    /// };
    ///
    /// store.append_job_run(row).expect("append_job_run failed");
    /// ```
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, `Err(String)` with an error message on failure.
    #[instrument(level = "debug", skip(self, row), fields(run_id = %row.run_id, job_id = %row.job_id))]
    pub fn append_job_run(&self, row: JobRunRow) -> Result<(), String> {
        debug!(run_id = %row.run_id, job_id = %row.job_id, outcome = ?row.outcome, duration_ms = ?row.duration_ms, "DB write: append_job_run");
        let mut conn = self.pool.get().map_err(|e| format!("db pool error: {e}"))?;

        diesel::insert_into(job_runs::table)
            .values(&row)
            .execute(&mut conn)
            .map_err(|e| format!("append_job_run failed: {e}"))?;

        debug!(run_id = %row.run_id, "DB write: append_job_run succeeded");
        Ok(())
    }

    /// Retrieves the persisted daemon health snapshot for the singleton record.
    ///
    /// Returns `Some(DaemonHealthRow)` if the record exists, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let store = open_test_store(); // helper that returns a DaemonStateStore
    /// let health = store.load_daemon_health().unwrap();
    /// if let Some(row) = health {
    ///     println!("last_seen: {}", row.last_seen);
    /// }
    /// ```
    #[instrument(level = "debug", skip(self))]
    pub fn load_daemon_health(&self) -> Result<Option<DaemonHealthRow>, String> {
        debug!("DB read: load_daemon_health");
        let mut conn = self.pool.get().map_err(|e| format!("db pool error: {e}"))?;

        let row = daemon_health::table
            .find(1)
            .first::<DaemonHealthRow>(&mut conn)
            .optional()
            .map_err(|e| format!("load_daemon_health failed: {e}"))?;

        debug!(
            found = row.is_some(),
            "DB read: load_daemon_health complete"
        );
        Ok(row)
    }

    /// Loads the current status for the job identified by `job_id`.
    ///
    /// # Returns
    ///
    /// `Ok(Some(JobStatusRow))` if a status row exists for `job_id`, `Ok(None)` if no row is found, or `Err(String)` if a database error occurs.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use crate::daemon::db::store::DaemonStateStore;
    /// # let store: DaemonStateStore = unimplemented!();
    /// let status = store.load_job_status("job-123").unwrap();
    /// if let Some(row) = status {
    ///     println!("found status for job: {}", row.job_id);
    /// } else {
    ///     println!("no status for job-123");
    /// }
    /// ```
    #[instrument(level = "debug", skip(self), fields(job_id))]
    pub fn load_job_status(&self, job_id: &str) -> Result<Option<JobStatusRow>, String> {
        debug!(job_id, "DB read: load_job_status");
        let mut conn = self.pool.get().map_err(|e| format!("db pool error: {e}"))?;

        let row = job_status::table
            .find(job_id)
            .first::<JobStatusRow>(&mut conn)
            .optional()
            .map_err(|e| format!("load_job_status failed: {e}"))?;

        debug!(
            job_id,
            found = row.is_some(),
            "DB read: load_job_status complete"
        );
        Ok(row)
    }

    /// Load up to `limit` run history rows for `job_id`, ordered by `started_at` descending (most recent first).
    ///
    /// The returned vector contains at most `limit` rows filtered to the given `job_id`; it may be empty if no runs exist.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let runs = store.load_job_runs("my-job", 5).unwrap();
    /// // at most 5 most recent runs for "my-job"
    /// assert!(runs.len() <= 5);
    /// ```
    #[instrument(level = "debug", skip(self), fields(job_id, limit))]
    pub fn load_job_runs(&self, job_id: &str, limit: usize) -> Result<Vec<JobRunRow>, String> {
        debug!(job_id, limit, "DB read: load_job_runs");
        let mut conn = self.pool.get().map_err(|e| format!("db pool error: {e}"))?;

        let rows = job_runs::table
            .filter(job_runs::job_id.eq(job_id))
            .order((job_runs::started_at.desc(), job_runs::run_id.desc()))
            .limit(limit as i64)
            .load::<JobRunRow>(&mut conn)
            .map_err(|e| format!("load_job_runs failed: {e}"))?;

        debug!(
            job_id,
            row_count = rows.len(),
            "DB read: load_job_runs complete"
        );
        Ok(rows)
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::db;

    /// Create a temporary, file-backed SQLite database and return a `DaemonStateStore` that uses it.
    ///
    /// The database is created in the system temporary directory and uniquely named so tests can run
    /// in isolation.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let store = open_test_store();
    /// // use `store` in tests; the database is scoped to a temporary file.
    /// ```
    fn open_test_store() -> DaemonStateStore {
        let dir = std::env::temp_dir().join(format!("dnsync-store-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("test-{}.sqlite", uuid::Uuid::new_v4().as_simple()));
        let pool = db::open(&path).expect("test db should open");
        DaemonStateStore::new(pool)
    }

    /// Creates a sample `DaemonHealthRow` populated with consistent example values.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let row = sample_health_row();
    /// assert_eq!(row.id, 1);
    /// assert_eq!(row.daemon_id, "daemon-xyz");
    /// assert_eq!(row.daemon_state, "live");
    /// assert_eq!(row.overall_health, "healthy");
    /// ```
    fn sample_health_row() -> DaemonHealthRow {
        DaemonHealthRow {
            id: 1,
            daemon_id: "daemon-xyz".to_string(),
            started_at: "2026-01-01T00:00:00Z".to_string(),
            last_heartbeat_at: "2026-01-01T00:01:00Z".to_string(),
            daemon_state: "live".to_string(),
            overall_health: "healthy".to_string(),
            last_health_change_at: "2026-01-01T00:00:00Z".to_string(),
            last_error_summary: None,
            jobs_total: 4,
            jobs_enabled: 4,
            jobs_healthy: 4,
            jobs_degraded: 0,
            jobs_running: 0,
        }
    }

    /// Creates a sample `JobStatusRow` populated with deterministic default values for the given job ID.
    ///
    /// Useful for tests that need a consistent, fully-populated job status row with no prior runs or failures.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let row = sample_job_status("job-123");
    /// assert_eq!(row.job_id, "job-123");
    /// assert_eq!(row.job_kind, "sync");
    /// assert_eq!(row.enabled, 1);
    /// assert_eq!(row.current_state, "healthy");
    /// assert_eq!(row.consecutive_failures, 0);
    /// ```
    fn sample_job_status(job_id: &str) -> JobStatusRow {
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

    /// Builds a test JobRunRow with the given run id, job id, and start timestamp.
    ///
    /// `run_id` is the run identifier, `job_id` is the job identifier, and `started_at` is a timestamp string (e.g. ISO-8601).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let r = sample_job_run("run-1", "job-a", "2023-01-01T00:00:00Z");
    /// assert_eq!(r.run_id, "run-1");
    /// assert_eq!(r.job_id, "job-a");
    /// assert_eq!(r.started_at, "2023-01-01T00:00:00Z");
    /// assert_eq!(r.finished_at.as_deref(), Some("2023-01-01T00:00:00Z"));
    /// assert_eq!(r.outcome.as_deref(), Some("success"));
    /// ```
    fn sample_job_run(run_id: &str, job_id: &str, started_at: &str) -> JobRunRow {
        JobRunRow {
            run_id: run_id.to_string(),
            job_id: job_id.to_string(),
            job_kind: "sync".to_string(),
            trigger_kind: "scheduled".to_string(),
            started_at: started_at.to_string(),
            finished_at: Some(format!("{started_at}")),
            outcome: Some("success".to_string()),
            error_summary: None,
            duration_ms: Some(100),
        }
    }

    // ── save / load daemon health ─────────────────────────────────────────────

    #[test]
    fn test_save_and_load_daemon_health() {
        let store = open_test_store();
        let row = sample_health_row();

        store.save_daemon_health(row.clone()).unwrap();

        let loaded = store
            .load_daemon_health()
            .unwrap()
            .expect("should have a row");
        assert_eq!(loaded.daemon_id, "daemon-xyz");
        assert_eq!(loaded.overall_health, "healthy");
        assert_eq!(loaded.jobs_total, 4);
        assert_eq!(loaded.last_error_summary, None);
    }

    #[test]
    fn test_save_daemon_health_upserts() {
        let store = open_test_store();
        let row = sample_health_row();

        store.save_daemon_health(row.clone()).unwrap();

        // Save again with updated values.
        let updated = DaemonHealthRow {
            overall_health: "degraded".to_string(),
            jobs_degraded: 2,
            jobs_healthy: 2,
            last_error_summary: Some("zone sync failed".to_string()),
            ..row
        };
        store.save_daemon_health(updated).unwrap();

        let loaded = store
            .load_daemon_health()
            .unwrap()
            .expect("should have row");
        assert_eq!(loaded.overall_health, "degraded");
        assert_eq!(loaded.jobs_degraded, 2);
        assert_eq!(loaded.jobs_healthy, 2);
        assert_eq!(
            loaded.last_error_summary.as_deref(),
            Some("zone sync failed")
        );
    }

    // ── save / load job status ────────────────────────────────────────────────

    #[test]
    fn test_save_and_load_job_status() {
        let store = open_test_store();
        let row = sample_job_status("job-alpha");

        store.save_job_status(row).unwrap();

        let loaded = store
            .load_job_status("job-alpha")
            .unwrap()
            .expect("should have job status");
        assert_eq!(loaded.job_id, "job-alpha");
        assert_eq!(loaded.current_state, "healthy");
        assert_eq!(loaded.consecutive_failures, 0);
        assert_eq!(loaded.enabled, 1);
    }

    #[test]
    fn test_save_job_status_upserts() {
        let store = open_test_store();
        let row = sample_job_status("job-beta");

        store.save_job_status(row.clone()).unwrap();

        let updated = JobStatusRow {
            current_state: "degraded".to_string(),
            consecutive_failures: 5,
            last_error_summary: Some("timeout".to_string()),
            ..row
        };
        store.save_job_status(updated).unwrap();

        let loaded = store
            .load_job_status("job-beta")
            .unwrap()
            .expect("should have job status after upsert");
        assert_eq!(loaded.current_state, "degraded");
        assert_eq!(loaded.consecutive_failures, 5);
        assert_eq!(loaded.last_error_summary.as_deref(), Some("timeout"));
    }

    // ── append / load job runs ────────────────────────────────────────────────

    #[test]
    fn test_append_and_load_job_runs() {
        let store = open_test_store();

        // Insert 3 runs with distinct started_at timestamps.
        store
            .append_job_run(sample_job_run("run-1", "job-a", "2026-01-01T00:00:01Z"))
            .unwrap();
        store
            .append_job_run(sample_job_run("run-2", "job-a", "2026-01-01T00:00:02Z"))
            .unwrap();
        store
            .append_job_run(sample_job_run("run-3", "job-a", "2026-01-01T00:00:03Z"))
            .unwrap();

        // Load all 3 — should be ordered most-recent first.
        let runs = store.load_job_runs("job-a", 10).unwrap();
        assert_eq!(runs.len(), 3);
        assert_eq!(runs[0].run_id, "run-3"); // most recent
        assert_eq!(runs[1].run_id, "run-2");
        assert_eq!(runs[2].run_id, "run-1");

        // Limit to 2.
        let limited = store.load_job_runs("job-a", 2).unwrap();
        assert_eq!(limited.len(), 2);
        assert_eq!(limited[0].run_id, "run-3");
        assert_eq!(limited[1].run_id, "run-2");
    }

    #[test]
    fn test_load_job_runs_for_different_jobs() {
        let store = open_test_store();

        store
            .append_job_run(sample_job_run("run-x1", "job-x", "2026-01-01T00:00:01Z"))
            .unwrap();
        store
            .append_job_run(sample_job_run("run-x2", "job-x", "2026-01-01T00:00:02Z"))
            .unwrap();
        store
            .append_job_run(sample_job_run("run-y1", "job-y", "2026-01-01T00:00:01Z"))
            .unwrap();

        // job-x runs should not bleed into job-y results.
        let x_runs = store.load_job_runs("job-x", 10).unwrap();
        assert_eq!(x_runs.len(), 2);
        assert!(x_runs.iter().all(|r| r.job_id == "job-x"));

        let y_runs = store.load_job_runs("job-y", 10).unwrap();
        assert_eq!(y_runs.len(), 1);
        assert_eq!(y_runs[0].run_id, "run-y1");
    }

    // ── missing data returns None ─────────────────────────────────────────────

    #[test]
    fn test_load_nonexistent_returns_none() {
        let store = open_test_store();

        // Empty DB: daemon health singleton has never been saved.
        let health = store.load_daemon_health().unwrap();
        assert!(
            health.is_none(),
            "expected None for empty daemon_health table"
        );

        // Unknown job id.
        let status = store.load_job_status("no-such-job").unwrap();
        assert!(status.is_none(), "expected None for unknown job_id");

        // Unknown job id for runs.
        let runs = store.load_job_runs("no-such-job", 10).unwrap();
        assert!(
            runs.is_empty(),
            "expected empty vec for unknown job_id runs"
        );
    }
}
