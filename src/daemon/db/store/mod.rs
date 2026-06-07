//! `DaemonStateStore` — high-level read/write facade over [`DbPool`].
//!
//! All methods are synchronous (intended to be called via `spawn_blocking`
//! from an async context). No DNS logic lives here.

use diesel::prelude::*;
use tracing::{debug, instrument};

use super::DbPool;
use super::models::{DaemonHealthRow, JobRunRow, JobStatusRow};
use super::schema::{daemon_health, job_runs, job_status};

mod ledger;

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
mod tests;
