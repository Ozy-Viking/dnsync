//! Async worker pool connecting the scheduler to job executors.
//!
//! Architecture:
//!   scheduler (ticks) → job_tx (bounded mpsc) → worker pool (N workers) → executor.execute()
//!                                                         ↓
//!                                               db_write_tx (mpsc) → DB writer task → DaemonStateStore

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, trace, warn};

use crate::daemon::{
    db::{
        models::{JobRunRow, JobStatusRow},
        store::DaemonStateStore,
    },
    executor::{JobContext, JobExecutor, JobOutcome},
    scheduler::JobTrigger,
};

// ─── DbWriteRequest ────────────────────────────────────────────────────────────

/// Sent by workers to the DB writer task after a job finishes.
pub enum DbWriteRequest {
    JobRun(JobRunRow),
    JobStatus(JobStatusRow),
}

// ─── spawn_workers ─────────────────────────────────────────────────────────────

/// Spawn a pool of worker tasks that consume `JobTrigger`s from a bounded queue,
/// execute them via job-specific `JobExecutor`s, and forward `JobRun` and `JobStatus`
/// write requests to the provided DB writer channel.
///
/// The returned `mpsc::Sender<JobTrigger>` is the enqueue handle for submitting jobs.
/// Workers share a single receiver protected by an async mutex and exit when the job
/// channel is closed.
///
/// # Examples
///
/// ```text
/// use std::sync::Arc;
/// use tokio::sync::mpsc;
/// use daemon::worker::{spawn_workers, DbWriteRequest, JobTrigger};
///
/// // A trivial executor factory that never finds an executor.
/// let executors: Arc<dyn Fn(&str) -> Option<std::sync::Arc<dyn daemon::worker::JobExecutor>> + Send + Sync> =
///     Arc::new(|_id| None);
///
/// #[tokio::main]
/// async fn main() {
///     let (db_write_tx, _db_write_rx) = mpsc::channel::<DbWriteRequest>(8);
///     let job_tx = spawn_workers(2, 16, executors, db_write_tx).await;
///
///     // `job_tx` can now be used to enqueue `JobTrigger` values.
///     // job_tx.send(JobTrigger { job_id: "example".into(), trigger_kind: ..., dry_run: false }).await.unwrap();
/// }
/// ```
#[instrument(skip(executors, db_write_tx), fields(num_workers, queue_capacity))]
pub async fn spawn_workers(
    num_workers: usize,
    queue_capacity: usize,
    executors: Arc<dyn Fn(&str) -> Option<Arc<dyn JobExecutor>> + Send + Sync>,
    db_write_tx: mpsc::Sender<DbWriteRequest>,
) -> mpsc::Sender<JobTrigger> {
    info!(num_workers, queue_capacity, "spawning worker pool");
    let (job_tx, job_rx) = mpsc::channel::<JobTrigger>(queue_capacity);
    // Wrap the receiver in Arc<Mutex> so it can be shared across workers.
    let job_rx = Arc::new(tokio::sync::Mutex::new(job_rx));

    for worker_id in 0..num_workers {
        let job_rx = Arc::clone(&job_rx);
        let executors = Arc::clone(&executors);
        let db_write_tx = db_write_tx.clone();

        tokio::spawn(async move {
            debug!(worker_id, "worker started");
            // Track consecutive_failures per job_id within this worker.
            let mut worker_failures: HashMap<String, i32> = HashMap::new();
            loop {
                trace!(worker_id, "worker waiting for job");
                let trigger = {
                    let mut rx = job_rx.lock().await;
                    rx.recv().await
                };

                let trigger = match trigger {
                    Some(t) => t,
                    None => {
                        debug!(worker_id, "job channel closed; worker exiting");
                        break; // channel closed
                    }
                };

                let job_id = trigger.job_id.clone();
                trace!(worker_id, job_id = %job_id, "worker received job trigger");

                let executor = match executors(&job_id) {
                    Some(e) => e,
                    None => {
                        warn!(worker_id, job_id = %job_id, "no executor found for job — skipping");
                        continue;
                    }
                };

                let run_id = uuid::Uuid::new_v4().to_string();
                let started_at = Utc::now();
                info!(worker_id, job_id = %job_id, run_id = %run_id, "job started");
                let ctx = JobContext {
                    run_id: run_id.clone(),
                    job_id: job_id.clone(),
                    trigger: trigger.trigger_kind,
                    dry_run: trigger.dry_run,
                };

                let (outcome, duration) = executor.execute(&ctx).await;

                let finished_at = Utc::now().to_rfc3339();
                let started_at_str = started_at.to_rfc3339();
                let duration_ms = duration.as_millis() as i32;

                let outcome_str = match &outcome {
                    JobOutcome::Success => "success",
                    JobOutcome::Failure { .. } => "failure",
                    JobOutcome::DryRun => "dry_run",
                };

                let error_summary = match &outcome {
                    JobOutcome::Failure { error } => Some(error.clone()),
                    _ => None,
                };

                info!(
                    worker_id,
                    job_id = %job_id,
                    run_id = %run_id,
                    outcome = outcome_str,
                    duration_ms = duration.as_millis(),
                    "job finished"
                );

                let job_run = JobRunRow {
                    run_id: run_id.clone(),
                    job_id: job_id.clone(),
                    job_kind: "unknown".to_string(), // populated in Phase 8 from config
                    trigger_kind: format!("{:?}", trigger.trigger_kind).to_lowercase(),
                    started_at: started_at_str.clone(),
                    finished_at: Some(finished_at.clone()),
                    outcome: Some(outcome_str.to_string()),
                    error_summary: error_summary.clone(),
                    duration_ms: Some(duration_ms),
                };

                let (current_state, consecutive_failures) = match &outcome {
                    JobOutcome::Success | JobOutcome::DryRun => {
                        worker_failures.insert(job_id.clone(), 0);
                        ("healthy".to_string(), 0)
                    }
                    JobOutcome::Failure { .. } => {
                        let prev = worker_failures.get(&job_id).copied().unwrap_or(0);
                        let new_count = prev + 1;
                        worker_failures.insert(job_id.clone(), new_count);
                        ("degraded".to_string(), new_count)
                    }
                };

                let job_status = JobStatusRow {
                    job_id: job_id.clone(),
                    job_kind: "unknown".to_string(), // populated in Phase 8 from config
                    enabled: 1,
                    current_state,
                    last_started_at: Some(started_at_str),
                    last_finished_at: Some(finished_at.clone()),
                    last_success_at: if matches!(outcome, JobOutcome::Success) {
                        Some(finished_at.clone())
                    } else {
                        None
                    },
                    last_failure_at: if matches!(outcome, JobOutcome::Failure { .. }) {
                        Some(finished_at)
                    } else {
                        None
                    },
                    last_error_summary: error_summary,
                    consecutive_failures,
                    last_run_id: Some(run_id.clone()),
                };

                trace!(worker_id, job_id = %job_id, run_id = %run_id, "sending JobRun to DB writer");
                if let Err(e) = db_write_tx.send(DbWriteRequest::JobRun(job_run)).await {
                    error!(worker_id, job_id = %job_id, run_id = %run_id, error = %e, "failed to send JobRun to DB writer");
                }
                trace!(worker_id, job_id = %job_id, run_id = %run_id, "sending JobStatus to DB writer");
                if let Err(e) = db_write_tx
                    .send(DbWriteRequest::JobStatus(job_status))
                    .await
                {
                    error!(worker_id, job_id = %job_id, run_id = %run_id, error = %e, "failed to send JobStatus to DB writer");
                }
            }
        });
    }

    job_tx
}

// ─── spawn_db_writer ───────────────────────────────────────────────────────────

/// Start a background task that serially processes `DbWriteRequest` messages using the provided `DaemonStateStore`.
///
/// Each incoming request is executed on a blocking thread so SQLite access is serialized through the single writer task.
/// The task logs failures from blocking calls and exits when the request channel closes.
///
/// # Examples
///
/// ```text
/// use tokio::sync::mpsc;
/// // let store: DaemonStateStore = ...;
/// let (tx, rx) = mpsc::channel(16);
/// let _handle = spawn_db_writer(store, rx);
/// // send DbWriteRequest messages to `tx`
/// ```
#[instrument(skip(store, db_write_rx))]
pub fn spawn_db_writer(
    store: DaemonStateStore,
    mut db_write_rx: mpsc::Receiver<DbWriteRequest>,
) -> tokio::task::JoinHandle<()> {
    // Wrap in Arc so it can be cloned into each spawn_blocking call.
    let store = Arc::new(store);

    info!("DB writer task started");
    tokio::spawn(async move {
        while let Some(req) = db_write_rx.recv().await {
            match req {
                DbWriteRequest::JobRun(row) => {
                    debug!(run_id = %row.run_id, job_id = %row.job_id, outcome = ?row.outcome, "DB writer: writing JobRun");
                    let store = Arc::clone(&store);
                    match tokio::task::spawn_blocking(move || store.append_job_run(row)).await {
                        Err(e) => error!(error = %e, "DB writer task panicked on JobRun"),
                        Ok(Err(e)) => error!(error = %e, "append_job_run failed"),
                        Ok(Ok(())) => {}
                    }
                }
                DbWriteRequest::JobStatus(row) => {
                    debug!(job_id = %row.job_id, current_state = %row.current_state, "DB writer: writing JobStatus");
                    let store = Arc::clone(&store);
                    match tokio::task::spawn_blocking(move || store.save_job_status(row)).await {
                        Err(e) => error!(error = %e, "DB writer task panicked on JobStatus"),
                        Ok(Err(e)) => error!(error = %e, "save_job_status failed"),
                        Ok(Ok(())) => {}
                    }
                }
            }
        }
        debug!("DB writer task: channel closed, exiting");
    })
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::{db, executor::JobOutcome, scheduler::JobTrigger, types::TriggerKind};
    use chrono::Utc;
    use std::time::Duration;

    struct MockExecutor;

    #[async_trait::async_trait]
    impl JobExecutor for MockExecutor {
        /// A test/mock executor that always reports a successful run with a fixed short duration.
        ///
        /// # Examples
        ///
        /// ```rust,ignore
        /// # use crate::daemon::worker::{MockExecutor, JobContext, JobOutcome};
        /// # async fn __example() {
        /// let exec = MockExecutor;
        /// // `ctx` can be any valid `JobContext` for tests; fields omitted here for brevity.
        /// let ctx = JobContext {
        ///     run_id: "run".into(),
        ///     job_id: "job".into(),
        ///     trigger: Default::default(),
        ///     dry_run: false,
        /// };
        /// let (outcome, dur) = exec.execute(&ctx).await;
        /// assert_eq!(outcome, JobOutcome::Success);
        /// assert_eq!(dur.as_millis(), 10);
        /// # }
        /// ```
        async fn execute(&self, _ctx: &JobContext) -> (JobOutcome, Duration) {
            (JobOutcome::Success, Duration::from_millis(10))
        }
    }

    /// Creates a temporary `DaemonStateStore` backed by a uniquely named SQLite file in the system
    /// temporary directory.
    ///
    /// The directory and file are created under `std::env::temp_dir()` with a PID-based prefix and a
    /// UUID filename to avoid collisions. Panics if the temporary directory cannot be created or the
    /// test database fails to open.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let store = open_test_store();
    /// // use `store` for test assertions or pass to functions under test
    /// drop(store);
    /// ```
    #[allow(dead_code)]
    fn open_test_store() -> DaemonStateStore {
        let dir = std::env::temp_dir().join(format!("dnsync-worker-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("test-{}.sqlite", uuid::Uuid::new_v4().as_simple()));
        let pool = db::open(&path).expect("test db should open");
        DaemonStateStore::new(pool)
    }

    /// Constructs a sample `JobRunRow` representing a successful test run.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let row = sample_job_run_row();
    /// assert_eq!(row.run_id, "run-test-1");
    /// assert_eq!(row.job_id, "job-test");
    /// assert_eq!(row.outcome.as_deref(), Some("success"));
    /// assert_eq!(row.duration_ms, Some(10));
    /// ```
    fn sample_job_run_row() -> JobRunRow {
        JobRunRow {
            run_id: "run-test-1".to_string(),
            job_id: "job-test".to_string(),
            job_kind: "sync".to_string(),
            trigger_kind: "scheduled".to_string(),
            started_at: "2026-01-01T00:00:00Z".to_string(),
            finished_at: Some("2026-01-01T00:00:01Z".to_string()),
            outcome: Some("success".to_string()),
            error_summary: None,
            duration_ms: Some(10),
        }
    }

    /// Construct a representative `JobStatusRow` for tests.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let row = sample_job_status_row();
    /// assert_eq!(row.job_id, "job-test");
    /// assert_eq!(row.job_kind, "sync");
    /// assert_eq!(row.enabled, 1);
    /// assert_eq!(row.current_state, "healthy");
    /// assert_eq!(row.consecutive_failures, 0);
    /// ```
    fn sample_job_status_row() -> JobStatusRow {
        JobStatusRow {
            job_id: "job-test".to_string(),
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

    /// Unit test: construct a `DbWriteRequest::JobRun` and match it.
    #[test]
    fn test_db_write_request_job_run_variant() {
        let row = sample_job_run_row();
        let req = DbWriteRequest::JobRun(row);
        assert!(matches!(req, DbWriteRequest::JobRun(_)));
    }

    /// Unit test: construct a `DbWriteRequest::JobStatus` and match it.
    #[test]
    fn test_db_write_request_job_status_variant() {
        let row = sample_job_status_row();
        let req = DbWriteRequest::JobStatus(row);
        assert!(matches!(req, DbWriteRequest::JobStatus(_)));
    }

    /// Integration test: send one `JobTrigger` through the pool, wait for the
    /// DB write channel to receive a `DbWriteRequest`, assert it's a `JobRun`.
    #[tokio::test]
    async fn test_spawn_workers_sends_to_channel() {
        let (db_write_tx, mut db_write_rx) = mpsc::channel::<DbWriteRequest>(10);

        let executors: Arc<dyn Fn(&str) -> Option<Arc<dyn JobExecutor>> + Send + Sync> =
            Arc::new(|job_id: &str| {
                if job_id == "test-job" {
                    Some(Arc::new(MockExecutor) as Arc<dyn JobExecutor>)
                } else {
                    None
                }
            });

        let job_tx = spawn_workers(1, 10, executors, db_write_tx).await;

        let trigger = JobTrigger {
            job_id: "test-job".to_string(),
            scheduled_at: Utc::now(),
            trigger_kind: TriggerKind::Manual,
            dry_run: false,
        };

        job_tx.send(trigger).await.expect("should send trigger");

        // Wait for the first DbWriteRequest — should be a JobRun.
        let req = tokio::time::timeout(std::time::Duration::from_secs(5), db_write_rx.recv())
            .await
            .expect("timed out waiting for db write")
            .expect("channel closed unexpectedly");

        assert!(
            matches!(req, DbWriteRequest::JobRun(_)),
            "expected DbWriteRequest::JobRun as first message"
        );
    }

    /// Test that a full bounded channel returns `TrySendError::Full` on the
    /// second send, demonstrating the drop-on-full behavior at the channel boundary.
    #[tokio::test]
    async fn test_queue_full_drops_trigger() {
        // Create a channel with capacity 1.
        let (job_tx, _job_rx) = mpsc::channel::<JobTrigger>(1);

        let trigger1 = JobTrigger {
            job_id: "job-a".to_string(),
            scheduled_at: Utc::now(),
            trigger_kind: TriggerKind::Scheduled,
            dry_run: false,
        };
        let trigger2 = JobTrigger {
            job_id: "job-b".to_string(),
            scheduled_at: Utc::now(),
            trigger_kind: TriggerKind::Scheduled,
            dry_run: false,
        };

        // First send fills the queue (capacity=1, no receiver consuming).
        job_tx
            .try_send(trigger1)
            .expect("first send should succeed");

        // Second send should fail with Full because the channel is at capacity.
        let result = job_tx.try_send(trigger2);
        assert!(
            matches!(result, Err(tokio::sync::mpsc::error::TrySendError::Full(_))),
            "expected TrySendError::Full, got: {result:?}"
        );
    }
}
