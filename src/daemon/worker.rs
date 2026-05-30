//! Async worker pool connecting the scheduler to job executors.
//!
//! Architecture:
//!   scheduler (ticks) → job_tx (bounded mpsc) → worker pool (N workers) → executor.execute()
//!                                                         ↓
//!                                               db_write_tx (mpsc) → DB writer task → DaemonStateStore

use std::sync::Arc;

use chrono::Utc;
use tokio::sync::mpsc;
use tracing::{warn, error};

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

/// Spawn `num_workers` worker tasks.
///
/// Each worker pulls from the shared `job_rx`, calls the appropriate executor,
/// then sends results to `db_write_tx`.
///
/// Returns the sender side so callers can enqueue jobs.
pub async fn spawn_workers(
    num_workers: usize,
    queue_capacity: usize,
    executors: Arc<dyn Fn(&str) -> Option<Arc<dyn JobExecutor>> + Send + Sync>,
    db_write_tx: mpsc::Sender<DbWriteRequest>,
) -> mpsc::Sender<JobTrigger> {
    let (job_tx, job_rx) = mpsc::channel::<JobTrigger>(queue_capacity);
    // Wrap the receiver in Arc<Mutex> so it can be shared across workers.
    let job_rx = Arc::new(tokio::sync::Mutex::new(job_rx));

    for _ in 0..num_workers {
        let job_rx = Arc::clone(&job_rx);
        let executors = Arc::clone(&executors);
        let db_write_tx = db_write_tx.clone();

        tokio::spawn(async move {
            loop {
                let trigger = {
                    let mut rx = job_rx.lock().await;
                    rx.recv().await
                };

                let trigger = match trigger {
                    Some(t) => t,
                    None => break, // channel closed
                };

                let job_id = trigger.job_id.clone();

                let executor = match executors(&job_id) {
                    Some(e) => e,
                    None => {
                        warn!(job_id = %job_id, "no executor found for job — skipping");
                        continue;
                    }
                };

                let run_id = uuid::Uuid::new_v4().to_string();
                let started_at = Utc::now();
                let ctx = JobContext {
                    run_id: run_id.clone(),
                    job_id: job_id.clone(),
                    trigger: trigger.trigger_kind,
                    dry_run: false,
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
                    JobOutcome::Success | JobOutcome::DryRun => ("healthy".to_string(), 0),
                    JobOutcome::Failure { .. } => ("degraded".to_string(), 1),
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
                    last_run_id: Some(run_id),
                };

                if let Err(e) = db_write_tx.send(DbWriteRequest::JobRun(job_run)).await {
                    error!(error = %e, "failed to send JobRun to DB writer");
                }
                if let Err(e) = db_write_tx.send(DbWriteRequest::JobStatus(job_status)).await {
                    error!(error = %e, "failed to send JobStatus to DB writer");
                }
            }
        });
    }

    job_tx
}

// ─── spawn_db_writer ───────────────────────────────────────────────────────────

/// Spawn the DB writer task. Owns a `DaemonStateStore`.
///
/// Processes `DbWriteRequest` messages serially, ensuring single-writer
/// access to SQLite.
pub async fn spawn_db_writer(
    store: DaemonStateStore,
    mut db_write_rx: mpsc::Receiver<DbWriteRequest>,
) {
    // Wrap in Arc so it can be cloned into each spawn_blocking call.
    let store = Arc::new(store);

    tokio::spawn(async move {
        while let Some(req) = db_write_rx.recv().await {
            match req {
                DbWriteRequest::JobRun(row) => {
                    let store = Arc::clone(&store);
                    match tokio::task::spawn_blocking(move || store.append_job_run(row)).await {
                        Err(e) => error!(error = %e, "DB writer task panicked on JobRun"),
                        Ok(Err(e)) => error!(error = %e, "append_job_run failed"),
                        Ok(Ok(())) => {}
                    }
                }
                DbWriteRequest::JobStatus(row) => {
                    let store = Arc::clone(&store);
                    match tokio::task::spawn_blocking(move || store.save_job_status(row)).await {
                        Err(e) => error!(error = %e, "DB writer task panicked on JobStatus"),
                        Ok(Err(e)) => error!(error = %e, "save_job_status failed"),
                        Ok(Ok(())) => {}
                    }
                }
            }
        }
    });
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::{
        db,
        executor::JobOutcome,
        scheduler::JobTrigger,
        types::TriggerKind,
    };
    use chrono::Utc;
    use std::time::Duration;

    struct MockExecutor;

    #[async_trait::async_trait]
    impl JobExecutor for MockExecutor {
        async fn execute(&self, _ctx: &JobContext) -> (JobOutcome, Duration) {
            (JobOutcome::Success, Duration::from_millis(10))
        }
    }

    #[allow(dead_code)]
    fn open_test_store() -> DaemonStateStore {
        let dir =
            std::env::temp_dir().join(format!("dnsync-worker-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!(
            "test-{}.sqlite",
            uuid::Uuid::new_v4().as_simple()
        ));
        let pool = db::open(&path).expect("test db should open");
        DaemonStateStore::new(pool)
    }

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
        };

        job_tx.send(trigger).await.expect("should send trigger");

        // Wait for the first DbWriteRequest — should be a JobRun.
        let req = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            db_write_rx.recv(),
        )
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
        };
        let trigger2 = JobTrigger {
            job_id: "job-b".to_string(),
            scheduled_at: Utc::now(),
            trigger_kind: TriggerKind::Scheduled,
        };

        // First send fills the queue (capacity=1, no receiver consuming).
        job_tx.try_send(trigger1).expect("first send should succeed");

        // Second send should fail with Full because the channel is at capacity.
        let result = job_tx.try_send(trigger2);
        assert!(
            matches!(result, Err(tokio::sync::mpsc::error::TrySendError::Full(_))),
            "expected TrySendError::Full, got: {result:?}"
        );
    }
}
