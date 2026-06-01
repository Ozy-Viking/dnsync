//! JobExecutor trait and concrete executor implementations.
//!
//! Executors call INTO `control_plane::sync` — not the other way around.
//! No DNS logic lives in executor code itself.

use std::time::Duration;

use crate::daemon::types::TriggerKind;

pub mod record_sync;
pub mod zone_export;
pub mod zone_sync;

pub use record_sync::RecordSyncExecutor;
pub use zone_export::ZoneExportExecutor;
pub use zone_sync::ZoneSyncExecutor;

/// The outcome of a single job execution.
#[derive(Debug, Clone, PartialEq)]
pub enum JobOutcome {
    Success,
    Failure {
        error: String,
    },
    /// apply=false — the plan was computed but not applied.
    DryRun,
}

/// Context passed to an executor for a single job run.
pub struct JobContext {
    pub run_id: String,
    pub job_id: String,
    pub trigger: TriggerKind,
    pub dry_run: bool,
}

/// Trait implemented by all job executor types.
#[async_trait::async_trait]
pub trait JobExecutor: Send + Sync {
    async fn execute(&self, ctx: &JobContext) -> (JobOutcome, Duration);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::config::{AppConfig, JobConfig, JobKind};
    use std::collections::BTreeMap;

    /// Create an `AppConfig` containing a single enabled `RecordSync` job with the given `job_id`.
    ///
    /// The returned configuration has empty `servers` and `clusters`, no `daemon`, and one `JobConfig`:
    /// `kind = JobKind::RecordSync`, `from = Some("src-server")`, `to = Some("dst-server")`,
    /// `schedule = Some("@hourly")`, `create_missing = true`, `overwrite_existing = true`, and `output_dir = None`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let cfg = make_record_sync_config("nightly-sync");
    /// assert_eq!(cfg.jobs.len(), 1);
    /// assert_eq!(cfg.jobs[0].id, "nightly-sync");
    /// assert_eq!(cfg.jobs[0].kind, JobKind::RecordSync);
    /// ```
    fn make_record_sync_config(job_id: &str) -> AppConfig {
        AppConfig {
            servers: vec![],
            clusters: BTreeMap::new(),
            daemon: None,
            jobs: vec![JobConfig {
                id: job_id.to_string(),
                kind: JobKind::RecordSync,
                enabled: true,
                critical: false,
                schedule: Some("@hourly".to_string()),
                interval: None,
                timezone: None,
                run_immediately: false,
                jitter: None,
                dry_run: false,
                from: Some("src-server".to_string()),
                to: Some("dst-server".to_string()),
                zones: vec![],
                ip_map: BTreeMap::new(),
                create_missing: true,
                overwrite_existing: true,
                delete_destination_only: false,
                ignore: vec![],
                output_dir: None,
            }],
        }
    }

    /// Create an `AppConfig` with a single enabled `ZoneExport` job using the provided job id and sensible defaults for tests.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let cfg = make_zone_export_config("nightly-export");
    /// assert_eq!(cfg.jobs.len(), 1);
    /// let job = &cfg.jobs[0];
    /// assert_eq!(job.id, "nightly-export");
    /// assert!(matches!(job.kind, JobKind::ZoneExport));
    /// assert_eq!(job.output_dir.as_deref(), Some("/tmp/zones"));
    /// ```
    fn make_zone_export_config(job_id: &str) -> AppConfig {
        AppConfig {
            servers: vec![],
            clusters: BTreeMap::new(),
            daemon: None,
            jobs: vec![JobConfig {
                id: job_id.to_string(),
                kind: JobKind::ZoneExport,
                enabled: true,
                critical: false,
                schedule: Some("@hourly".to_string()),
                interval: None,
                timezone: None,
                run_immediately: false,
                jitter: None,
                dry_run: false,
                from: None,
                to: None,
                zones: vec![],
                ip_map: BTreeMap::new(),
                create_missing: true,
                overwrite_existing: true,
                delete_destination_only: false,
                ignore: vec![],
                output_dir: Some("/tmp/zones".to_string()),
            }],
        }
    }

    /// A job_id not in config.jobs must return Failure immediately (no async call needed).
    #[tokio::test]
    async fn test_job_not_found_returns_failure() {
        let config = make_record_sync_config("nightly-sync");
        let executor = RecordSyncExecutor {
            config,
            job_id: "nonexistent-job".to_string(),
        };
        let ctx = JobContext {
            run_id: "run-1".to_string(),
            job_id: "nonexistent-job".to_string(),
            trigger: TriggerKind::Manual,
            dry_run: false,
        };

        let (outcome, elapsed) = executor.execute(&ctx).await;

        assert!(
            matches!(&outcome, JobOutcome::Failure { error } if error.contains("job not found")),
            "expected Failure with 'job not found', got {outcome:?}"
        );
        assert_eq!(elapsed, Duration::ZERO);
    }

    /// A job_id not in config.jobs for ZoneSyncExecutor must also return Failure.
    #[tokio::test]
    async fn test_zone_sync_job_not_found_returns_failure() {
        let config = make_record_sync_config("nightly-sync");
        let executor = ZoneSyncExecutor {
            config,
            job_id: "nonexistent-job".to_string(),
        };
        let ctx = JobContext {
            run_id: "run-1".to_string(),
            job_id: "nonexistent-job".to_string(),
            trigger: TriggerKind::Manual,
            dry_run: false,
        };

        let (outcome, elapsed) = executor.execute(&ctx).await;

        assert!(
            matches!(&outcome, JobOutcome::Failure { error } if error.contains("job not found")),
            "expected Failure with 'job not found', got {outcome:?}"
        );
        assert_eq!(elapsed, Duration::ZERO);
    }

    /// ZoneExportExecutor always returns Failure with "not yet implemented".
    #[tokio::test]
    async fn test_zone_export_stub_returns_failure() {
        let config = make_zone_export_config("export-job");
        let executor = ZoneExportExecutor {
            config,
            job_id: "export-job".to_string(),
        };
        let ctx = JobContext {
            run_id: "run-2".to_string(),
            job_id: "export-job".to_string(),
            trigger: TriggerKind::Scheduled,
            dry_run: false,
        };

        let (outcome, _elapsed) = executor.execute(&ctx).await;

        assert!(
            matches!(&outcome, JobOutcome::Failure { error } if error.contains("not yet implemented")),
            "expected Failure with 'not yet implemented', got {outcome:?}"
        );
    }

    /// ZoneExportExecutor returns Failure even for a missing job (stub always fails).
    #[tokio::test]
    async fn test_zone_export_stub_missing_job_returns_failure() {
        let config = make_zone_export_config("export-job");
        let executor = ZoneExportExecutor {
            config,
            job_id: "missing-job".to_string(),
        };
        let ctx = JobContext {
            run_id: "run-3".to_string(),
            job_id: "missing-job".to_string(),
            trigger: TriggerKind::Scheduled,
            dry_run: false,
        };

        let (outcome, _elapsed) = executor.execute(&ctx).await;

        assert!(
            matches!(outcome, JobOutcome::Failure { .. }),
            "expected Failure, got {outcome:?}"
        );
    }
}
