//! RecordSyncExecutor — executes a RecordSync job by calling into
//! `control_plane::sync::run_sync_json`.

use std::time::{Duration, Instant};

use tracing::{debug, info, instrument, warn};

use crate::control_plane::config::AppConfig;
use crate::control_plane::sync::{SyncDiffOptions, run_sync_json};

use super::{JobContext, JobExecutor, JobOutcome};

/// Executor for `RecordSync` jobs.
///
/// Looks up the job config by `job_id`, builds the appropriate options, and
/// delegates to `control_plane::sync::run_sync_json`. No DNS logic lives here.
pub struct RecordSyncExecutor {
    pub config: AppConfig,
    pub job_id: String,
}

#[async_trait::async_trait]
impl JobExecutor for RecordSyncExecutor {
    /// Execute the configured RecordSync job identified by this executor's `job_id`.
    ///
    /// The method looks up the job in `self.config.jobs`, builds sync options (including `ip_map` and compiled
    /// ignore patterns), calls `control_plane::sync::run_sync_json` with those options, measures elapsed time,
    /// and maps the call result to a `JobOutcome`. If `ctx.dry_run` is true the function performs a dry run and
    /// returns `JobOutcome::DryRun` with the measured duration.
    ///
    /// # Returns
    ///
    /// `(JobOutcome, Duration)` — the job outcome and the elapsed time taken to run (or zero duration if the
    /// job was not found).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use std::time::Duration;
    /// # use tokio::runtime::Runtime;
    /// # use crate::daemon::executor::record_sync::RecordSyncExecutor;
    /// # use crate::{AppConfig, JobContext};
    /// let rt = Runtime::new().unwrap();
    /// let exec = RecordSyncExecutor { config: AppConfig::default(), job_id: "example".into() };
    /// let ctx = JobContext { run_id: "r1".into(), dry_run: true };
    /// let (outcome, elapsed) = rt.block_on(async { exec.execute(&ctx).await });
    /// // `outcome` will be `JobOutcome::DryRun` for this example because `ctx.dry_run` is true.
    /// ```
    #[instrument(skip(self, ctx), fields(job_id = %self.job_id, run_id = %ctx.run_id))]
    async fn execute(&self, ctx: &JobContext) -> (JobOutcome, Duration) {
        let Some(job) = self.config.jobs.iter().find(|j| j.id == self.job_id) else {
            warn!(job_id = %self.job_id, "RecordSync job not found in config");
            return (
                JobOutcome::Failure {
                    error: "job not found".to_string(),
                },
                Duration::ZERO,
            );
        };

        debug!(
            job_id = %self.job_id,
            run_id = %ctx.run_id,
            from = ?job.from,
            to = ?job.to,
            dry_run = ctx.dry_run,
            "RecordSyncExecutor: executing job"
        );

        let ip_map_vec: Vec<String> = job.ip_map.iter().map(|(k, v)| format!("{k}={v}")).collect();

        let apply = !ctx.dry_run && !job.dry_run;

        let ignore_patterns: Vec<regex::Regex> = job
            .ignore
            .iter()
            .map(|p| regex::Regex::new(p).expect("ignore pattern was validated at config load"))
            .collect();
        let diff_opts = SyncDiffOptions {
            create_missing: job.create_missing,
            overwrite_existing: job.overwrite_existing,
            delete_destination_only: job.delete_destination_only,
            ignore: ignore_patterns,
        };

        let start = Instant::now();
        let result = run_sync_json(
            Some(&self.config),
            None,
            job.from.as_deref(),
            job.to.as_deref(),
            &job.zones,
            &ip_map_vec,
            apply,
            diff_opts,
        )
        .await;
        let elapsed = start.elapsed();

        match result {
            Err(e) => {
                warn!(job_id = %self.job_id, run_id = %ctx.run_id, error = %e, duration_ms = elapsed.as_millis(), "RecordSync failed");
                (
                    JobOutcome::Failure {
                        error: e.to_string(),
                    },
                    elapsed,
                )
            }
            Ok(value) => {
                if value.get("error").is_some() {
                    let error_msg = value["error"]
                        .as_str()
                        .unwrap_or("unknown error")
                        .to_string();
                    warn!(job_id = %self.job_id, run_id = %ctx.run_id, error = %error_msg, duration_ms = elapsed.as_millis(), "RecordSync returned error in result");
                    (JobOutcome::Failure { error: error_msg }, elapsed)
                } else if !apply {
                    info!(job_id = %self.job_id, run_id = %ctx.run_id, duration_ms = elapsed.as_millis(), "RecordSync dry run complete");
                    (JobOutcome::DryRun, elapsed)
                } else {
                    info!(job_id = %self.job_id, run_id = %ctx.run_id, duration_ms = elapsed.as_millis(), "RecordSync completed successfully");
                    (JobOutcome::Success, elapsed)
                }
            }
        }
    }
}
