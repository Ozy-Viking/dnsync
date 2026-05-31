//! ZoneSyncExecutor — executes a ZoneSync job by calling into
//! `control_plane::sync::run_sync_json`.
//!
//! ZoneSync is architecturally the same operation as RecordSync at this layer
//! (full zone copy via sync). The separate struct exists for future
//! differentiation (e.g. zone-level semantics, different defaults).

use std::time::{Duration, Instant};

use tracing::{debug, info, instrument, warn};

use crate::control_plane::config::AppConfig;
use crate::control_plane::sync::{SyncDiffOptions, run_sync_json};

use super::{JobContext, JobExecutor, JobOutcome};

/// Executor for `ZoneSync` jobs.
pub struct ZoneSyncExecutor {
    pub config: AppConfig,
    pub job_id: String,
}

#[async_trait::async_trait]
impl JobExecutor for ZoneSyncExecutor {
    /// Execute the ZoneSync job configured under `self.job_id` using the provided `ctx`.
    ///
    /// Looks up the job in `self.config.jobs` and runs a sync between the job's `from` and `to` locations
    /// using the job's zones, ip_map, and diff options. If the job is not found the function returns
    /// `JobOutcome::Failure { error: "job not found" }` with a zero duration. If `ctx.dry_run` is true,
    /// the sync is executed in dry-run mode and the function returns `JobOutcome::DryRun`. On success
    /// returns `JobOutcome::Success`; on failure returns `JobOutcome::Failure { error: ... }`.
    ///
    /// # Examples
    ///
    /// ```
    /// # // The following is an illustrative example; real types must be constructed according to the crate's API.
    /// # use std::time::Duration;
    /// # use tokio::runtime::Runtime;
    /// # fn main() {
    /// # let rt = Runtime::new().unwrap();
    /// # rt.block_on(async {
    /// let config = AppConfig::default();
    /// let executor = ZoneSyncExecutor { config, job_id: "example".to_string() };
    /// let ctx = JobContext::default();
    /// let (outcome, duration) = executor.execute(&ctx).await;
    /// // duration is the elapsed time taken by the operation
    /// assert!(duration >= Duration::ZERO);
    /// # });
    /// # }
    /// ```
    #[instrument(skip(self, ctx), fields(job_id = %self.job_id, run_id = %ctx.run_id))]
    async fn execute(&self, ctx: &JobContext) -> (JobOutcome, Duration) {
        let Some(job) = self.config.jobs.iter().find(|j| j.id == self.job_id) else {
            warn!(job_id = %self.job_id, "ZoneSync job not found in config");
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
            "ZoneSyncExecutor: executing job"
        );

        let ip_map_vec: Vec<String> = job
            .ip_map
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();

        let apply = !ctx.dry_run;

        let ignore_patterns: Vec<regex::Regex> = job
            .ignore
            .iter()
            .filter_map(|p| regex::Regex::new(p).ok())
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

        if !apply {
            info!(job_id = %self.job_id, run_id = %ctx.run_id, duration_ms = elapsed.as_millis(), "ZoneSync dry run complete");
            return (JobOutcome::DryRun, elapsed);
        }

        match result {
            Err(e) => {
                warn!(job_id = %self.job_id, run_id = %ctx.run_id, error = %e, duration_ms = elapsed.as_millis(), "ZoneSync failed");
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
                    warn!(job_id = %self.job_id, run_id = %ctx.run_id, error = %error_msg, duration_ms = elapsed.as_millis(), "ZoneSync returned error in result");
                    (
                        JobOutcome::Failure {
                            error: error_msg,
                        },
                        elapsed,
                    )
                } else {
                    info!(job_id = %self.job_id, run_id = %ctx.run_id, duration_ms = elapsed.as_millis(), "ZoneSync completed successfully");
                    (JobOutcome::Success, elapsed)
                }
            }
        }
    }
}
