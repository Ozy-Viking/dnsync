//! RecordSyncExecutor — executes a RecordSync job by calling into
//! `control_plane::sync::run_sync_json`.

use std::time::{Duration, Instant};

use tracing::{debug, info, instrument, warn};

use crate::control_plane::config::AppConfig;
use crate::control_plane::sync::run_sync_json;

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

        let ip_map_vec: Vec<String> = job
            .ip_map
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();

        let apply = !ctx.dry_run;

        let start = Instant::now();
        let result = run_sync_json(
            Some(&self.config),
            None,
            job.from.as_deref(),
            job.to.as_deref(),
            &job.zones,
            &ip_map_vec,
            apply,
        )
        .await;
        let elapsed = start.elapsed();

        if !apply {
            info!(job_id = %self.job_id, run_id = %ctx.run_id, duration_ms = elapsed.as_millis(), "RecordSync dry run complete");
            return (JobOutcome::DryRun, elapsed);
        }

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
                    (
                        JobOutcome::Failure {
                            error: error_msg,
                        },
                        elapsed,
                    )
                } else {
                    info!(job_id = %self.job_id, run_id = %ctx.run_id, duration_ms = elapsed.as_millis(), "RecordSync completed successfully");
                    (JobOutcome::Success, elapsed)
                }
            }
        }
    }
}
