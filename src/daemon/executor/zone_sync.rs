//! ZoneSyncExecutor — executes a ZoneSync job by calling into
//! `control_plane::sync::run_sync_json`.
//!
//! ZoneSync is architecturally the same operation as RecordSync at this layer
//! (full zone copy via sync). The separate struct exists for future
//! differentiation (e.g. zone-level semantics, different defaults).

use std::time::{Duration, Instant};

use crate::control_plane::config::AppConfig;
use crate::control_plane::sync::run_sync_json;

use super::{JobContext, JobExecutor, JobOutcome};

/// Executor for `ZoneSync` jobs.
pub struct ZoneSyncExecutor {
    pub config: AppConfig,
    pub job_id: String,
}

#[async_trait::async_trait]
impl JobExecutor for ZoneSyncExecutor {
    async fn execute(&self, ctx: &JobContext) -> (JobOutcome, Duration) {
        let Some(job) = self.config.jobs.iter().find(|j| j.id == self.job_id) else {
            return (
                JobOutcome::Failure {
                    error: "job not found".to_string(),
                },
                Duration::ZERO,
            );
        };

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
            return (JobOutcome::DryRun, elapsed);
        }

        match result {
            Err(e) => (
                JobOutcome::Failure {
                    error: e.to_string(),
                },
                elapsed,
            ),
            Ok(value) => {
                if value.get("error").is_some() {
                    (
                        JobOutcome::Failure {
                            error: value["error"]
                                .as_str()
                                .unwrap_or("unknown error")
                                .to_string(),
                        },
                        elapsed,
                    )
                } else {
                    (JobOutcome::Success, elapsed)
                }
            }
        }
    }
}
