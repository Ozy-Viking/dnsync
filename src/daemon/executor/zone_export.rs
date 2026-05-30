//! ZoneExportExecutor — stub for a ZoneExport job.
//!
//! TODO: Implement actual zone export logic once the control_plane export API
//! exists. For now this always returns a Failure indicating the feature is not
//! yet implemented.

use std::time::Duration;

use tracing::{debug, instrument, warn};

use crate::control_plane::config::AppConfig;

use super::{JobContext, JobExecutor, JobOutcome};

/// Executor for `ZoneExport` jobs.
///
/// This is a **stub placeholder** — it always returns
/// `JobOutcome::Failure { error: "ZoneExport not yet implemented" }`.
/// A full implementation requires a `control_plane` export API that does not
/// yet exist.
pub struct ZoneExportExecutor {
    pub config: AppConfig,
    pub job_id: String,
}

#[async_trait::async_trait]
impl JobExecutor for ZoneExportExecutor {
    #[instrument(skip_all, fields(job_id = %self.job_id))]
    async fn execute(&self, _ctx: &JobContext) -> (JobOutcome, Duration) {
        // TODO: Implement zone export once control_plane::export exists.
        // Look up job config, query provider, write zone files to job.output_dir.
        let job_found = self.config.jobs.iter().find(|j| j.id == self.job_id).is_some();
        debug!(job_id = %self.job_id, job_found, "ZoneExportExecutor: stub invoked (not yet implemented)");

        if !job_found {
            warn!(job_id = %self.job_id, "ZoneExport job not found in config (stub)");
        }

        warn!(job_id = %self.job_id, "ZoneExport is not yet implemented; returning failure");
        (
            JobOutcome::Failure {
                error: "ZoneExport not yet implemented".to_string(),
            },
            Duration::ZERO,
        )
    }
}
