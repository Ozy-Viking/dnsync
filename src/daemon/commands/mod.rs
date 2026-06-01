//! One-shot daemon commands — `job list` and `job run`.
//!
//! These are called directly from the CLI adapter (no worker pool is started).
//! They open the state DB, do their work, and return.

use std::sync::Arc;

use chrono::Utc;
use tracing::{debug, info, instrument, warn};

use crate::control_plane::config::{AppConfig, JobKind};
use crate::daemon::{
    db::{
        self,
        models::{JobRunRow, JobStatusRow},
        store::DaemonStateStore,
    },
    executor::{
        JobContext, JobExecutor, JobOutcome, RecordSyncExecutor, ZoneExportExecutor,
        ZoneSyncExecutor,
    },
    types::TriggerKind,
};

// ─── Public types ──────────────────────────────────────────────────────────────

/// Summary of a configured job and its last-known state from the DB.
pub struct JobSummary {
    pub job_id: String,
    pub kind: String,
    pub enabled: bool,
    pub state: String,
    pub last_run_at: Option<String>,
    pub consecutive_failures: i32,
}

// Re-export JobOutcome for callers.
pub use crate::daemon::executor::JobOutcome as JobOutcomeAlias;

// ─── Helper: resolve state DB path ────────────────────────────────────────────

/// Resolve the filesystem path to the daemon state database following the configured precedence.
///
/// Resolution precedence:
/// 1. `config.daemon.state_db` if present.
/// 2. `DNSYNC_STATE_DB` environment variable if set.
/// 3. XDG data home default: `<xdg_data_home>/dnsync/state.db`, where `xdg_data_home` is
///    `XDG_DATA_HOME` or `$HOME/.local/share`, or `.` if neither is available.
///
/// # Returns
///
/// A `PathBuf` pointing to the resolved state database file.
///
/// # Examples
///
/// ```rust,ignore
/// // Prefer an explicit path from the application config when available:
/// let path = resolve_state_db(&config);
/// println!("state DB: {}", path.display());
/// ```
fn resolve_state_db(config: &AppConfig) -> std::path::PathBuf {
    if let Some(ref daemon) = config.daemon
        && let Some(ref p) = daemon.state_db
    {
        return p.clone();
    }

    // Fall back to $DNSYNC_STATE_DB env var or XDG default.
    if let Ok(p) = std::env::var("DNSYNC_STATE_DB") {
        return std::path::PathBuf::from(p);
    }

    dirs_xdg_data_home().join("dnsync").join("state.db")
}

/// Determine the XDG data home directory path using environment fallbacks.
///
/// Checks the `XDG_DATA_HOME` environment variable first. If unset, falls back to
/// `$HOME/.local/share` when `HOME` is present. If neither variable is set,
/// returns the current directory (`.`).
///
/// # Examples
///
/// ```text
/// use std::path::PathBuf;
///
/// // Prefer XDG_DATA_HOME when set
/// std::env::set_var("XDG_DATA_HOME", "/tmp/xdg_data_home");
/// assert_eq!(dirs_xdg_data_home(), PathBuf::from("/tmp/xdg_data_home"));
/// std::env::remove_var("XDG_DATA_HOME");
///
/// // Fall back to HOME/.local/share when HOME is set
/// std::env::set_var("HOME", "/home/alice");
/// assert_eq!(
///     dirs_xdg_data_home(),
///     PathBuf::from("/home/alice").join(".local").join("share")
/// );
/// std::env::remove_var("HOME");
///
/// // When neither is set, return the current directory
/// std::env::remove_var("XDG_DATA_HOME");
/// std::env::remove_var("HOME");
/// assert_eq!(dirs_xdg_data_home(), PathBuf::from("."));
/// ```
fn dirs_xdg_data_home() -> std::path::PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        return std::path::PathBuf::from(xdg);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return std::path::PathBuf::from(home).join(".local").join("share");
    }
    std::path::PathBuf::from(".")
}

// ─── Helper: build executor for a job ─────────────────────────────────────────

/// Constructs a job executor for the configured job identified by `job_id`.
///
/// If a job with the given `job_id` exists in `config.jobs`, returns an `Arc<dyn JobExecutor>` whose concrete type corresponds to the job's `JobKind` (`RecordSyncExecutor`, `ZoneSyncExecutor`, or `ZoneExportExecutor`). Returns `None` when no matching job is found.
///
/// # Examples
///
/// ```text
/// // Assume `config` contains a job with id "job-alpha".
/// let exec = build_executor(&config, "job-alpha");
/// assert!(exec.is_some());
/// ```
fn build_executor(config: &AppConfig, job_id: &str) -> Option<Arc<dyn JobExecutor>> {
    let job = config.jobs.iter().find(|j| j.id == job_id)?;
    let executor: Arc<dyn JobExecutor> = match job.kind {
        JobKind::RecordSync => Arc::new(RecordSyncExecutor {
            config: config.clone(),
            job_id: job_id.to_string(),
        }),
        JobKind::ZoneSync => Arc::new(ZoneSyncExecutor {
            config: config.clone(),
            job_id: job_id.to_string(),
        }),
        JobKind::ZoneExport => Arc::new(ZoneExportExecutor {
            config: config.clone(),
            job_id: job_id.to_string(),
        }),
    };
    Some(executor)
}

// ─── list_jobs ─────────────────────────────────────────────────────────────────

/// Produce a list of all configured jobs, merging each job's configuration with any available
/// status information from the daemon state database.
///
/// Jobs with no recorded status will have `state` set to `"unknown"`, `last_run_at` set to
/// `None`, and `consecutive_failures` set to `0`.
///
/// # Examples
///
/// ```text
/// // Run the async function on a runtime to obtain job summaries.
/// let rt = tokio::runtime::Runtime::new().unwrap();
/// let config = crate::tests::empty_config(); // helper from this crate's tests
/// let summaries = rt.block_on(crate::daemon::commands::list_jobs(&config)).unwrap();
/// assert!(summaries.is_empty());
/// ```
#[instrument(skip(config))]
pub async fn list_jobs(config: &AppConfig) -> Result<Vec<JobSummary>, String> {
    if config.jobs.is_empty() {
        debug!("no jobs configured; returning empty list");
        return Ok(vec![]);
    }

    let db_path = resolve_state_db(config);
    debug!(db_path = %db_path.display(), "resolved state DB path");

    // Open DB only if it already exists — if it doesn't, we have no run history.
    let store_opt: Option<Arc<DaemonStateStore>> = if db_path.exists() {
        let pool = db::open(&db_path)?;
        Some(Arc::new(DaemonStateStore::new(pool)))
    } else {
        warn!(db_path = %db_path.display(), "state DB does not exist; job statuses will be unknown");
        None
    };

    // Collect job IDs for batch DB lookup.
    let job_ids: Vec<String> = config.jobs.iter().map(|j| j.id.clone()).collect();

    // Load all job statuses via spawn_blocking (works on both single- and multi-threaded runtimes).
    let status_map: std::collections::HashMap<String, crate::daemon::db::models::JobStatusRow> =
        if let Some(ref store) = store_opt {
            let store_clone = Arc::clone(store);
            let ids = job_ids.clone();
            tokio::task::spawn_blocking(move || {
                let mut map = std::collections::HashMap::new();
                for id in &ids {
                    if let Ok(Some(row)) = store_clone.load_job_status(id) {
                        map.insert(id.clone(), row);
                    }
                }
                map
            })
            .await
            .map_err(|e| format!("load_job_status panicked: {e}"))?
        } else {
            std::collections::HashMap::new()
        };

    let mut summaries = Vec::with_capacity(config.jobs.len());

    for job in &config.jobs {
        let kind_str = match job.kind {
            JobKind::RecordSync => "record_sync",
            JobKind::ZoneSync => "zone_sync",
            JobKind::ZoneExport => "zone_export",
        }
        .to_string();

        let (state, last_run_at, consecutive_failures) = if let Some(row) = status_map.get(&job.id)
        {
            (
                row.current_state.clone(),
                row.last_finished_at.clone(),
                row.consecutive_failures,
            )
        } else {
            ("unknown".to_string(), None, 0)
        };

        summaries.push(JobSummary {
            job_id: job.id.clone(),
            kind: kind_str,
            enabled: job.enabled,
            state,
            last_run_at,
            consecutive_failures,
        });
    }

    info!(job_count = summaries.len(), "job list assembled");
    Ok(summaries)
}

// ─── run_job ───────────────────────────────────────────────────────────────────

/// Trigger a configured job immediately and return its outcome.
///
/// Attempts to persist the run record and updated job status to the state database when the database can be opened; if persistence fails after the DB is opened, an `Err(String)` is returned. If the configured job id is not found, returns an error describing the missing job.
///
/// # Returns
/// `JobOutcome` describing the job result; on failure returns an error message (`String`).
///
/// # Examples
///
/// ```text
/// // Example (illustrative):
/// // let config = /* an AppConfig with a job having id "job-id" */;
/// // let outcome = tokio::runtime::Runtime::new().unwrap()
/// //     .block_on(run_job(&config, "job-id"))
/// //     .unwrap();
/// // assert!(matches!(outcome, JobOutcome::Success | JobOutcome::Failure { .. } | JobOutcome::DryRun));
/// ```
#[instrument(skip(config), fields(job_id = %job_id))]
pub async fn run_job(config: &AppConfig, job_id: &str) -> Result<JobOutcome, String> {
    // Verify the job exists.
    if config.jobs.iter().find(|j| j.id == job_id).is_none() {
        return Err(format!("job not found: {job_id}"));
    }

    let executor =
        build_executor(config, job_id).ok_or_else(|| format!("job not found: {job_id}"))?;

    let run_id = uuid::Uuid::new_v4().to_string();
    let started_at = Utc::now();
    info!(run_id = %run_id, trigger = "manual", "job triggered");

    let ctx = JobContext {
        run_id: run_id.clone(),
        job_id: job_id.to_string(),
        trigger: TriggerKind::Manual,
        dry_run: false,
    };

    let (outcome, duration) = executor.execute(&ctx).await;

    let outcome_str = match &outcome {
        JobOutcome::Success => "success",
        JobOutcome::Failure { .. } => "failure",
        JobOutcome::DryRun => "dry_run",
    };
    info!(
        run_id = %run_id,
        outcome = outcome_str,
        duration_ms = duration.as_millis(),
        "job finished"
    );

    // Persist to DB if possible.
    let db_path = resolve_state_db(config);
    if let Ok(pool) = db::open(&db_path) {
        let store = DaemonStateStore::new(pool);
        let store = Arc::new(store);

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

        let job_kind_str = config
            .jobs
            .iter()
            .find(|j| j.id == job_id)
            .map(|j| match j.kind {
                JobKind::RecordSync => "record_sync",
                JobKind::ZoneSync => "zone_sync",
                JobKind::ZoneExport => "zone_export",
            })
            .unwrap_or("unknown")
            .to_string();

        let job_run = JobRunRow {
            run_id: run_id.clone(),
            job_id: job_id.to_string(),
            job_kind: job_kind_str.clone(),
            trigger_kind: "manual".to_string(),
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
            job_id: job_id.to_string(),
            job_kind: job_kind_str,
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

        let store_run = Arc::clone(&store);
        tokio::task::spawn_blocking(move || store_run.append_job_run(job_run))
            .await
            .unwrap_or_else(|e| Err(format!("spawn_blocking panicked: {e}")))
            .map_err(|e| format!("failed to persist job run to DB: {e}"))?;

        let store_status = Arc::clone(&store);
        tokio::task::spawn_blocking(move || store_status.save_job_status(job_status))
            .await
            .unwrap_or_else(|e| Err(format!("spawn_blocking panicked: {e}")))
            .map_err(|e| format!("failed to persist job status to DB: {e}"))?;
    }

    Ok(outcome)
}

// ─── healthcheck ──────────────────────────────────────────────────────────────

/// Check daemon health by reading the daemon state database.
///
/// Returns `Ok(true)` when the stored daemon state equals `"live"` and the overall health is not `"fatal"`,
/// `Ok(false)` when the DB exists but the stored state indicates the daemon is not healthy.
///
/// # Errors
/// Returns `Err` when the state DB file does not exist or when no health record is found in the DB.
///
/// # Examples
///
/// ```rust,ignore
/// # use crate::config::AppConfig;
/// # async fn example(config: &AppConfig) -> Result<(), String> {
/// let healthy = crate::daemon::commands::healthcheck(config).await?;
/// println!("daemon healthy: {}", healthy);
/// # Ok(())
/// # }
/// ```
#[instrument(skip(config))]
pub async fn healthcheck(config: &AppConfig) -> Result<bool, String> {
    let db_path = resolve_state_db(config);
    debug!(db_path = %db_path.display(), "resolved state DB path for healthcheck");

    if !db_path.exists() {
        warn!(db_path = %db_path.display(), "state DB does not exist; daemon has never started");
        return Err("state database does not exist (daemon has never started)".to_string());
    }

    let pool = db::open(&db_path)?;
    let store = Arc::new(DaemonStateStore::new(pool));

    let health = tokio::task::spawn_blocking(move || store.load_daemon_health())
        .await
        .map_err(|e| format!("load_daemon_health panicked: {e}"))??;

    match health {
        None => {
            warn!("no health record found in state database");
            Err("no health record found in state database".to_string())
        }
        Some(row) => {
            let is_live = row.daemon_state == "live";
            let is_not_fatal = row.overall_health != "fatal";
            let healthy = is_live && is_not_fatal;
            info!(
                daemon_state = %row.daemon_state,
                overall_health = %row.overall_health,
                healthy,
                "healthcheck result"
            );
            Ok(healthy)
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
