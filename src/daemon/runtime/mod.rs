//! Daemon run loop — the entry point for `dnsync daemon`.
//!
//! Responsibilities:
//! 1. Opens the SQLite state DB.
//! 2. Creates a `DaemonStateStore`.
//! 3. Spawns the DB writer task.
//! 4. Builds `ScheduledJob` list from config.
//! 5. Spawns the worker pool.
//! 6. Runs the scheduling loop (sleep → trigger → repeat).
//! 7. Handles graceful shutdown on ctrl-c or cancellation token.
//! 8. Writes `DaemonHealthRow` on startup; updates `daemon_state` to "stopped" on shutdown.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use rand::SeedableRng;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument, warn};

use crate::control_plane::config::{AppConfig, JobKind};
use crate::daemon::{
    db::{self, models::DaemonHealthRow, store::DaemonStateStore},
    executor::{RecordSyncExecutor, ZoneExportExecutor, ZoneSyncExecutor},
    schedule::parse_schedule,
    scheduler::{JobTrigger, ScheduledJob, apply_jitter, next_job_to_fire},
    types::TriggerKind,
    worker::{DbWriteRequest, spawn_db_writer, spawn_workers},
};

// ─── State DB path resolution ──────────────────────────────────────────────────

/// Resolve the SQLite state database path for the daemon.
///
/// Priority:
/// 1. `config.daemon.state_db` if present.
/// 2. `DNSYNC_STATE_DB` environment variable if set.
/// 3. `$XDG_DATA_HOME/dnsync/state.db`, or `$HOME/.local/share/dnsync/state.db`, or `./dnsync/state.db` as a final fallback.
///
/// # Examples
///
/// ```rust,ignore,ignore
/// // If daemon state_db is not set, the environment variable will be used:
/// std::env::set_var("DNSYNC_STATE_DB", "/tmp/my_state.db");
/// let cfg = /* AppConfig with no daemon.state_db */;
/// let path = resolve_state_db(&cfg);
/// assert_eq!(path, std::path::PathBuf::from("/tmp/my_state.db"));
/// ```
fn resolve_state_db(config: &AppConfig) -> std::path::PathBuf {
    crate::daemon::state_path::resolve_state_db(config)
}

// ─── parse_shutdown_timeout ────────────────────────────────────────────────────

/// Parse a short duration string using an integer followed by `s` (seconds) or `m` (minutes).
///
/// Accepts trimmed inputs like `"5s"` or `"1m"`. If the input is invalid or uses an unsupported
/// suffix the function returns a default of 5 seconds.
///
/// # Examples
///
/// ```text
/// use std::time::Duration;
/// assert_eq!(super::parse_duration("10s"), Duration::from_secs(10));
/// assert_eq!(super::parse_duration("2m"), Duration::from_secs(120));
/// assert_eq!(super::parse_duration(" invalid "), Duration::from_secs(5));
/// ```
fn parse_duration(s: &str) -> Duration {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('s') {
        if let Ok(secs) = n.parse::<u64>() {
            return Duration::from_secs(secs);
        }
    }
    if let Some(n) = s.strip_suffix('m') {
        if let Ok(mins) = n.parse::<u64>() {
            return Duration::from_secs(mins * 60);
        }
    }
    // Default to 5 seconds if parsing fails.
    Duration::from_secs(5)
}

// ─── run ───────────────────────────────────────────────────────────────────────

/// Runs the daemon main loop until the provided cancellation token is triggered or the process receives ctrl-c.
///
/// The function opens and initializes the state database, starts background workers (including a DB writer and job executors),
/// schedules and triggers jobs per configuration, and performs a graceful shutdown sequence when cancelled.
///
/// # Returns
///
/// `Ok(())` when the daemon stops after receiving a cancellation signal or ctrl-c; `Err(String)` if startup fails (for example,
/// opening the state DB or writing the initial health row).
///
/// # Examples
///
/// ```rust,ignore
/// use tokio::time::timeout;
/// use tokio_util::sync::CancellationToken;
///
/// #[tokio::main]
/// async fn main() {
///     let config = /* build AppConfig */ todo!();
///     let cancel = CancellationToken::new();
///     let handle = tokio::spawn(async move { crate::daemon::runtime::run(config, cancel.clone()).await });
///     // trigger shutdown immediately for demonstration
///     cancel.cancel();
///     let res = timeout(std::time::Duration::from_secs(1), handle).await;
///     assert!(res.is_ok());
/// }
/// ```
#[instrument(skip(config, cancel), fields(daemon_id))]
pub async fn run(config: AppConfig, cancel: CancellationToken) -> Result<(), String> {
    let daemon_id = uuid::Uuid::new_v4().to_string();
    tracing::Span::current().record("daemon_id", &daemon_id.as_str());
    let started_at = Utc::now().to_rfc3339();

    // ── 1. Open state DB ──────────────────────────────────────────────────────
    let db_path = resolve_state_db(&config);
    debug!(db_path = %db_path.display(), "opening state DB");
    let pool = db::open(&db_path)?;
    let store = DaemonStateStore::new(pool);

    // ── 2. Spawn DB writer task ───────────────────────────────────────────────
    let (db_write_tx, db_write_rx) = mpsc::channel::<DbWriteRequest>(256);
    info!("starting DB writer task");
    let db_writer_handle = spawn_db_writer(DaemonStateStore::new(db::open(&db_path)?), db_write_rx);

    // ── 3. Write startup health row ───────────────────────────────────────────
    let jobs_total = config.jobs.len() as i32;
    let jobs_enabled = config.jobs.iter().filter(|j| j.enabled).count() as i32;

    let startup_health = DaemonHealthRow {
        id: 1,
        daemon_id: daemon_id.clone(),
        started_at: started_at.clone(),
        last_heartbeat_at: started_at.clone(),
        daemon_state: "live".to_string(),
        overall_health: "healthy".to_string(),
        last_health_change_at: started_at.clone(),
        last_error_summary: None,
        jobs_total,
        jobs_enabled,
        jobs_healthy: jobs_enabled,
        jobs_degraded: 0,
        jobs_running: 0,
    };

    {
        let store_ref = Arc::new(DaemonStateStore::new(db::open(&db_path)?));
        let health = startup_health.clone();
        tokio::task::spawn_blocking(move || store_ref.save_daemon_health(health))
            .await
            .map_err(|e| format!("startup health write panicked: {e}"))?
            .map_err(|e| format!("startup health write failed: {e}"))?;
    }

    info!(daemon_id = %daemon_id, "daemon started");

    // ── 4. Build executor closure ─────────────────────────────────────────────
    // A dedicated store handle for ownership-ledger reads/writes during job
    // runs, separate from the DB-writer task's connection.
    let ledger_store = Arc::new(DaemonStateStore::new(db::open(&db_path)?));
    let config_arc = Arc::new(config.clone());
    let executors: Arc<
        dyn Fn(&str) -> Option<Arc<dyn crate::daemon::executor::JobExecutor>> + Send + Sync,
    > = {
        let cfg = Arc::clone(&config_arc);
        let ledger_store = Arc::clone(&ledger_store);
        Arc::new(move |job_id: &str| {
            let job = cfg.jobs.iter().find(|j| j.id == job_id)?;
            let exec: Arc<dyn crate::daemon::executor::JobExecutor> = match job.kind {
                JobKind::RecordSync => Arc::new(RecordSyncExecutor {
                    config: (*cfg).clone(),
                    job_id: job_id.to_string(),
                    ledger: Some(Arc::clone(&ledger_store)),
                }),
                JobKind::ZoneSync => Arc::new(ZoneSyncExecutor {
                    config: (*cfg).clone(),
                    job_id: job_id.to_string(),
                }),
                JobKind::ZoneExport => Arc::new(ZoneExportExecutor {
                    config: (*cfg).clone(),
                    job_id: job_id.to_string(),
                }),
            };
            Some(exec)
        })
    };

    // ── 5. Spawn worker pool ──────────────────────────────────────────────────
    let num_workers = config.daemon.as_ref().map_or(4, |d| d.worker_threads);
    info!(num_workers = num_workers, "starting worker pool");
    let job_tx = spawn_workers(num_workers, 64, executors, db_write_tx.clone()).await;

    // ── 6. Build scheduled jobs list ─────────────────────────────────────────
    let mut scheduled_jobs: Vec<ScheduledJob> = Vec::new();
    debug!(
        total_jobs = config.jobs.len(),
        "building scheduled jobs list"
    );
    for job in &config.jobs {
        let schedule_str = job
            .schedule
            .as_deref()
            .or(job.interval.as_deref())
            .unwrap_or("5m");

        let cron_expr = match parse_schedule(schedule_str) {
            Ok(expr) => expr,
            Err(e) => {
                warn!(job_id = %job.id, error = %e, "skipping job with invalid schedule");
                continue;
            }
        };

        let timezone = job
            .timezone
            .as_deref()
            .and_then(|tz| tz.parse::<chrono_tz::Tz>().ok())
            .unwrap_or(chrono_tz::UTC);

        let jitter_max = job
            .jitter
            .as_deref()
            .map(parse_duration)
            .unwrap_or(Duration::ZERO);

        debug!(
            job_id = %job.id,
            enabled = job.enabled,
            "scheduled job registered"
        );
        scheduled_jobs.push(ScheduledJob {
            id: job.id.clone(),
            cron_expr,
            timezone,
            jitter_max,
            enabled: job.enabled,
        });
    }

    // ── 7. Fire run_immediately jobs right away ────────────────────────────────
    for job in config
        .jobs
        .iter()
        .filter(|j| j.run_immediately && j.enabled)
    {
        info!(job_id = %job.id, "triggering run_immediately job");
        let trigger = JobTrigger {
            job_id: job.id.clone(),
            scheduled_at: Utc::now(),
            trigger_kind: TriggerKind::Scheduled,
            dry_run: job.dry_run,
        };
        match job_tx.try_send(trigger) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                warn!(job_id = %job.id, "run_immediately trigger dropped — queue full");
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                info!(job_id = %job.id, "job channel closed — stopping scheduler");
            }
        }
    }

    // ── 8. Determine shutdown timeout ─────────────────────────────────────────
    let shutdown_timeout = config
        .daemon
        .as_ref()
        .map(|d| parse_duration(&d.shutdown_timeout))
        .unwrap_or(Duration::from_secs(5));

    // ── 9. Scheduling loop ────────────────────────────────────────────────────
    info!("entering scheduling loop");

    loop {
        let mut rng = rand::rngs::StdRng::from_entropy();
        if scheduled_jobs.is_empty() {
            // No jobs configured — just wait for shutdown signal.
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::signal::ctrl_c() => break,
            }
        }

        let now = Utc::now();
        let Some((next_job, fire_time)) = next_job_to_fire(&scheduled_jobs, now) else {
            // All jobs disabled — wait for shutdown.
            tokio::select! {
                _ = cancel.cancelled() => {},
                _ = tokio::signal::ctrl_c() => {},
            }
            break;
        };

        debug!(
            job_id = %next_job.id,
            fire_time = %fire_time,
            "scheduler tick: next job selected"
        );

        let fire_time_with_jitter = apply_jitter(fire_time, next_job.jitter_max, &mut rng);

        if fire_time_with_jitter != fire_time {
            debug!(
                job_id = %next_job.id,
                fire_time_with_jitter = %fire_time_with_jitter,
                "jitter applied to fire time"
            );
        }

        let sleep_duration = (fire_time_with_jitter - now)
            .to_std()
            .unwrap_or(Duration::ZERO);

        let deadline = tokio::time::Instant::now() + sleep_duration;

        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                info!(job_id = %next_job.id, scheduled_at = %fire_time, "triggering scheduled job");
                let dry_run = config_arc
                    .jobs
                    .iter()
                    .find(|j| j.id == next_job.id)
                    .map(|j| j.dry_run)
                    .unwrap_or(false);
                let trigger = JobTrigger {
                    job_id: next_job.id.clone(),
                    scheduled_at: fire_time,
                    trigger_kind: TriggerKind::Scheduled,
                    dry_run,
                };
                match job_tx.try_send(trigger) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        warn!(job_id = %next_job.id, "job queue full — trigger dropped");
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        info!(job_id = %next_job.id, "job channel closed — stopping scheduler");
                        break;
                    }
                }
            }
            _ = cancel.cancelled() => {
                info!("cancellation token triggered — shutting down");
                break;
            }
            _ = tokio::signal::ctrl_c() => {
                info!("ctrl-c received — shutting down");
                break;
            }
        }
    }

    // ── 10. Graceful shutdown ─────────────────────────────────────────────────
    // Drop job_tx so workers drain and exit.
    info!("draining worker pool (dropping job_tx)");
    drop(job_tx);

    // Wait up to shutdown_timeout for in-flight jobs to finish.
    // We accomplish this by waiting for the db_write_tx to be the sole holder.
    let shutdown_deadline = tokio::time::Instant::now() + shutdown_timeout;
    while db_write_tx.strong_count() > 1 {
        if tokio::time::Instant::now() >= shutdown_deadline {
            warn!("shutdown timeout reached — some in-flight jobs may not have finished");
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Drop db_write_tx so the DB writer task drains and exits, then await it.
    drop(db_write_tx);
    let _ = db_writer_handle.await;

    // Update daemon health to "stopped".
    let stopped_health = DaemonHealthRow {
        daemon_state: "stopped".to_string(),
        last_heartbeat_at: Utc::now().to_rfc3339(),
        ..startup_health
    };

    {
        let store_ref = Arc::new(store);
        let health = stopped_health;
        if let Err(e) = tokio::task::spawn_blocking(move || store_ref.save_daemon_health(health))
            .await
            .map_err(|e| format!("shutdown health write panicked: {e}"))
            .and_then(|r| r.map_err(|e| format!("shutdown health write failed: {e}")))
        {
            error!(error = %e, "failed to write stopped state to DB");
        }
    }

    info!(daemon_id = %daemon_id, "daemon stopped");
    Ok(())
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
