//! Daemon-related CLI command handling: `daemon`, `job`, and `healthcheck`.
//!
//! These need the application config but not a single-server client, so they are
//! dispatched before single-client resolution.

use std::path::PathBuf;

use crate::{
    cli::JobCmd,
    control_plane::config,
    core::error::{self, Result},
    daemon::{commands as daemon_commands, executor::JobOutcome, runtime as daemon_runtime},
};

/// Run the sync daemon in the foreground until cancelled.
///
/// The daemon runtime already shuts down on its cancellation token or Ctrl-C
/// (SIGINT). Here we additionally wire SIGTERM (used by Docker/systemd `stop`)
/// to the same token so containerised deployments shut down gracefully.
pub async fn handle_daemon(config_path: Option<PathBuf>) -> Result<()> {
    let cfg = config::AppConfig::load(config_path)?.unwrap_or_default();
    let cancel = tokio_util::sync::CancellationToken::new();
    spawn_sigterm_listener(cancel.clone());
    daemon_runtime::run(cfg, cancel)
        .await
        .map_err(error::Error::config)?;
    Ok(())
}

/// Cancel `cancel` when the process receives SIGTERM. No-op on non-Unix
/// platforms, where SIGTERM does not exist (Ctrl-C is still handled by the
/// runtime).
fn spawn_sigterm_listener(cancel: tokio_util::sync::CancellationToken) {
    #[cfg(unix)]
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                sigterm.recv().await;
                tracing::info!("received SIGTERM; shutting down daemon");
                cancel.cancel();
            }
            Err(e) => tracing::warn!("failed to install SIGTERM handler: {e}"),
        }
    });
    #[cfg(not(unix))]
    let _ = cancel;
}

/// Handle a `job` subcommand (list configured jobs or run a single job).
pub async fn handle_job(config_path: Option<PathBuf>, job_cmd: &JobCmd) -> Result<()> {
    let cfg = config::AppConfig::load(config_path)?.unwrap_or_default();
    match job_cmd {
        JobCmd::List => {
            let summaries = daemon_commands::list_jobs(&cfg)
                .await
                .map_err(error::Error::config)?;
            if summaries.is_empty() {
                println!("No jobs configured.");
            } else {
                println!(
                    "{:<24} {:<14} {:<8} {:<12} {:<6}  LAST RUN",
                    "JOB ID", "KIND", "ENABLED", "STATE", "FAILS"
                );
                println!("{}", "-".repeat(90));
                for s in &summaries {
                    println!(
                        "{:<24} {:<14} {:<8} {:<12} {:<6}  {}",
                        s.job_id,
                        s.kind,
                        if s.enabled { "yes" } else { "no" },
                        s.state,
                        s.consecutive_failures,
                        s.last_run_at.as_deref().unwrap_or("never"),
                    );
                }
            }
            Ok(())
        }
        JobCmd::Run { id } => {
            let outcome = daemon_commands::run_job(&cfg, id)
                .await
                .map_err(error::Error::config)?;
            match outcome {
                JobOutcome::Success => println!("Job '{id}' completed successfully."),
                JobOutcome::DryRun => {
                    println!("Job '{id}' completed (dry run — no changes applied).")
                }
                JobOutcome::Failure { error: msg } => {
                    eprintln!("Job '{id}' failed: {msg}");
                    std::process::exit(1);
                }
            }
            Ok(())
        }
    }
}

/// Check whether the daemon is healthy. Exits the process with code 1 when the
/// daemon is unhealthy or unreachable.
pub async fn handle_healthcheck(config_path: Option<PathBuf>) -> Result<()> {
    let cfg = config::AppConfig::load_if_exists(config_path)?.unwrap_or_default();
    match daemon_commands::healthcheck(&cfg).await {
        Ok(true) => {
            println!("daemon is live and healthy");
            Ok(())
        }
        Ok(false) => {
            eprintln!("daemon is not healthy");
            std::process::exit(1);
        }
        Err(msg) => {
            eprintln!("{msg}");
            std::process::exit(1);
        }
    }
}
