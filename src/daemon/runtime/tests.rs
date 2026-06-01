use super::*;
use crate::control_plane::config::AppConfig;
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;

/// Creates a minimal AppConfig for tests using the provided SQLite state DB path.

///

/// The returned config contains no servers or jobs and a daemon configuration tuned for fast test runs:

/// short heartbeat intervals, a 1 second shutdown timeout, a single worker thread, and a critical failure threshold of 5.

///

/// # Examples

///

/// ```rust,ignore

/// let db_path = std::path::PathBuf::from("/tmp/test_state.db");

/// let cfg = minimal_config(db_path.clone());

/// assert!(cfg.servers.is_empty());

/// assert!(cfg.jobs.is_empty());

/// let daemon = cfg.daemon.unwrap();

/// assert_eq!(daemon.state_db.unwrap(), db_path);

/// assert_eq!(daemon.shutdown_timeout, "1s");

/// assert_eq!(daemon.worker_threads, 1);

/// ```
fn minimal_config(db_path: std::path::PathBuf) -> AppConfig {
    AppConfig {
        servers: vec![],
        clusters: BTreeMap::new(),
        daemon: Some(crate::control_plane::config::DaemonConfig {
            state_db: Some(db_path),
            heartbeat_interval: "5s".to_string(),
            heartbeat_timeout: "20s".to_string(),
            shutdown_timeout: "1s".to_string(),
            worker_threads: 1,
            critical_failure_threshold: 5,
        }),
        jobs: vec![],
    }
}

/// Returns a unique PathBuf for a temporary SQLite file placed in a per-process
/// subdirectory of the system temp directory.
///
/// The path is of the form `<temp_dir>/dnsync-runtime-test-<pid>/runtime-<uuid>.sqlite`.
///
/// # Examples
///
/// ```rust,ignore
/// let p = temp_db_path();
/// // parent directory is created
/// assert!(p.parent().unwrap().exists());
/// // file name uses the .sqlite extension
/// assert_eq!(p.extension().and_then(|s| s.to_str()), Some("sqlite"));
/// ```
fn temp_db_path() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("dnsync-runtime-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(format!(
        "runtime-{}.sqlite",
        uuid::Uuid::new_v4().as_simple()
    ))
}

/// Smoke test: run with no jobs, immediately cancel — must finish within 1 second.
#[tokio::test]
async fn test_run_exits_on_cancel() {
    let db_path = temp_db_path();
    let config = minimal_config(db_path);
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let handle = tokio::spawn(async move { run(config, cancel_clone).await });

    // Cancel immediately.
    cancel.cancel();

    let result = tokio::time::timeout(std::time::Duration::from_secs(1), handle)
        .await
        .expect("run() should complete within 1 second after cancel")
        .expect("task should not have panicked");

    assert!(
        result.is_ok(),
        "run() should return Ok after cancel, got: {result:?}"
    );
}
