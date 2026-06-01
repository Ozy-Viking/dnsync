
use super::*;
use crate::control_plane::config::{AppConfig, JobConfig, JobKind};
use std::collections::BTreeMap;

/// Creates an AppConfig with no servers, no clusters, no daemon configuration, and no jobs.
///
/// # Examples
///
/// ```rust,ignore
/// let cfg = empty_config();
/// assert!(cfg.servers.is_empty());
/// assert!(cfg.clusters.is_empty());
/// assert!(cfg.daemon.is_none());
/// assert!(cfg.jobs.is_empty());
/// ```
fn empty_config() -> AppConfig {
    AppConfig {
        servers: vec![],
        clusters: BTreeMap::new(),
        daemon: None,
        jobs: vec![],
    }
}

/// Create an AppConfig containing two sample jobs for use in unit tests.
///
/// The returned config contains:
/// - `job-alpha`: a record sync job scheduled `@hourly` (enabled).
/// - `job-beta`: a zone export job scheduled `@daily` (disabled) with `output_dir` set to `/tmp/zones`.
///
/// # Examples
///
/// ```rust,ignore
/// let cfg = config_with_jobs();
/// assert_eq!(cfg.jobs.len(), 2);
/// assert_eq!(cfg.jobs[0].id, "job-alpha");
/// assert_eq!(cfg.jobs[1].id, "job-beta");
/// ```
fn config_with_jobs() -> AppConfig {
    let job1 = JobConfig {
        id: "job-alpha".to_string(),
        kind: JobKind::RecordSync,
        enabled: true,
        critical: false,
        schedule: Some("@hourly".to_string()),
        interval: None,
        timezone: None,
        run_immediately: false,
        jitter: None,
        dry_run: false,
        from: Some("src".to_string()),
        to: Some("dst".to_string()),
        zones: vec![],
        ip_map: BTreeMap::new(),
        create_missing: true,
        overwrite_existing: true,
        delete_destination_only: false,
        ignore: vec![],
        output_dir: None,
    };
    let job2 = JobConfig {
        id: "job-beta".to_string(),
        kind: JobKind::ZoneExport,
        enabled: false,
        critical: false,
        schedule: Some("@daily".to_string()),
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
    };
    AppConfig {
        servers: vec![],
        clusters: BTreeMap::new(),
        daemon: None,
        jobs: vec![job1, job2],
    }
}

// ── test_list_jobs_empty_config ───────────────────────────────────────────

/// Config with no jobs: list_jobs returns empty vec.
#[tokio::test]
async fn test_list_jobs_empty_config() {
    let config = empty_config();
    let result = list_jobs(&config).await.expect("should succeed");
    assert!(
        result.is_empty(),
        "expected empty list for config with no jobs"
    );
}

// ── test_list_jobs_merges_config_and_db ───────────────────────────────────

/// Config has 2 jobs; DB has status for 1; result has both with correct state.
#[tokio::test]
async fn test_list_jobs_merges_config_and_db() {
    use crate::daemon::db;
    use crate::daemon::db::models::JobStatusRow;
    use crate::daemon::db::store::DaemonStateStore;

    // Open a temp DB and insert a status row for job-alpha only.
    let dir = std::env::temp_dir().join(format!("dnsync-cmd-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join(format!(
        "test-list-{}.sqlite",
        uuid::Uuid::new_v4().as_simple()
    ));
    let pool = db::open(&db_path).expect("test db should open");
    let store = DaemonStateStore::new(pool);
    store
        .save_job_status(JobStatusRow {
            job_id: "job-alpha".to_string(),
            job_kind: "record_sync".to_string(),
            enabled: 1,
            current_state: "healthy".to_string(),
            last_started_at: None,
            last_finished_at: Some("2026-01-01T00:00:00Z".to_string()),
            last_success_at: Some("2026-01-01T00:00:00Z".to_string()),
            last_failure_at: None,
            last_error_summary: None,
            consecutive_failures: 0,
            last_run_id: Some("run-1".to_string()),
        })
        .expect("save_job_status should succeed");

    // Build a config that points to this DB.
    let mut config = config_with_jobs();
    config.daemon = Some(crate::control_plane::config::DaemonConfig {
        state_db: Some(db_path),
        heartbeat_interval: "5s".to_string(),
        heartbeat_timeout: "20s".to_string(),
        shutdown_timeout: "5s".to_string(),
        worker_threads: 4,
        critical_failure_threshold: 5,
    });

    let summaries = list_jobs(&config).await.expect("list_jobs should succeed");

    assert_eq!(
        summaries.len(),
        2,
        "expected 2 summaries (one per job in config)"
    );

    let alpha = summaries
        .iter()
        .find(|s| s.job_id == "job-alpha")
        .expect("should have job-alpha");
    assert_eq!(
        alpha.state, "healthy",
        "job-alpha should have state from DB"
    );
    assert_eq!(alpha.kind, "record_sync");
    assert!(alpha.enabled);

    let beta = summaries
        .iter()
        .find(|s| s.job_id == "job-beta")
        .expect("should have job-beta");
    assert_eq!(
        beta.state, "unknown",
        "job-beta should be 'unknown' (no DB row)"
    );
    assert_eq!(beta.kind, "zone_export");
    assert!(!beta.enabled);
}

// ── test_run_job_unknown_id ───────────────────────────────────────────────

/// run_job with an unknown job_id should return Err containing "job not found".
#[tokio::test]
async fn test_run_job_unknown_id() {
    let config = empty_config();
    let result = run_job(&config, "no-such-job").await;
    assert!(
        result.is_err(),
        "expected Err for unknown job id, got: {result:?}"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("job not found"),
        "expected 'job not found' in error, got: {err}"
    );
    assert!(
        err.contains("no-such-job"),
        "expected job id in error, got: {err}"
    );
}
