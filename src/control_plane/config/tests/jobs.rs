use super::*;

/// Verifies that a minimal `record_sync` job deserializes from TOML and passes validation.
///
/// # Examples
///
/// ```rust,ignore
/// let toml = r#"
/// [[servers]]
/// id = "cf"
/// token = "tok"
///
/// [[servers]]
/// id = "home"
/// token = "tok"
///
/// [[jobs]]
/// id = "sync-cf-home"
/// kind = "record_sync"
/// interval = "5m"
/// from = "cf"
/// to = "home"
/// "#;
/// let config: AppConfig = toml::from_str(toml).expect("should parse");
/// config.validate().expect("should validate");
/// assert_eq!(config.jobs.len(), 1);
/// let job = &config.jobs[0];
/// assert_eq!(job.kind, JobKind::RecordSync);
/// ```
#[test]
fn parses_minimal_record_sync_job() {
    let toml = concat!(
        r#"
            [[servers]]
            id = "cf"
            token = "tok"

            [[servers]]
            id = "home"
            token = "tok"

            [[jobs]]
            id = "sync-cf-home"
            kind = "record_sync"
            interval = "5m"
            from = "cf"
            to = "home"
            "#
    );
    let config: AppConfig = toml::from_str(toml).expect("should parse");
    config.validate().expect("should validate");
    assert_eq!(config.jobs.len(), 1);
    let job = &config.jobs[0];
    assert_eq!(job.id, "sync-cf-home");
    assert_eq!(job.kind, JobKind::RecordSync);
    assert_eq!(job.interval.as_deref(), Some("5m"));
    assert_eq!(job.from.as_deref(), Some("cf"));
    assert_eq!(job.to.as_deref(), Some("home"));
    assert!(job.enabled);
    assert!(!job.critical);
}

#[test]
fn parses_full_record_sync_job_with_all_fields() {
    let toml = concat!(
        r#"
            [[servers]]
            id = "src"
            token = "tok"

            [[servers]]
            id = "dst"
            token = "tok"

            [[jobs]]
            id = "full-job"
            kind = "record_sync"
            enabled = true
            critical = true
            schedule = "*/5 * * * *"
            timezone = "America/New_York"
            run_immediately = true
            jitter = "30s"
            dry_run = true
            from = "src"
            to = "dst"
            zones = ["example.com", "internal.lan"]
            create_missing = false
            overwrite_existing = false
            delete_destination_only = true
            ignore = ["^_dmarc\\."]

            [jobs.ip_map]
            "203.0.113.10" = "192.168.1.10"
            "#
    );
    let config: AppConfig = toml::from_str(toml).expect("should parse");
    config.validate().expect("should validate");
    let job = &config.jobs[0];
    assert_eq!(job.id, "full-job");
    assert!(job.critical);
    assert_eq!(job.schedule.as_deref(), Some("*/5 * * * *"));
    assert_eq!(job.timezone.as_deref(), Some("America/New_York"));
    assert!(job.run_immediately);
    assert_eq!(job.jitter.as_deref(), Some("30s"));
    assert!(job.dry_run);
    assert_eq!(job.zones, ["example.com", "internal.lan"]);
    assert!(!job.create_missing);
    assert!(!job.overwrite_existing);
    assert!(job.delete_destination_only);
    assert_eq!(job.ignore, ["^_dmarc\\."]);
    assert_eq!(
        job.ip_map.get("203.0.113.10").map(String::as_str),
        Some("192.168.1.10")
    );
}

#[test]
fn parses_zone_sync_job() {
    let toml = concat!(
        r#"
            [[servers]]
            id = "primary"
            token = "tok"

            [[servers]]
            id = "secondary"
            token = "tok"

            [[jobs]]
            id = "zone-sync"
            kind = "zone_sync"
            interval = "1h"
            from = "primary"
            to = "secondary"
            zones = ["example.com"]
            "#
    );
    let config: AppConfig = toml::from_str(toml).expect("should parse");
    config.validate().expect("should validate");
    let job = &config.jobs[0];
    assert_eq!(job.kind, JobKind::ZoneSync);
}

#[test]
fn parses_zone_export_job() {
    let toml = concat!(
        r#"
            [[servers]]
            id = "primary"
            token = "tok"

            [[jobs]]
            id = "zone-export"
            kind = "zone_export"
            interval = "1d"
            output_dir = "/tmp/zones"
            "#
    );
    let config: AppConfig = toml::from_str(toml).expect("should parse");
    config.validate().expect("should validate");
    let job = &config.jobs[0];
    assert_eq!(job.kind, JobKind::ZoneExport);
    assert_eq!(job.output_dir.as_deref(), Some("/tmp/zones"));
}

#[test]
fn parses_daemon_config() {
    let toml = concat!(
        r#"
            [[servers]]
            id = "home"
            token = "tok"

            [daemon]
            state_db = "/var/lib/dnsync/state.db"
            heartbeat_interval = "10s"
            worker_threads = 8
            critical_failure_threshold = 3
            "#
    );
    let config: AppConfig = toml::from_str(toml).expect("should parse");
    config.validate().expect("should validate");
    let daemon = config.daemon.as_ref().expect("daemon should be present");
    assert_eq!(
        daemon
            .state_db
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .as_deref(),
        Some("/var/lib/dnsync/state.db")
    );
    assert_eq!(daemon.heartbeat_interval, "10s");
    assert_eq!(daemon.worker_threads, 8);
    assert_eq!(daemon.critical_failure_threshold, 3);
    // defaults
    assert_eq!(daemon.heartbeat_timeout, "20s");
    assert_eq!(daemon.shutdown_timeout, "5s");
}

#[test]
fn rejects_duplicate_job_ids() {
    let toml = concat!(
        r#"
            [[servers]]
            id = "cf"
            token = "tok"

            [[servers]]
            id = "home"
            token = "tok"

            [[jobs]]
            id = "sync"
            kind = "record_sync"
            interval = "5m"
            from = "cf"
            to = "home"

            [[jobs]]
            id = "SYNC"
            kind = "record_sync"
            interval = "5m"
            from = "home"
            to = "cf"
            "#
    );
    let config: AppConfig = toml::from_str(toml).expect("should parse");
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("duplicate job id"));
}

#[test]
fn rejects_job_with_both_schedule_and_interval() {
    let toml = concat!(
        r#"
            [[servers]]
            id = "cf"
            token = "tok"

            [[servers]]
            id = "home"
            token = "tok"

            [[jobs]]
            id = "both"
            kind = "record_sync"
            schedule = "*/5 * * * *"
            interval = "5m"
            from = "cf"
            to = "home"
            "#
    );
    let config: AppConfig = toml::from_str(toml).expect("should parse");
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("both 'schedule' and 'interval'"));
}

#[test]
fn rejects_job_with_neither_schedule_nor_interval() {
    let toml = concat!(
        r#"
            [[servers]]
            id = "cf"
            token = "tok"

            [[servers]]
            id = "home"
            token = "tok"

            [[jobs]]
            id = "neither"
            kind = "record_sync"
            from = "cf"
            to = "home"
            "#
    );
    let config: AppConfig = toml::from_str(toml).expect("should parse");
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("either 'schedule' or 'interval'"));
}

#[test]
fn rejects_record_sync_job_missing_from() {
    let toml = concat!(
        r#"
            [[servers]]
            id = "home"
            token = "tok"

            [[jobs]]
            id = "no-from"
            kind = "record_sync"
            interval = "5m"
            to = "home"
            "#
    );
    let config: AppConfig = toml::from_str(toml).expect("should parse");
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("requires 'from'"));
}

#[test]
fn rejects_record_sync_job_missing_to() {
    let toml = concat!(
        r#"
            [[servers]]
            id = "home"
            token = "tok"

            [[jobs]]
            id = "no-to"
            kind = "record_sync"
            interval = "5m"
            from = "home"
            "#
    );
    let config: AppConfig = toml::from_str(toml).expect("should parse");
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("requires 'to'"));
}

#[test]
fn rejects_record_sync_job_same_from_to() {
    let toml = concat!(
        r#"
            [[servers]]
            id = "home"
            token = "tok"

            [[jobs]]
            id = "same"
            kind = "record_sync"
            interval = "5m"
            from = "home"
            to = "home"
            "#
    );
    let config: AppConfig = toml::from_str(toml).expect("should parse");
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("identical source and destination"));
}

/// Verifies that a `zone_export` job without `output_dir` fails validation.
///
/// # Examples
///
/// ```rust,ignore
/// let toml = concat!(
///     r#"
///     [[servers]]
///     id = "home"
///     token = "tok"
///
///     [[jobs]]
///     id = "no-output"
///     kind = "zone_export"
///     interval = "1d"
///     "#
/// );
/// let config: AppConfig = toml::from_str(toml).expect("should parse");
/// let err = config.validate().unwrap_err();
/// assert!(err.to_string().contains("requires 'output_dir'"));
/// ```
#[test]
fn rejects_zone_export_job_missing_output_dir() {
    let toml = concat!(
        r#"
            [[servers]]
            id = "home"
            token = "tok"

            [[jobs]]
            id = "no-output"
            kind = "zone_export"
            interval = "1d"
            "#
    );
    let config: AppConfig = toml::from_str(toml).expect("should parse");
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("requires 'output_dir'"));
}

#[test]
fn rejects_invalid_ip_map_entry_in_job() {
    let toml = concat!(
        r#"
            [[servers]]
            id = "cf"
            token = "tok"

            [[servers]]
            id = "home"
            token = "tok"

            [[jobs]]
            id = "bad-ip"
            kind = "record_sync"
            interval = "5m"
            from = "cf"
            to = "home"

            [jobs.ip_map]
            "203.0.113.10" = "fd00::1"
            "#
    );
    let config: AppConfig = toml::from_str(toml).expect("should parse");
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("IPv4 and IPv6"));
}
#[test]
fn cloudflare_inferred_local_server_does_not_get_provider_transport_defaults() {
    let cfg: AppConfig = toml::from_str(
        r#"
              [[servers]]
              id = "cf-localhost"
              vendor = "cloudflare"
              base_url = "http://localhost:5380"
              token_env = "TOKEN"
          "#,
    )
    .unwrap();

    let server = cfg.selected_server(None).unwrap();
    assert!(server.dns.is_none());
    assert!(server.dot.is_none());
    assert!(server.doh.is_none());
    assert!(server.doq.is_none());
}
