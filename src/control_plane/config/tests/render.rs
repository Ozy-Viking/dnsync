//! Round-trip tests for the config write side (`render` + `persist`).
//!
//! The parse side is well covered elsewhere; these tests exercise rendering an
//! `AppConfig` back to TOML and the in-place edit helpers (`add_server`,
//! `update_server_endpoint`, `update_defaults`) that must preserve unrelated
//! file content while staying re-parseable and valid.

use super::*;

// ── render_toml ─────────────────────────────────────────────────────────────

#[test]
fn starter_toml_is_valid_and_self_documenting() {
    let toml_str = AppConfig::render_starter_toml().expect("render starter");
    assert!(toml_str.contains("[[servers]]"));
    assert!(toml_str.contains("token_env"));
    // Must be loadable straight back into a valid config.
    let cfg: AppConfig = toml::from_str(&toml_str).expect("starter re-parses");
    cfg.validate().expect("starter validates");
    assert_eq!(cfg.servers.len(), 1);
}

#[test]
fn render_round_trips_servers_clusters_daemon_and_jobs() {
    let cfg: AppConfig = toml::from_str(
        r#"
            [[servers]]
            id = "home"
            vendor = "technitium"
            base_url = "http://home.local:5380"
            token = "home-token"

            [servers.dot]
            enabled = true
            addr = "10.0.0.1:853"
            server_name = "home.lan"

            [[servers.validation_endpoints]]
            name = "router"
            transport = "dns"
            address = "10.0.0.1"

            [[servers]]
            id = "lab"
            vendor = "technitium"
            base_url = "http://lab.local:5380"
            token_env = "LAB_TOKEN"

            [clusters.home-dns]
            members = ["home", "lab"]

            [daemon]
            heartbeat_interval = "5s"
            heartbeat_timeout = "20s"
            shutdown_timeout = "5s"
            worker_threads = 4
            critical_failure_threshold = 5

            [[jobs]]
            id = "sync-home-lab"
            kind = "record_sync"
            schedule = "0 * * * * *"
            from = "home"
            to = "lab"
            ignore = ["^_acme-challenge"]

            [jobs.ip_map]
            "10.0.0.1" = "10.1.0.1"
        "#,
    )
    .expect("rich config parses");
    cfg.validate().expect("rich config validates");

    let rendered = cfg.render_toml().expect("render");
    let reparsed: AppConfig = toml::from_str(&rendered).expect("rendered output re-parses");
    reparsed.validate().expect("rendered output validates");

    assert_eq!(reparsed.servers.len(), 2);
    let home = reparsed.selected_server(Some("home")).unwrap();
    assert_eq!(
        home.token.as_ref().map(ApiToken::expose_for_auth),
        Some("home-token")
    );
    assert_eq!(
        home.dot.as_ref().unwrap().addr.as_deref(),
        Some("10.0.0.1:853")
    );
    assert_eq!(home.validation_endpoints.len(), 1);

    let lab = reparsed.selected_server(Some("lab")).unwrap();
    assert_eq!(lab.token_env.as_deref(), Some("LAB_TOKEN"));
    assert!(lab.token.is_none());

    assert!(reparsed.clusters.contains_key("home-dns"));
    let daemon = reparsed.daemon.as_ref().expect("daemon preserved");
    assert_eq!(daemon.worker_threads, 4);

    assert_eq!(reparsed.jobs.len(), 1);
    assert_eq!(reparsed.jobs[0].from.as_deref(), Some("home"));
    assert_eq!(
        reparsed.jobs[0].ip_map.get("10.0.0.1").map(String::as_str),
        Some("10.1.0.1")
    );
}

/// Verifies that rendering a server without credentials writes an empty token placeholder.
///
/// Ensures that when a server has neither an explicit token nor a token environment variable,
/// `AppConfig::render_toml()` emits `token = ""` so the generated TOML contains a placeholder
/// for the credential field.
///
/// # Examples
///
/// ```
/// let mut s = server_with_url("http://x:5380");
/// s.id = "placeholder".into();
/// s.token = None;
/// s.token_env = None;
/// let cfg = AppConfig {
///     servers: vec![s],
///     clusters: std::collections::BTreeMap::new(),
///     daemon: None,
///     jobs: Vec::new(),
/// };
/// let rendered = cfg.render_toml().unwrap();
/// assert!(rendered.contains("token = \"\""));
/// ```
fn render_writes_empty_token_placeholder_when_no_credential() {
    let mut server = server_with_url("http://x:5380");
    server.id = "placeholder".into();
    server.token = None;
    server.token_env = None;
    let cfg = AppConfig {
        servers: vec![server],
        clusters: BTreeMap::new(),
        daemon: None,
        jobs: Vec::new(),
    };
    let rendered = cfg.render_toml().unwrap();
    assert!(
        rendered.contains("token = \"\""),
        "expected empty token placeholder, got:\n{rendered}"
    );
}

// ── add_server ──────────────────────────────────────────────────────────────

/// Creates a `DnsServerConfig` pre-populated with a sample URL, the given `id`, and a test API token.
///
/// Useful in tests to produce a valid server config quickly.
///
/// # Examples
///
/// ```
/// let s = server("home");
/// assert_eq!(s.id, "home");
/// assert!(s.token.is_some());
/// assert!(s.base_url.contains("example"));
/// ```
fn server(id: &str) -> DnsServerConfig {
    let mut s = server_with_url("http://example:5380");
    s.id = id.to_string();
    s.token = Some(ApiToken::new("tok"));
    s
}

/// Verifies that add_server creates a new config file on first call and appends subsequent servers.
///
/// The test creates a temporary config path, adds two servers (`"home"` then `"lab"`), loads the resulting
/// configuration, and asserts that both servers exist in insertion order.
///
/// # Examples
///
/// ```
/// let path = temp_config_path("add-server");
/// add_server(Some(path.clone()), server("home")).expect("first add creates file");
/// add_server(Some(path.clone()), server("lab")).expect("second add appends");
///
/// let cfg = load_from_path(&path).expect("load after adds");
/// let ids: Vec<&str> = cfg.servers.iter().map(|s| s.id.as_str()).collect();
/// assert_eq!(ids, vec!["home", "lab"]);
/// ```
#[test]
fn add_server_creates_file_then_appends() {
    let path = temp_config_path("add-server");
    add_server(Some(path.clone()), server("home")).expect("first add creates file");
    add_server(Some(path.clone()), server("lab")).expect("second add appends");

    let cfg = load_from_path(&path).expect("load after adds");
    let ids: Vec<&str> = cfg.servers.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, vec!["home", "lab"]);
}

#[test]
fn add_server_rejects_duplicate_id() {
    let path = temp_config_path("add-dup");
    add_server(Some(path.clone()), server("home")).unwrap();
    let err = add_server(Some(path.clone()), server("HOME"))
        .expect_err("duplicate id must be rejected")
        .to_string();
    assert!(err.contains("duplicate DNS server id"), "unexpected: {err}");
}

/// Ensures that appending a server preserves pre-existing comments in the config file.
///
/// Writes a hand-authored config containing a comment and a `[[servers]]` table, then calls
/// `add_server` to append another server and asserts the original comment remains and the new
/// server `id` appears in the file.
///
/// # Examples
///
/// ```
/// // Arrange: create config file with a leading comment and one server
/// let path = temp_config_path("add-comments");
/// ensure_config_dir(&path).unwrap();
/// write_private_file(&path, "# my hand-written comment\n[[servers]]\nid = \"home\"\n").unwrap();
///
/// // Act: append a new server
/// add_server(Some(path.clone()), server("lab")).expect("append to commented file");
///
/// // Assert: original comment still present and new server id written
/// let raw = std::fs::read_to_string(&path).unwrap();
/// assert!(raw.contains("# my hand-written comment"));
/// assert!(raw.contains("id = \"lab\""));
/// ```
#[test]
fn add_server_preserves_existing_comments() {
    let path = temp_config_path("add-comments");
    ensure_config_dir(&path).unwrap();
    write_private_file(
        &path,
        "# my hand-written comment\n[[servers]]\nid = \"home\"\ntoken = \"tok\"\n",
    )
    .unwrap();

    add_server(Some(path.clone()), server("lab")).expect("append to commented file");

    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(
        raw.contains("# my hand-written comment"),
        "comment was dropped:\n{raw}"
    );
    assert!(raw.contains("id = \"lab\""));
}

// ── update_server_endpoint ──────────────────────────────────────────────────

#[test]
fn update_server_endpoint_adds_then_removes_transport() {
    let path = temp_config_path("endpoint");
    add_server(Some(path.clone()), server("home")).unwrap();

    update_server_endpoint(
        Some(path.clone()),
        "home",
        EndpointUpdate::Dot(Some(DotTransportConfig {
            enabled: true,
            addr: Some("10.0.0.1:853".into()),
            server_name: Some("home.lan".into()),
            timeout_ms: None,
        })),
    )
    .expect("add dot endpoint");

    let cfg = load_from_path(&path).unwrap();
    let dot = cfg.selected_server(Some("home")).unwrap().dot.as_ref();
    assert_eq!(dot.unwrap().addr.as_deref(), Some("10.0.0.1:853"));

    update_server_endpoint(Some(path.clone()), "home", EndpointUpdate::Dot(None))
        .expect("remove dot endpoint");
    let cfg = load_from_path(&path).unwrap();
    assert!(cfg.selected_server(Some("home")).unwrap().dot.is_none());
}

/// Verifies that attempting to update an endpoint for a non-existent server returns an error.
///
/// # Examples
///
/// ```
/// let path = temp_config_path("endpoint-missing");
/// add_server(Some(path.clone()), server("home")).unwrap();
/// let err = update_server_endpoint(Some(path), "ghost", EndpointUpdate::Dns(None))
///     .expect_err("unknown server must error")
///     .to_string();
/// assert!(err.contains("does not define a DNS server named 'ghost'"));
/// ```
#[test]
fn update_server_endpoint_unknown_server_errors() {
    let path = temp_config_path("endpoint-missing");
    add_server(Some(path.clone()), server("home")).unwrap();
    let err = update_server_endpoint(Some(path), "ghost", EndpointUpdate::Dns(None))
        .expect_err("unknown server must error")
        .to_string();
    assert!(
        err.contains("does not define a DNS server named 'ghost'"),
        "unexpected: {err}"
    );
}

// ── update_defaults ─────────────────────────────────────────────────────────

#[test]
fn update_defaults_fills_missing_fields_only() {
    let path = temp_config_path("defaults");
    ensure_config_dir(&path).unwrap();
    // A minimal server entry missing base_url/mcp_access.
    write_private_file(
        &path,
        "[[servers]]\nid = \"home\"\nvendor = \"technitium\"\ntoken = \"tok\"\n",
    )
    .unwrap();

    let report = update_defaults(Some(path.clone())).expect("update defaults");
    assert!(
        report.added_values > 0,
        "expected to add at least base_url + mcp_access"
    );
    assert_eq!(report.updated_servers, 1);

    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(
        raw.contains("base_url"),
        "base_url default not added:\n{raw}"
    );
    // Existing token must be untouched.
    assert!(raw.contains("token = \"tok\""));

    // Running again is idempotent — nothing left to add.
    let report2 = update_defaults(Some(path)).expect("second update");
    assert_eq!(report2.added_values, 0);
}
