use super::*;

#[tokio::test]
async fn localhost_url_is_local() {
    assert_eq!(
        server_with_url("http://localhost:5380")
            .resolved_location()
            .await,
        ServerLocation::Local
    );
}

#[tokio::test]
async fn loopback_ip_is_local() {
    assert_eq!(
        server_with_url("http://127.0.0.1:5380")
            .resolved_location()
            .await,
        ServerLocation::Local
    );
}

#[tokio::test]
async fn private_ip_is_local() {
    assert_eq!(
        server_with_url("http://192.168.1.10:5380")
            .resolved_location()
            .await,
        ServerLocation::Local
    );
    assert_eq!(
        server_with_url("http://10.0.0.1:8080")
            .resolved_location()
            .await,
        ServerLocation::Local
    );
}

#[tokio::test]
async fn public_ip_is_external() {
    assert_eq!(
        server_with_url("https://1.2.3.4:5380")
            .resolved_location()
            .await,
        ServerLocation::External
    );
}

#[tokio::test]
async fn cloud_domain_is_external() {
    assert_eq!(
        server_with_url("https://api.pangolin.net/v1")
            .resolved_location()
            .await,
        ServerLocation::External
    );
}

#[tokio::test]
async fn technitium_default_url_is_local() {
    let server = DnsServerConfig {
        id: "test".to_string(),
        vendor: VendorKind::Technitium,
        location: None,
        base_url: None,
        base_url_env: None,
        token: None,
        token_env: None,
        org_id: None,
        cluster: None,
        dns: None,
        dot: None,
        doh: None,
        doq: None,
        mcp: McpPermissions::default(),
        validation_endpoints: Vec::new(),
    };
    assert_eq!(server.resolved_location().await, ServerLocation::Local);
}

#[tokio::test]
async fn pangolin_default_url_is_external() {
    let server = DnsServerConfig {
        id: "test".to_string(),
        vendor: VendorKind::Pangolin,
        location: None,
        base_url: None,
        base_url_env: None,
        token: None,
        token_env: None,
        org_id: None,
        cluster: None,
        dns: None,
        dot: None,
        doh: None,
        doq: None,
        mcp: McpPermissions::default(),
        validation_endpoints: Vec::new(),
    };
    assert_eq!(server.resolved_location().await, ServerLocation::External);
}

#[tokio::test]
async fn explicit_location_overrides_auto_detection() {
    let mut server = server_with_url("https://api.pangolin.net");
    server.location = Some(ServerLocation::Local);
    assert_eq!(server.resolved_location().await, ServerLocation::Local);

    server.location = Some(ServerLocation::External);
    assert_eq!(server.resolved_location().await, ServerLocation::External);
}

// ── url_host extraction ───────────────────────────────────────────────────

#[test]
fn url_host_strips_scheme_and_port() {
    assert_eq!(url_host("http://localhost:5380"), "localhost");
    assert_eq!(url_host("https://192.168.1.1:443"), "192.168.1.1");
    assert_eq!(url_host("https://api.pangolin.net/v1"), "api.pangolin.net");
}

#[test]
fn url_host_handles_ipv6_literals() {
    assert_eq!(url_host("http://[::1]:5380"), "::1");
}

#[test]
fn url_host_no_port() {
    assert_eq!(url_host("http://myserver"), "myserver");
}

// ── location field TOML round-trip ────────────────────────────────────────

/// Verifies that a server's explicit `location` value is preserved when parsing from TOML.
///
/// # Examples
///
/// ```rust,ignore
/// let toml = r#"
///     [[servers]]
///     id = "home"
///     vendor = "technitium"
///     location = "external"
///     token = "tok"
/// "#;
/// let config: AppConfig = toml::from_str(toml).expect("should parse");
/// let server = config.selected_server(None).unwrap();
/// assert_eq!(server.location, Some(ServerLocation::External));
/// ```
#[test]
fn location_field_round_trips_in_toml() {
    let toml = r#"
            [[servers]]
            id = "home"
            vendor = "technitium"
            location = "external"
            token = "tok"
        "#;
    let config: AppConfig = toml::from_str(toml).expect("should parse");
    let server = config.selected_server(None).unwrap();
    assert_eq!(server.location, Some(ServerLocation::External));
}
