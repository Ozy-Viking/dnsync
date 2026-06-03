use super::*;

use crate::control_plane::config::AppConfig;

fn make_server(config: AppConfig) -> DnsServer {
    DnsServer::new(config, vec![], vec![])
}

#[tokio::test]
async fn dns_get_config_returns_toml() {
    let config: AppConfig = toml::from_str(
        r#"
            [[servers]]
            id = "primary"
            vendor = "technitium"
            token = "supersecret"
            "#,
    )
    .unwrap();
    let server = make_server(config);
    let result = server.dns_get_config().await.unwrap();
    assert!(!result.is_error.unwrap_or(false));
    let text = result.content[0]
        .as_text()
        .expect("expected text content")
        .text
        .clone();
    // Must be parseable TOML
    let parsed: toml::Value = toml::from_str(&text).expect("output should be valid TOML");
    // Token must be redacted
    let token = parsed["servers"][0]["token"].as_str().unwrap();
    assert_eq!(token, "[redacted]");
}

#[tokio::test]
async fn dns_get_config_preserves_token_env() {
    let config: AppConfig = toml::from_str(
        r#"
            [[servers]]
            id = "primary"
            vendor = "technitium"
            token_env = "MY_DNS_TOKEN"
            "#,
    )
    .unwrap();
    let server = make_server(config);
    let result = server.dns_get_config().await.unwrap();
    assert!(!result.is_error.unwrap_or(false));
    let text = result.content[0]
        .as_text()
        .expect("expected text content")
        .text
        .clone();
    let parsed: toml::Value = toml::from_str(&text).expect("output should be valid TOML");
    // token_env should be preserved as-is
    let token_env = parsed["servers"][0]["token_env"].as_str().unwrap();
    assert_eq!(token_env, "MY_DNS_TOKEN");
    // token key should not appear (was None)
    assert!(parsed["servers"][0].get("token").is_none());
}

#[tokio::test]
async fn dns_version_returns_package_version() {
    let server = make_server(AppConfig::default());
    let result = server.dns_version().await.unwrap();
    assert!(!result.is_error.unwrap_or(false));
    let value: serde_json::Value = serde_json::from_str(&result.content[0].as_text().unwrap().text)
        .expect("output should be valid JSON");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
}

// ── resolve_server early-return (no network) ────────────────────────────────

/// Creates an `AppConfig` containing a single server named "primary".
///
/// The returned configuration includes a server with:
/// - `id = "primary"`
/// - `vendor = "technitium"`
/// - `token = "tok"`
/// - `servers.mcp.access = ["read", "write", "delete"]`
///
/// # Examples
///
/// ```
/// let cfg = single_server_config();
/// assert_eq!(cfg.servers[0].id, "primary");
/// assert_eq!(cfg.servers[0].vendor.as_deref(), Some("technitium"));
/// assert_eq!(cfg.servers[0].token.as_deref(), Some("tok"));
/// assert_eq!(cfg.servers[0].mcp.as_ref().unwrap().access, vec!["read", "write", "delete"]);
/// ```
fn single_server_config() -> AppConfig {
    toml::from_str(
        r#"
            [[servers]]
            id = "primary"
            vendor = "technitium"
            token = "tok"

            [servers.mcp]
            access = ["read", "write", "delete"]
        "#,
    )
    .unwrap()
}

/// Ensures `dns_list_zones` errors when called with a server id that does not exist.
///
/// The test constructs a server from a known configuration and calls `dns_list_zones`
/// with `server_id = "ghost"`, asserting the call fails and the error message
/// contains "no server named 'ghost'".
///
/// # Examples
///
/// ```
/// let server = make_server(single_server_config());
/// let params = ListZonesParams {
///     server_id: "ghost".into(),
///     page_number: None,
///     zones_per_page: None,
/// };
/// let err = server
///     .dns_list_zones(Parameters(params))
///     .await
///     .expect_err("unknown server must error before any network call");
/// assert!(err.message.contains("no server named 'ghost'"));
/// ```
#[tokio::test]
async fn list_zones_unknown_server_id_errors() {
    let server = make_server(single_server_config());
    let p = ListZonesParams {
        server_id: "ghost".into(),
        page_number: None,
        zones_per_page: None,
    };
    let err = server
        .dns_list_zones(Parameters(p))
        .await
        .expect_err("unknown server must error before any network call");
    assert!(
        err.message.contains("no server named 'ghost'"),
        "unexpected: {err:?}"
    );
}

/// Verifies that attempting to create a DNS zone for a non-existent server ID returns an error.
///
/// This test constructs a server from a known single-server configuration and calls
/// `dns_create_zone` with `server_id = "ghost"`, asserting the call fails before any network activity.
///
/// # Examples
///
/// ```
/// let server = make_server(single_server_config());
/// let p = CreateZoneParams {
///     server_id: "ghost".into(),
///     zone: "example.com".into(),
///     zone_type: "Primary".into(),
/// };
/// assert!(server.dns_create_zone(Parameters(p)).await.is_err());
/// ```
#[tokio::test]
async fn create_zone_unknown_server_id_errors() {
    let server = make_server(single_server_config());
    let p = CreateZoneParams {
        server_id: "ghost".into(),
        zone: "example.com".into(),
        zone_type: "Primary".into(),
    };
    assert!(server.dns_create_zone(Parameters(p)).await.is_err());
}

#[tokio::test]
async fn transfer_zone_unknown_source_errors() {
    let server = make_server(single_server_config());
    let p = TransferZoneParams {
        zone: "example.com".into(),
        from: "ghost".into(),
        to: "primary".into(),
        overwrite: true,
        overwrite_zone: false,
    };
    assert!(server.dns_transfer_zone(Parameters(p)).await.is_err());
}

/// Verifies that a zone transfer is rejected when the destination server does not permit write access.
///
/// The test constructs two servers in the configuration: a source (`src`) that permits write and
/// a destination (`dst`) that is read-only. It invokes `dns_transfer_zone` to transfer a zone
/// from `src` to `dst` and asserts the RPC result indicates an error and the returned message
/// mentions that the destination "does not permit write".
///
/// # Examples
///
/// ```
/// // configuration: src has write, dst is read-only
/// // calling dns_transfer_zone(...) returns a result with `is_error == Some(true)`
/// // and the content text contains "does not permit write"
/// ```
#[tokio::test]
async fn transfer_zone_blocked_when_destination_lacks_write() {
    // `src` can read; `dst` is read-only, so the write check fails before
    // any backend call is attempted.
    let config: AppConfig = toml::from_str(
        r#"
            [[servers]]
            id = "src"
            vendor = "technitium"
            token = "tok"
            [servers.mcp]
            access = ["read", "write", "delete"]

            [[servers]]
            id = "dst"
            vendor = "technitium"
            token = "tok"
            [servers.mcp]
            access = ["read"]
        "#,
    )
    .unwrap();
    let server = make_server(config);
    let p = TransferZoneParams {
        zone: "example.com".into(),
        from: "src".into(),
        to: "dst".into(),
        overwrite: true,
        overwrite_zone: false,
    };
    let result = server.dns_transfer_zone(Parameters(p)).await.unwrap();
    assert_eq!(result.is_error, Some(true));
    assert!(
        result.content[0]
            .as_text()
            .unwrap()
            .text
            .contains("does not permit write")
    );
}
