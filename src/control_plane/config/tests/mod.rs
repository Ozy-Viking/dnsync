//! Tests for `control_plane::config`, split by area.

pub(crate) use super::*;

use std::time::{SystemTime, UNIX_EPOCH};

mod jobs;
mod loading;
mod persistence;
mod resolve;
mod transport;

fn temp_config_path(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();

    env::temp_dir()
        .join("dnsync-config-tests")
        .join(format!("{name}-{}-{nonce}", std::process::id()))
        .join("config.toml")
}

fn config() -> AppConfig {
    toml::from_str(
        r#"
                [[servers]]
                id = "home"
                vendor = "technitium"
                base_url = "http://home.local:5380"
                token = "home-token"

                [servers.mcp]
                access = ["read"]
                allowed_zones = ["example.com", "internal.lan"]
                show_settings_secrets = true

                [[servers]]
                id = "lab"
                vendor = "technitium"
                base_url = "http://lab.local:5380"
                token_env = "LAB_TOKEN"
            "#,
    )
    .expect("config should parse")
}

// ── resolved_location ─────────────────────────────────────────────────────

fn server_with_url(url: &str) -> DnsServerConfig {
    DnsServerConfig {
        id: "test".to_string(),
        vendor: VendorKind::Technitium,
        location: None,
        base_url: Some(url.to_string()),
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
    }
}

// ── jobs ─────────────────────────────────────────────────────────────────

/// TOML snippet containing two minimal `[[servers]]` entries for tests.
///
/// The snippet defines servers with ids "cf" and "home", each including a literal `token`.
///
/// # Examples
///
/// ```rust,ignore
/// let toml = two_server_config();
/// assert!(toml.contains("id = \"cf\""));
/// assert!(toml.contains("id = \"home\""));
/// ```
#[allow(dead_code)]
fn two_server_config() -> &'static str {
    r#"
            [[servers]]
            id = "cf"
            token = "tok"

            [[servers]]
            id = "home"
            token = "tok"
        "#
}
