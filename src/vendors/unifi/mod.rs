pub mod client;
pub mod mapping;
pub mod responses;
pub mod service;

use std::env;

use crate::control_plane::config::{self as app_config, DnsServerConfig};
use crate::core::error::{Error, Result};
use crate::core::secret::ApiToken;
use crate::vendors::runtime::ClientOverrides;

/// Construct a UniFi client from the resolved server entry and per-call overrides.
///
/// Resolution order matches the conventions documented in `docs/new-vendor.md`:
/// CLI override → vendor env var → `base_url_env` lookup → config `base_url` → default.
/// The same applies to tokens. The UniFi site identifier is sourced from the
/// `DNSYNC_UNIFI_SITE` env var or the config `org_id` field; the configured
/// value is the controller's human-readable site name (e.g. `"Default"`),
/// though a site UUID is also accepted. The client resolves the value to a
/// UUID on the first DNS call via `GET /v1/sites`.
pub fn client_from_server(
    server: &DnsServerConfig,
    overrides: ClientOverrides<'_>,
) -> Result<client::UnifiClient> {
    let base_url = overrides
        .base_url
        .map(ToOwned::to_owned)
        .or_else(|| env::var("DNSYNC_UNIFI_BASE_URL").ok())
        .or_else(|| server.base_url_env.as_ref().and_then(|k| env::var(k).ok()))
        .or_else(|| server.base_url.clone())
        .unwrap_or_else(|| app_config::UNIFI_DEFAULT_BASE_URL.to_string());
    let token = overrides
        .token
        .cloned()
        .or_else(|| env::var("DNSYNC_UNIFI_API_TOKEN").ok().map(ApiToken::new))
        .or_else(|| {
            server
                .token_env
                .as_ref()
                .and_then(|k| env::var(k).ok())
                .map(ApiToken::new)
        })
        .or_else(|| server.token.clone())
        .ok_or_else(|| {
            Error::parse(
                "UniFi API token is required from --token, DNSYNC_UNIFI_API_TOKEN, token_env, or config token",
            )
        })?;
    let site = env::var("DNSYNC_UNIFI_SITE")
        .ok()
        .or_else(|| server.org_id.clone())
        .ok_or_else(|| {
            Error::parse(
                "UniFi site is required from DNSYNC_UNIFI_SITE or config org_id (human-readable site name, e.g. \"Default\", or the site UUID)",
            )
        })?;
    client::UnifiClient::new(base_url, token, site)
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn clear_unifi_env() {
        // SAFETY: callers hold ENV_LOCK while mutating these process-wide env vars.
        unsafe {
            std::env::remove_var("DNSYNC_UNIFI_BASE_URL");
            std::env::remove_var("DNSYNC_UNIFI_API_TOKEN");
            std::env::remove_var("DNSYNC_UNIFI_SITE");
        }
    }

    #[test]
    fn client_uses_default_base_url_from_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_unifi_env();
        let app_config: app_config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "udm"
                vendor = "unifi"
                token = "unifi-token"
                org_id = "Default"
            "#,
        )
        .unwrap();
        let server = app_config.selected_server(Some("udm")).unwrap();

        let client = client_from_server(server, ClientOverrides::default()).unwrap();

        assert_eq!(client.base_url(), app_config::UNIFI_DEFAULT_BASE_URL);
        assert_eq!(client.site(), "Default");
    }

    #[test]
    fn cli_token_wins_over_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_unifi_env();
        let app_config: app_config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "udm"
                vendor = "unifi"
                token = "config-token"
                org_id = "Default"
            "#,
        )
        .unwrap();
        let server = app_config.selected_server(Some("udm")).unwrap();

        let client = client_from_server(
            server,
            ClientOverrides {
                token: Some(&ApiToken::new("cli-token")),
                ..ClientOverrides::default()
            },
        )
        .unwrap();

        assert_eq!(client.site(), "Default");
        assert_eq!(
            client.token_for_test(),
            "cli-token",
            "CLI --token must take precedence over the config token field"
        );
    }

    #[test]
    fn errors_without_token() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_unifi_env();
        let app_config: app_config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "udm"
                vendor = "unifi"
                org_id = "Default"
            "#,
        )
        .unwrap();
        let server = app_config.selected_server(Some("udm")).unwrap();

        let err = client_from_server(server, ClientOverrides::default()).unwrap_err();

        assert!(err.to_string().contains("UniFi API token"));
    }

    #[test]
    fn errors_without_site_id() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_unifi_env();
        let app_config: app_config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "udm"
                vendor = "unifi"
                token = "tok"
            "#,
        )
        .unwrap();
        let server = app_config.selected_server(Some("udm")).unwrap();

        let err = client_from_server(server, ClientOverrides::default()).unwrap_err();

        assert!(err.to_string().contains("UniFi site"));
    }

    #[test]
    fn vendor_env_vars_resolve_without_config_fields() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_unifi_env();
        // SAFETY: this test serialises access to process-wide env vars via ENV_LOCK.
        unsafe {
            std::env::set_var(
                "DNSYNC_UNIFI_BASE_URL",
                "https://udm.local/proxy/network/integration/v1",
            );
            std::env::set_var("DNSYNC_UNIFI_API_TOKEN", "env-token");
            std::env::set_var("DNSYNC_UNIFI_SITE", "Lab");
        }
        let app_config: app_config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "udm"
                vendor = "unifi"
            "#,
        )
        .unwrap();
        let server = app_config.selected_server(Some("udm")).unwrap();

        let client = client_from_server(server, ClientOverrides::default()).unwrap();

        assert_eq!(
            client.base_url(),
            "https://udm.local/proxy/network/integration/v1"
        );
        assert_eq!(client.site(), "Lab");
        assert_eq!(client.token_for_test(), "env-token");

        clear_unifi_env();
    }
}
