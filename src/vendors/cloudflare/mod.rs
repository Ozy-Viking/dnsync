pub mod client;
pub mod mapping;
pub mod service;

use std::env;

use crate::control_plane::config::{self as app_config, DnsServerConfig};
use crate::core::error::{Error, Result};
use crate::core::secret::ApiToken;
use crate::vendors::runtime::ClientOverrides;

pub fn client_from_server(
    server: &DnsServerConfig,
    overrides: ClientOverrides<'_>,
) -> Result<client::CloudflareClient> {
    let base_url = overrides
        .base_url
        .map(ToOwned::to_owned)
        .or_else(|| env::var("DNSYNC_CLOUDFLARE_BASE_URL").ok())
        .or_else(|| server.base_url_env.as_ref().and_then(|k| env::var(k).ok()))
        .or_else(|| server.base_url.clone())
        .unwrap_or_else(|| app_config::CLOUDFLARE_DEFAULT_BASE_URL.to_string());
    let token = overrides
        .token
        .cloned()
        .or_else(|| env::var("DNSYNC_CLOUDFLARE_API_TOKEN").ok().map(ApiToken::new))
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
                "Cloudflare API token is required from --token, DNSYNC_CLOUDFLARE_API_TOKEN, token_env, or config token",
            )
        })?;
    client::CloudflareClient::new(base_url, token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::dns::service::DnsVendor;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn clear_cloudflare_env() {
        // SAFETY: callers hold ENV_LOCK while mutating these process-wide env vars.
        unsafe {
            std::env::remove_var("DNSYNC_CLOUDFLARE_BASE_URL");
            std::env::remove_var("DNSYNC_CLOUDFLARE_API_TOKEN");
        }
    }

    #[test]
    fn client_uses_config_token() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_cloudflare_env();
        let app_config: app_config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "cf"
                vendor = "cloudflare"
                token = "config-token"
            "#,
        )
        .unwrap();
        let server = app_config.selected_server(Some("cf")).unwrap();

        let client = client_from_server(server, ClientOverrides::default()).unwrap();

        assert_eq!(client.kind(), app_config::VendorKind::Cloudflare);
    }

    #[test]
    fn cli_token_wins_over_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_cloudflare_env();
        let app_config: app_config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "cf"
                vendor = "cloudflare"
                token = "config-token"
            "#,
        )
        .unwrap();
        let server = app_config.selected_server(Some("cf")).unwrap();

        let client = client_from_server(
            server,
            ClientOverrides {
                token: Some(&ApiToken::new("cli-token")),
                ..ClientOverrides::default()
            },
        )
        .unwrap();

        assert_eq!(client.kind(), app_config::VendorKind::Cloudflare);
    }

    #[test]
    fn errors_without_token() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_cloudflare_env();
        let app_config: app_config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "cf"
                vendor = "cloudflare"
            "#,
        )
        .unwrap();
        let server = app_config.selected_server(Some("cf")).unwrap();

        let err = client_from_server(server, ClientOverrides::default()).unwrap_err();

        assert!(err.to_string().contains("Cloudflare API token"));
    }

    #[test]
    fn client_from_server_uses_vendor_env_without_overrides() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_cloudflare_env();
        // SAFETY: this test serializes access to these process-wide env vars.
        unsafe {
            std::env::set_var("DNSYNC_CLOUDFLARE_BASE_URL", "https://cf.example/client/v4");
            std::env::set_var("DNSYNC_CLOUDFLARE_API_TOKEN", "cf-env-token");
        }
        let app_config: app_config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "cf"
                vendor = "cloudflare"
            "#,
        )
        .unwrap();
        let server = app_config.selected_server(Some("cf")).unwrap();

        let client = client_from_server(server, ClientOverrides::default()).unwrap();

        assert_eq!(client.base_url(), "https://cf.example/client/v4");
        assert_eq!(client.kind(), app_config::VendorKind::Cloudflare);

        // SAFETY: this test serializes access to these process-wide env vars.
        clear_cloudflare_env();
    }
}
