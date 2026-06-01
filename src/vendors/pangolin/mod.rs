pub mod client;
pub mod mapping;
pub mod responses;
pub mod service;

use std::env;

use crate::control_plane::config::{self as app_config, DnsServerConfig};
use crate::core::error::{Error, Result};
use crate::core::secret::ApiToken;
use crate::vendors::runtime::ClientOverrides;

pub fn client_from_server(
    server: &DnsServerConfig,
    overrides: ClientOverrides<'_>,
) -> Result<client::PangolinClient> {
    let base_url = overrides
        .base_url
        .map(ToOwned::to_owned)
        .or_else(|| env::var("DNSYNC_PANGOLIN_BASE_URL").ok())
        .or_else(|| server.base_url_env.as_ref().and_then(|k| env::var(k).ok()))
        .or_else(|| server.base_url.clone())
        .unwrap_or_else(|| app_config::PANGOLIN_DEFAULT_BASE_URL.to_string());
    let token = overrides
        .token
        .cloned()
        .or_else(|| env::var("DNSYNC_PANGOLIN_API_TOKEN").ok().map(ApiToken::new))
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
                "Pangolin API token is required from --token, DNSYNC_PANGOLIN_API_TOKEN, token_env, or config token",
            )
        })?;
    let org_id = env::var("DNSYNC_PANGOLIN_ORG_ID")
        .ok()
        .or_else(|| server.org_id.clone())
        .ok_or_else(|| {
            Error::parse("Pangolin org ID is required from DNSYNC_PANGOLIN_ORG_ID or config org_id")
        })?;
    client::PangolinClient::new(base_url, token, org_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn clear_pangolin_env() {
        // SAFETY: callers hold ENV_LOCK while mutating these process-wide env vars.
        unsafe {
            std::env::remove_var("DNSYNC_PANGOLIN_BASE_URL");
            std::env::remove_var("DNSYNC_PANGOLIN_API_TOKEN");
            std::env::remove_var("DNSYNC_PANGOLIN_ORG_ID");
        }
    }

    #[test]
    fn client_uses_default_base_url_from_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_pangolin_env();
        let app_config: app_config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "cloud"
                vendor = "pangolin"
                token = "pangolin-token"
                org_id = "org_123"
            "#,
        )
        .unwrap();
        let server = app_config.selected_server(Some("cloud")).unwrap();

        let client = client_from_server(server, ClientOverrides::default()).unwrap();

        assert_eq!(client.base_url(), app_config::PANGOLIN_DEFAULT_BASE_URL);
        assert_eq!(client.org_id, "org_123");
    }

    #[test]
    fn client_from_server_uses_vendor_env_without_overrides() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_pangolin_env();
        // SAFETY: this test serializes access to these process-wide env vars.
        unsafe {
            std::env::set_var("DNSYNC_PANGOLIN_BASE_URL", "https://pangolin.example/v1");
            std::env::set_var("DNSYNC_PANGOLIN_API_TOKEN", "pangolin-env-token");
            std::env::set_var("DNSYNC_PANGOLIN_ORG_ID", "env-org");
        }
        let app_config: app_config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "cloud"
                vendor = "pangolin"
            "#,
        )
        .unwrap();
        let server = app_config.selected_server(Some("cloud")).unwrap();

        let client = client_from_server(server, ClientOverrides::default()).unwrap();

        assert_eq!(client.base_url(), "https://pangolin.example/v1");
        assert_eq!(client.org_id, "env-org");

        // SAFETY: this test serializes access to these process-wide env vars.
        clear_pangolin_env();
    }
}
