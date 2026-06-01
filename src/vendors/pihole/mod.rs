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
) -> Result<client::PiholeClient> {
    let base_url = overrides
        .base_url
        .map(ToOwned::to_owned)
        .or_else(|| env::var("DNSYNC_PIHOLE_BASE_URL").ok())
        .or_else(|| server.base_url_env.as_ref().and_then(|k| env::var(k).ok()))
        .or_else(|| server.base_url.clone())
        .unwrap_or_else(|| app_config::PIHOLE_DEFAULT_BASE_URL.to_string());

    let password = overrides
        .token
        .cloned()
        .or_else(|| env::var("DNSYNC_PIHOLE_PASSWORD").ok().map(ApiToken::new))
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
                "Pi-hole password is required from --token, DNSYNC_PIHOLE_PASSWORD, token_env, or config token",
            )
        })?;

    client::PiholeClient::new(base_url, password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::dns::service::DnsVendor;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn clear_pihole_env() {
        // SAFETY: callers hold ENV_LOCK while mutating these process-wide env vars.
        unsafe {
            std::env::remove_var("DNSYNC_PIHOLE_BASE_URL");
            std::env::remove_var("DNSYNC_PIHOLE_PASSWORD");
        }
    }

    #[test]
    fn client_uses_config_token() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_pihole_env();
        let app_config: app_config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "ph"
                vendor = "pihole"
                token = "my-password"
            "#,
        )
        .unwrap();
        let server = app_config.selected_server(Some("ph")).unwrap();

        let client = client_from_server(server, ClientOverrides::default()).unwrap();

        assert_eq!(client.kind(), app_config::VendorKind::Pihole);
    }

    #[test]
    fn cli_token_wins_over_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_pihole_env();
        let app_config: app_config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "ph"
                vendor = "pihole"
                token = "config-password"
            "#,
        )
        .unwrap();
        let server = app_config.selected_server(Some("ph")).unwrap();

        let client = client_from_server(
            server,
            ClientOverrides {
                token: Some(&ApiToken::new("cli-password")),
                ..ClientOverrides::default()
            },
        )
        .unwrap();

        assert_eq!(client.kind(), app_config::VendorKind::Pihole);
    }

    #[test]
    fn errors_without_token() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_pihole_env();
        let app_config: app_config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "ph"
                vendor = "pihole"
            "#,
        )
        .unwrap();
        let server = app_config.selected_server(Some("ph")).unwrap();

        let err = client_from_server(server, ClientOverrides::default()).unwrap_err();

        assert!(err.to_string().contains("Pi-hole password"));
    }

    #[test]
    fn env_var_wins_over_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_pihole_env();
        // SAFETY: this test serializes access to these process-wide env vars.
        unsafe {
            std::env::set_var("DNSYNC_PIHOLE_BASE_URL", "http://192.168.1.1");
            std::env::set_var("DNSYNC_PIHOLE_PASSWORD", "env-password");
        }
        let app_config: app_config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "ph"
                vendor = "pihole"
            "#,
        )
        .unwrap();
        let server = app_config.selected_server(Some("ph")).unwrap();

        let client = client_from_server(server, ClientOverrides::default()).unwrap();

        assert_eq!(client.base_url, "http://192.168.1.1");
        assert_eq!(client.kind(), app_config::VendorKind::Pihole);

        // SAFETY: this test serializes access to these process-wide env vars.
        clear_pihole_env();
    }

    #[test]
    fn default_base_url_is_pihole() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_pihole_env();
        let app_config: app_config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "ph"
                vendor = "pihole"
                token = "pass"
            "#,
        )
        .unwrap();
        let server = app_config.selected_server(Some("ph")).unwrap();

        let client = client_from_server(server, ClientOverrides::default()).unwrap();

        assert_eq!(client.base_url, app_config::PIHOLE_DEFAULT_BASE_URL);
    }

    #[test]
    fn base_url_env_wins_over_config_base_url() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_pihole_env();
        // SAFETY: serialized via ENV_LOCK.
        unsafe {
            std::env::set_var("MY_PIHOLE_URL", "http://192.168.100.1");
        }
        let app_config: app_config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "ph"
                vendor = "pihole"
                base_url = "http://pi.hole"
                base_url_env = "MY_PIHOLE_URL"
                token = "pass"
            "#,
        )
        .unwrap();
        let server = app_config.selected_server(Some("ph")).unwrap();

        let client = client_from_server(server, ClientOverrides::default()).unwrap();

        assert_eq!(client.base_url, "http://192.168.100.1");

        // SAFETY: serialized via ENV_LOCK.
        unsafe {
            std::env::remove_var("MY_PIHOLE_URL");
        }
    }

    #[test]
    fn vendor_kind_serde_round_trips() {
        let toml = r#"
            [[servers]]
            id = "ph"
            vendor = "pihole"
            token = "pass"
        "#;
        let config: app_config::AppConfig = toml::from_str(toml).expect("should parse");
        let server = config.selected_server(None).unwrap();
        assert_eq!(server.vendor, app_config::VendorKind::Pihole);
    }
}
