pub mod client;
pub mod config;
pub mod mapping;
pub mod responses;
pub mod service;

use std::env;

use crate::control_plane::config::{self as app_config, DnsServerConfig};
use crate::core::error::{Error, Result};
use crate::core::secret::ApiToken;
use crate::vendors::runtime::ClientOverrides;

pub fn client_from_cli_without_config(
    overrides: ClientOverrides<'_>,
) -> Result<client::TechnitiumClient> {
    let base_url = overrides
        .base_url
        .map(ToOwned::to_owned)
        .or_else(|| env::var("DNSYNC_TECHNITIUM_BASE_URL").ok())
        .or_else(|| env::var("TECHNITIUM_BASE_URL").ok())
        .unwrap_or_else(|| app_config::TECHNITIUM_DEFAULT_BASE_URL.to_string());
    let token = overrides
        .token
        .cloned()
        .or_else(|| env::var("DNSYNC_TECHNITIUM_API_TOKEN").ok().map(ApiToken::new))
        .or_else(|| env::var("TECHNITIUM_API_TOKEN").ok().map(ApiToken::new))
        .ok_or_else(|| {
            Error::parse(
                "API token is required from --token, DNSYNC_TECHNITIUM_API_TOKEN, TECHNITIUM_API_TOKEN, or config",
            )
        })?;
    client::TechnitiumClient::new(base_url, token)
}

pub fn client_from_server(
    server: &DnsServerConfig,
    overrides: ClientOverrides<'_>,
) -> Result<client::TechnitiumClient> {
    let base_url = overrides
        .base_url
        .map(ToOwned::to_owned)
        .or_else(|| env::var("DNSYNC_TECHNITIUM_BASE_URL").ok())
        .or_else(|| env::var("TECHNITIUM_BASE_URL").ok())
        .or_else(|| server.base_url_env.as_ref().and_then(|k| env::var(k).ok()))
        .or_else(|| server.base_url.clone())
        .unwrap_or_else(|| app_config::TECHNITIUM_DEFAULT_BASE_URL.to_string());
    let token = overrides
        .token
        .cloned()
        .or_else(|| env::var("DNSYNC_TECHNITIUM_API_TOKEN").ok().map(ApiToken::new))
        .or_else(|| env::var("TECHNITIUM_API_TOKEN").ok().map(ApiToken::new))
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
                "API token is required from --token, DNSYNC_TECHNITIUM_API_TOKEN, TECHNITIUM_API_TOKEN, token_env, or config token",
            )
        })?;
    client::TechnitiumClient::new(base_url, token)
}
