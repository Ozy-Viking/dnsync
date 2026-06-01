//! Runtime resolution of a server's location, base URL, and token.

use super::*;

impl DnsServerConfig {
    /// Returns whether this server is local or external.
    ///
    /// Uses the explicit `location` config field when set; otherwise resolves
    /// the effective base URL's hostname via hickory — private/loopback IPs
    /// and `localhost` are `Local`, everything else is `External`.
    pub async fn resolved_location(&self) -> ServerLocation {
        if let Some(loc) = self.location {
            return loc;
        }
        let url = self.base_url.as_deref().unwrap_or(match self.vendor {
            VendorKind::Technitium => TECHNITIUM_DEFAULT_BASE_URL,
            VendorKind::Pangolin => PANGOLIN_DEFAULT_BASE_URL,
            VendorKind::Cloudflare => CLOUDFLARE_DEFAULT_BASE_URL,
            VendorKind::Unifi => UNIFI_DEFAULT_BASE_URL,
            VendorKind::Pihole => PIHOLE_DEFAULT_BASE_URL,
        });
        if url_is_local(url).await {
            ServerLocation::Local
        } else {
            ServerLocation::External
        }
    }

    pub fn resolved_base_url(&self, override_url: Option<&str>) -> String {
        override_url
            .map(ToOwned::to_owned)
            .or_else(|| self.base_url_env.as_ref().and_then(|k| env::var(k).ok()))
            .or_else(|| self.base_url.clone())
            .unwrap_or_else(|| match self.vendor {
                VendorKind::Technitium => TECHNITIUM_DEFAULT_BASE_URL.to_string(),
                VendorKind::Pangolin => PANGOLIN_DEFAULT_BASE_URL.to_string(),
                VendorKind::Cloudflare => CLOUDFLARE_DEFAULT_BASE_URL.to_string(),
                VendorKind::Unifi => UNIFI_DEFAULT_BASE_URL.to_string(),
                VendorKind::Pihole => PIHOLE_DEFAULT_BASE_URL.to_string(),
            })
    }

    pub fn resolved_token(&self, override_token: Option<&str>) -> Result<ApiToken> {
        if let Some(token) = override_token {
            return Ok(ApiToken::new(token));
        }

        if let Some(ref env_name) = self.token_env {
            return env::var(env_name).map(ApiToken::new).map_err(|_| {
                Error::config(format!(
                    "DNS server '{}' requires token env var '{env_name}' to be set",
                    self.id
                ))
            });
        }

        // Treat an empty string the same as absent — it's an unfilled placeholder.
        self.token
            .as_ref()
            .filter(|t| !t.is_empty())
            .cloned()
            .ok_or_else(|| {
                Error::config(format!(
                    "DNS server '{}' has no token configured; set token or token_env in config, or pass --token",
                    self.id
                ))
            })
    }
}

/// Extracts the host portion (no port, no brackets around IPv6 literals) from a URL.
pub(crate) fn url_host(url: &str) -> &str {
    let without_scheme = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let authority = without_scheme.split('/').next().unwrap_or(without_scheme);

    if authority.starts_with('[') {
        // IPv6 literal — strip brackets; ignore the trailing `]:port` part.
        authority
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or(authority)
    } else {
        // Strip port if present (e.g. "192.168.1.1:5380" → "192.168.1.1").
        authority.rsplit(':').nth(1).unwrap_or(authority)
    }
}

pub(crate) fn is_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Returns true when the URL resolves to a local/private address.
///
/// Literal IPs and `localhost` are checked directly. For any other hostname
/// hickory resolves it to an IP first — if any resolved address is
/// private/loopback the URL is considered local.
pub(crate) async fn url_is_local(url: &str) -> bool {
    let host = url_host(url);

    if host == "localhost" || host == "127.0.0.1" || host == "::1" {
        return true;
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_local_ip(ip);
    }

    // Hostname — resolve via hickory and check the resulting addresses.
    let resolver = match Resolver::builder_tokio() {
        Ok(builder) => match builder.build() {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(%e, "could not build resolver for location check");
                return false;
            }
        },
        Err(e) => {
            tracing::debug!(%e, "could not load resolver config for location check");
            return false;
        }
    };

    match resolver.lookup_ip(host).await {
        Ok(lookup) => lookup.iter().any(is_local_ip),
        Err(e) => {
            tracing::debug!(%e, host, "hostname resolution failed during location check");
            false
        }
    }
}

pub fn default_config_path() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    {
        Some(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join(".config")
                .join("dnsync")
                .join("config.toml"),
        )
    }

    #[cfg(not(debug_assertions))]
    env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .map(|dir| dir.join("dnsync").join("config.toml"))
}
