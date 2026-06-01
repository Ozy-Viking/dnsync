//! Server-level config types: `AppConfig`, `DnsServerConfig`, raw deserialisation, MCP permissions.

use super::*;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    #[serde(default)]
    pub servers: Vec<DnsServerConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub clusters: BTreeMap<String, ClusterConfig>,

    /// Daemon runtime configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon: Option<DaemonConfig>,

    /// Scheduled job definitions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub jobs: Vec<JobConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "DnsServerConfigRaw")]
pub struct DnsServerConfig {
    pub id: String,

    #[serde(default)]
    pub vendor: VendorKind,

    /// Whether this server is on a local network or an external/cloud service.
    /// Inferred from the base URL when omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<ServerLocation>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<ApiToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsTransportConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dot: Option<DotTransportConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doh: Option<DohTransportConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doq: Option<DoqTransportConfig>,

    #[serde(default, skip_serializing_if = "McpPermissions::is_default")]
    pub mcp: McpPermissions,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validation_endpoints: Vec<ValidationEndpointConfig>,
}

/// Intermediate struct used only for TOML deserialization.
///
/// Accepts `mcp_readonly` and `mcp_allowed_zones` directly on the server entry
/// (flat format) in addition to the nested `[servers.mcp]` table, then
/// merges them into `McpPermissions` via the `From` impl.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DnsServerConfigRaw {
    id: String,
    #[serde(default)]
    vendor: VendorKind,
    #[serde(default)]
    location: Option<ServerLocation>,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    base_url_env: Option<String>,
    #[serde(default)]
    token: Option<ApiToken>,
    #[serde(default)]
    token_env: Option<String>,
    #[serde(default)]
    org_id: Option<String>,
    #[serde(default)]
    cluster: Option<String>,
    #[serde(default)]
    dns: Option<DnsTransportConfig>,
    #[serde(default)]
    dot: Option<DotTransportConfig>,
    #[serde(default)]
    doh: Option<DohTransportConfig>,
    #[serde(default)]
    doq: Option<DoqTransportConfig>,
    #[serde(default)]
    mcp: McpPermissions,
    #[serde(default)]
    validation_endpoints: Vec<ValidationEndpointConfig>,
    // Flat shorthands — merged into `mcp` on conversion.
    /// Flat shorthand: `mcp_access = ["read", "write", "delete"]`.
    #[serde(default)]
    mcp_access: Option<Vec<PolicyRule>>,
    /// Deprecated flat shorthand kept for backward compatibility; prefer `mcp_access = ["read"]`.
    #[serde(default)]
    mcp_readonly: bool,
    #[serde(default)]
    mcp_allowed_zones: Vec<String>,
}

impl From<DnsServerConfigRaw> for DnsServerConfig {
    fn from(raw: DnsServerConfigRaw) -> Self {
        let mut zones = raw.mcp.allowed_zones;
        for z in raw.mcp_allowed_zones {
            if !zones.contains(&z) {
                zones.push(z);
            }
        }
        // Flat shorthand resolution: mcp_access wins over deprecated mcp_readonly;
        // intersect the flat shorthand with the nested mcp.access set.
        let config_set: HashSet<PolicyRule> = raw.mcp.access.iter().cloned().collect();
        let access = if let Some(flat) = raw.mcp_access {
            let flat_set: HashSet<PolicyRule> = flat.into_iter().collect();
            flat_set
                .intersection(&config_set)
                .cloned()
                .collect::<Vec<_>>()
        } else if raw.mcp_readonly {
            let flat_set: HashSet<PolicyRule> = [PolicyRule::Read].into_iter().collect();
            flat_set
                .intersection(&config_set)
                .cloned()
                .collect::<Vec<_>>()
        } else {
            raw.mcp.access
        };

        let mut server = DnsServerConfig {
            id: raw.id,
            vendor: raw.vendor,
            location: raw.location,
            base_url: raw.base_url,
            base_url_env: raw.base_url_env,
            token: raw.token,
            token_env: raw.token_env,
            org_id: raw.org_id,
            cluster: raw.cluster,
            dns: raw.dns,
            dot: raw.dot,
            doh: raw.doh,
            doq: raw.doq,
            mcp: McpPermissions {
                access,
                allowed_zones: zones,
                show_settings_secrets: raw.mcp.show_settings_secrets,
            },
            validation_endpoints: raw.validation_endpoints,
        };
        apply_provider_transport_defaults(&mut server);
        server
    }
}

pub(crate) fn apply_provider_transport_defaults(server: &mut DnsServerConfig) {
    let inferred_local = server.location.is_none()
        && server.base_url.as_deref().is_some_and(|url| {
            let host = url_host(url);
            host.eq_ignore_ascii_case("localhost")
                || host.parse::<IpAddr>().ok().is_some_and(is_local_ip)
        });
    if server.location == Some(ServerLocation::Local) || inferred_local {
        return;
    }

    // Vendor-specific transport defaults live in each vendor's module; the
    // control plane only dispatches to them.
    match server.vendor {
        VendorKind::Cloudflare => {
            #[cfg(feature = "cloudflare")]
            crate::vendors::cloudflare::apply_transport_defaults(server);
        }
        VendorKind::Technitium | VendorKind::Pangolin | VendorKind::Unifi | VendorKind::Pihole => {}
    }
}

pub(crate) fn default_true() -> bool {
    true
}

pub(crate) fn default_access() -> Vec<PolicyRule> {
    vec![PolicyRule::Read, PolicyRule::Write, PolicyRule::Delete]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpPermissions {
    /// Permitted operation classes (default: all).
    #[serde(default = "default_access")]
    pub access: Vec<PolicyRule>,

    #[serde(default)]
    pub allowed_zones: Vec<String>,

    #[serde(default)]
    pub show_settings_secrets: bool,
}

impl Default for McpPermissions {
    fn default() -> Self {
        Self {
            access: default_access(),
            allowed_zones: Vec::new(),
            show_settings_secrets: false,
        }
    }
}

impl McpPermissions {
    fn is_default(&self) -> bool {
        let full: HashSet<PolicyRule> = [PolicyRule::Read, PolicyRule::Write, PolicyRule::Delete]
            .into_iter()
            .collect();
        let current: HashSet<PolicyRule> = self.access.iter().cloned().collect();
        current == full && self.allowed_zones.is_empty() && !self.show_settings_secrets
    }
}
