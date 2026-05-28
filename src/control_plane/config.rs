use std::{
    collections::{BTreeMap, HashSet},
    env,
    net::IpAddr,
    path::{Path, PathBuf},
};

use hickory_resolver::Resolver;
use serde::{Deserialize, Serialize};

use crate::control_plane::policy::PolicyRule;
use crate::core::error::{Error, Result};
use crate::core::secret::ApiToken;

pub const TECHNITIUM_DEFAULT_BASE_URL: &str = "http://localhost:5380";
pub const PANGOLIN_DEFAULT_BASE_URL: &str = "https://api.pangolin.net/v1";
pub const CLOUDFLARE_DEFAULT_BASE_URL: &str = "https://api.cloudflare.com/client/v4";
pub const UNIFI_DEFAULT_BASE_URL: &str = "https://192.168.1.1/proxy/network/integration/v1";

/// Supported DNS vendor backends.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum VendorKind {
    #[default]
    Technitium,
    Pangolin,
    Cloudflare,
    Unifi,
}

/// Whether the DNS server is on a local network or an external/cloud service.
///
/// When omitted from config, the value is inferred from the base URL:
/// `localhost` and private-range IPs → `local`; everything else → `external`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ServerLocation {
    Local,
    External,
}

/// Transport used to query a DNS endpoint.
///
/// `Doq` is always available as a tag for `[servers.doq]` blocks and as a
/// CLI flag for the `dns query` subcommand, but the resolver path is
/// gated behind the `doq` Cargo feature; without it, queries over DoQ
/// return `ValidationFailureKind::UnsupportedTransport`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ValidationTransport {
    Dns,
    Doh,
    Dot,
    Doq,
}

/// Configured role for writes across a logical cluster.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterWritePolicy {
    #[default]
    PrimaryOnly,
}

/// Plain DNS query endpoint for a configured server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsTransportConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// DNS-over-TLS query endpoint for a configured server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DotTransportConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// DNS-over-HTTPS query endpoint for a configured server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DohTransportConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// DNS-over-QUIC query endpoint for a configured server.
///
/// Parsed and round-tripped on every build so configs are portable.
/// The actual resolver wiring is gated behind the `doq` Cargo feature;
/// without it, attempts to query this endpoint return
/// `ValidationFailureKind::UnsupportedTransport`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoqTransportConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// Logical cluster policy shared by member servers.
///
/// `primary` and `preferred_writer` accept either a configured DNS server id or
/// the special value `auto`, matched case-insensitively.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterConfig {
    #[serde(default)]
    pub vendor: VendorKind,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub write_policy: ClusterWritePolicy,
    /// Primary server id, or `auto` to discover it dynamically.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_zone: Option<String>,
    /// Preferred writer server id, or `auto` to discover it dynamically.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_writer: Option<String>,
}

/// DNS endpoint used to validate imported or listed records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationEndpointConfig {
    pub name: String,

    pub transport: ValidationTransport,

    #[serde(default)]
    pub address: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_server_name: Option<String>,

    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

impl std::str::FromStr for ValidationEndpointConfig {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let mut parts = value.splitn(3, ':');
        let name = parts
            .next()
            .filter(|part| !part.trim().is_empty())
            .ok_or_else(|| "validation endpoint must use name:transport:address".to_string())?;
        let transport = match parts.next().map(str::to_ascii_lowercase).as_deref() {
            Some("dns") => ValidationTransport::Dns,
            Some("doh") => ValidationTransport::Doh,
            Some("dot") => ValidationTransport::Dot,
            Some(other) => {
                return Err(format!(
                    "unsupported validation endpoint transport '{other}'; expected dns, doh, or dot"
                ));
            }
            None => return Err("validation endpoint must use name:transport:address".to_string()),
        };
        let target = parts
            .next()
            .filter(|part| !part.trim().is_empty())
            .ok_or_else(|| "validation endpoint must use name:transport:address".to_string())?;

        Ok(ValidationEndpointConfig {
            name: name.to_string(),
            transport,
            address: if matches!(transport, ValidationTransport::Doh) {
                String::new()
            } else {
                target.to_string()
            },
            port: None,
            url: if matches!(transport, ValidationTransport::Doh) {
                Some(target.to_string())
            } else {
                None
            },
            tls_server_name: None,
            enabled: true,
            timeout_ms: None,
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    #[serde(default)]
    pub servers: Vec<DnsServerConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub clusters: BTreeMap<String, ClusterConfig>,

    /// Named record-sync profiles (see `dns sync`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sync: Vec<SyncProfile>,
}

/// A named record-sync profile: copy records from one configured server to
/// another, optionally rewriting IP addresses on A/AAAA records.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncProfile {
    /// Unique profile name, invoked as `dns sync <name>`.
    pub name: String,

    /// Source server id — must match a `[[servers]]` entry.
    pub from: String,

    /// Destination server id — must match a `[[servers]]` entry.
    pub to: String,

    /// Zones to sync. Empty means every zone found on the source server.
    #[serde(default)]
    pub zones: Vec<String>,

    /// Explicit `source = destination` IP rewrites applied to A/AAAA records.
    #[serde(default)]
    pub ip_map: std::collections::BTreeMap<String, String>,
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
    pub token: Option<String>,
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
struct DnsServerConfigRaw {
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
    token: Option<String>,
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

        DnsServerConfig {
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
            },
            validation_endpoints: raw.validation_endpoints,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_access() -> Vec<PolicyRule> {
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
}

impl Default for McpPermissions {
    fn default() -> Self {
        Self {
            access: default_access(),
            allowed_zones: Vec::new(),
        }
    }
}

impl McpPermissions {
    fn is_default(&self) -> bool {
        let full: HashSet<PolicyRule> = [PolicyRule::Read, PolicyRule::Write, PolicyRule::Delete]
            .into_iter()
            .collect();
        let current: HashSet<PolicyRule> = self.access.iter().cloned().collect();
        current == full && self.allowed_zones.is_empty()
    }
}

impl AppConfig {
    pub fn starter() -> Self {
        AppConfig {
            servers: vec![DnsServerConfig {
                id: "default".to_string(),
                vendor: VendorKind::Technitium,
                location: None,
                base_url: Some(TECHNITIUM_DEFAULT_BASE_URL.to_string()),
                base_url_env: None,
                token: None,
                token_env: Some("DNSYNC_TECHNITIUM_API_TOKEN".to_string()),
                org_id: None,
                cluster: None,
                dns: None,
                dot: None,
                doh: None,
                doq: None,
                mcp: McpPermissions::default(),
                validation_endpoints: Vec::new(),
            }],
            clusters: BTreeMap::new(),
            sync: Vec::new(),
        }
    }

    pub fn render_starter_toml() -> Result<String> {
        Self::starter().render_toml()
    }

    pub fn render_toml(&self) -> Result<String> {
        let mut doc = toml_edit::DocumentMut::new();
        for server in &self.servers {
            append_server_entry(&mut doc, server);
        }
        append_cluster_entries(&mut doc, &self.clusters);
        for profile in &self.sync {
            append_sync_entry(&mut doc, profile);
        }
        Ok(doc.to_string())
    }

    /// Returns a copy of the config with every literal `token` value replaced
    /// by `"[redacted]"`. `token_env` values (env var names) are not secrets
    /// and are left as-is.
    pub fn redact(&self) -> Self {
        AppConfig {
            servers: self
                .servers
                .iter()
                .map(|s| DnsServerConfig {
                    token: s.token.as_ref().map(|_| "[redacted]".to_string()),
                    ..s.clone()
                })
                .collect(),
            clusters: self.clusters.clone(),
            sync: self.sync.clone(),
        }
    }

    /// Load the config file if it already exists; return `Ok(None)` if it does
    /// not. Unlike `load`, this never creates the file.
    pub fn load_if_exists(path: Option<PathBuf>) -> Result<Option<Self>> {
        let Some(path) = path.or_else(default_config_path) else {
            return Ok(None);
        };
        if !path.exists() {
            return Ok(None);
        }
        load_from_path(&path).map(Some)
    }

    /// Load the config file, creating it with starter defaults if it does not
    /// exist yet.
    pub fn load(path: Option<PathBuf>) -> Result<Option<Self>> {
        let Some(path) = path.or_else(default_config_path) else {
            return Ok(None);
        };

        if !path.exists() {
            write_default_config(&path, false)?;
        }

        load_from_path(&path).map(Some)
    }

    pub fn selected_server(&self, selected_id: Option<&str>) -> Result<&DnsServerConfig> {
        if let Some(id) = selected_id {
            return self
                .servers
                .iter()
                .find(|server| server.id.eq_ignore_ascii_case(id))
                .ok_or_else(|| {
                    Error::config(format!("config does not define a DNS server named '{id}'"))
                });
        }

        match self.servers.as_slice() {
            [server] => Ok(server),
            [] => Err(Error::config("config file does not define any DNS servers")),
            _ => Err(Error::config(
                "config file defines multiple DNS servers; select one with --server or DNSYNC_SERVER",
            )),
        }
    }

    fn validate(&self) -> Result<()> {
        let mut ids = std::collections::HashSet::new();
        for server in &self.servers {
            if server.id.trim().is_empty() {
                return Err(Error::config(
                    "config contains a DNS server with an empty id",
                ));
            }
            if !ids.insert(server.id.to_lowercase()) {
                return Err(Error::config(format!(
                    "config contains duplicate DNS server id '{}'",
                    server.id
                )));
            }
            if let Some(cluster_id) = &server.cluster
                && !self.clusters.contains_key(cluster_id)
            {
                return Err(Error::config(format!(
                    "DNS server '{}' references unknown cluster '{}'",
                    server.id, cluster_id
                )));
            }
            validate_server_transports(server)?;
            validate_validation_endpoints(server)?;
        }
        validate_clusters(&self.clusters, &ids)?;

        let mut sync_names = std::collections::HashSet::new();
        for profile in &self.sync {
            if profile.name.trim().is_empty() {
                return Err(Error::config(
                    "config contains a sync profile with an empty name",
                ));
            }
            if !sync_names.insert(profile.name.to_lowercase()) {
                return Err(Error::config(format!(
                    "config contains duplicate sync profile name '{}'",
                    profile.name
                )));
            }
            if !ids.contains(&profile.from.to_lowercase()) {
                return Err(Error::config(format!(
                    "sync profile '{}' references unknown source server '{}'",
                    profile.name, profile.from
                )));
            }
            if !ids.contains(&profile.to.to_lowercase()) {
                return Err(Error::config(format!(
                    "sync profile '{}' references unknown destination server '{}'",
                    profile.name, profile.to
                )));
            }
            if profile.from.to_lowercase() == profile.to.to_lowercase() {
                return Err(Error::config(format!(
                    "sync profile '{}' has identical source and destination server '{}'",
                    profile.name, profile.from
                )));
            }
            for (src, dst) in &profile.ip_map {
                validate_ip_pair(&profile.name, src, dst)?;
            }
        }

        Ok(())
    }
}

fn validate_validation_endpoints(server: &DnsServerConfig) -> Result<()> {
    for endpoint in &server.validation_endpoints {
        if endpoint.name.trim().is_empty() {
            return Err(Error::config(format!(
                "DNS server '{}' contains a validation endpoint with an empty name",
                server.id
            )));
        }

        match endpoint.transport {
            ValidationTransport::Dns | ValidationTransport::Dot
                if endpoint.address.trim().is_empty() =>
            {
                return Err(Error::config(format!(
                    "validation endpoint '{}' on DNS server '{}' requires address for {:?} transport",
                    endpoint.name, server.id, endpoint.transport
                )));
            }
            ValidationTransport::Doh
                if endpoint
                    .url
                    .as_deref()
                    .is_none_or(|url| url.trim().is_empty()) =>
            {
                return Err(Error::config(format!(
                    "validation endpoint '{}' on DNS server '{}' requires url for doh transport",
                    endpoint.name, server.id
                )));
            }
            _ => {}
        }
    }

    Ok(())
}

fn validate_server_transports(server: &DnsServerConfig) -> Result<()> {
    if let Some(dns) = &server.dns
        && dns.enabled
        && dns
            .addr
            .as_deref()
            .is_none_or(|addr| addr.trim().is_empty())
    {
        return Err(Error::config(format!(
            "DNS server '{}' has enabled dns transport without addr",
            server.id
        )));
    }

    if let Some(dot) = &server.dot
        && dot.enabled
        && dot
            .addr
            .as_deref()
            .is_none_or(|addr| addr.trim().is_empty())
    {
        return Err(Error::config(format!(
            "DNS server '{}' has enabled dot transport without addr",
            server.id
        )));
    }

    if let Some(doh) = &server.doh
        && doh.enabled
        && doh.url.as_deref().is_none_or(|url| url.trim().is_empty())
    {
        return Err(Error::config(format!(
            "DNS server '{}' has enabled doh transport without url",
            server.id
        )));
    }

    if let Some(doq) = &server.doq
        && doq.enabled
        && doq
            .addr
            .as_deref()
            .is_none_or(|addr| addr.trim().is_empty())
    {
        return Err(Error::config(format!(
            "DNS server '{}' has enabled doq transport without addr",
            server.id
        )));
    }

    Ok(())
}

fn validate_clusters(
    clusters: &BTreeMap<String, ClusterConfig>,
    server_ids: &HashSet<String>,
) -> Result<()> {
    for (id, cluster) in clusters {
        if id.trim().is_empty() {
            return Err(Error::config("config contains a cluster with an empty id"));
        }

        for member in &cluster.members {
            if !server_ids.contains(&member.to_lowercase()) {
                return Err(Error::config(format!(
                    "cluster '{id}' references unknown DNS server '{member}'"
                )));
            }
        }

        for field in [cluster.primary.as_ref(), cluster.preferred_writer.as_ref()]
            .into_iter()
            .flatten()
        {
            if !field.eq_ignore_ascii_case("auto") && !server_ids.contains(&field.to_lowercase()) {
                return Err(Error::config(format!(
                    "cluster '{id}' references unknown DNS server '{field}'"
                )));
            }
        }
    }

    Ok(())
}

pub fn init_config(path: Option<PathBuf>, force: bool) -> Result<PathBuf> {
    let Some(path) = path.or_else(default_config_path) else {
        return Err(Error::config(
            "could not determine a default config path; pass --config <path>",
        ));
    };

    write_default_config(&path, force)?;
    Ok(path)
}

/// Append a new server entry to the config file. Creates the file if it does
/// not exist yet. Existing file content — including comments and formatting —
/// is preserved; only the new `[[servers]]` block is appended.
pub fn add_server(path: Option<PathBuf>, server: DnsServerConfig) -> Result<PathBuf> {
    let Some(path) = path.or_else(default_config_path) else {
        return Err(Error::config(
            "could not determine a default config path; pass --config <path>",
        ));
    };

    // Validate via the serde types: check for duplicate IDs etc.
    let mut config = if path.exists() {
        load_from_path(&path)?
    } else {
        AppConfig::default()
    };
    config.servers.push(server.clone());
    config.validate()?;

    // Read the raw file so toml_edit can preserve comments and formatting.
    let raw = if path.exists() {
        std::fs::read_to_string(&path)
            .map_err(|e| Error::io(format!("reading config file '{}'", path.display()), e))?
    } else {
        String::new()
    };

    let mut doc: toml_edit::DocumentMut = raw.parse().map_err(|e| {
        Error::config(format!(
            "could not parse config file '{}': {e}",
            path.display()
        ))
    })?;

    append_server_entry(&mut doc, &server);

    ensure_config_dir(&path)?;
    write_private_file(&path, &doc.to_string())?;
    Ok(path)
}

/// Append a `[[servers]]` entry to a toml_edit document without touching
/// any existing content.
fn append_server_entry(doc: &mut toml_edit::DocumentMut, server: &DnsServerConfig) {
    use toml_edit::{Array, ArrayOfTables, Item, Table, value};

    let mut tbl = Table::new();
    // Blank line before each [[servers]] header for readability.
    tbl.decor_mut().set_prefix("\n");

    tbl["id"] = value(server.id.as_str());
    tbl["vendor"] = value(match server.vendor {
        VendorKind::Technitium => "technitium",
        VendorKind::Pangolin => "pangolin",
        VendorKind::Cloudflare => "cloudflare",
        VendorKind::Unifi => "unifi",
    });
    if let Some(loc) = server.location {
        tbl["location"] = value(match loc {
            ServerLocation::Local => "local",
            ServerLocation::External => "external",
        });
    }
    if let Some(ref v) = server.base_url {
        tbl["base_url"] = value(v.as_str());
    }
    if let Some(ref v) = server.base_url_env {
        tbl["base_url_env"] = value(v.as_str());
    }
    if let Some(ref v) = server.token_env {
        tbl["token_env"] = value(v.as_str());
    }
    match server.token.as_deref() {
        Some(t) => tbl["token"] = value(t),
        // Write an empty placeholder so the field is visible in the config file.
        None if server.token_env.is_none() => tbl["token"] = value(""),
        None => {}
    }
    if let Some(ref v) = server.org_id {
        tbl["org_id"] = value(v.as_str());
    }

    let mut access_arr = Array::new();
    for rule in &server.mcp.access {
        access_arr.push(match rule {
            PolicyRule::Read => "read",
            PolicyRule::Write => "write",
            PolicyRule::Delete => "delete",
        });
    }
    tbl["mcp_access"] = value(access_arr);
    let mut zones = Array::new();
    for zone in &server.mcp.allowed_zones {
        zones.push(zone.as_str());
    }
    tbl["mcp_allowed_zones"] = value(zones);

    if !server.validation_endpoints.is_empty() {
        let mut endpoints = ArrayOfTables::new();
        for endpoint in &server.validation_endpoints {
            let mut endpoint_tbl = Table::new();
            endpoint_tbl["name"] = value(endpoint.name.as_str());
            endpoint_tbl["transport"] = value(match endpoint.transport {
                ValidationTransport::Dns => "dns",
                ValidationTransport::Doh => "doh",
                ValidationTransport::Dot => "dot",
                ValidationTransport::Doq => "doq",
            });
            if !endpoint.address.is_empty() {
                endpoint_tbl["address"] = value(endpoint.address.as_str());
            }
            if let Some(port) = endpoint.port {
                endpoint_tbl["port"] = value(i64::from(port));
            }
            if let Some(ref url) = endpoint.url {
                endpoint_tbl["url"] = value(url.as_str());
            }
            if let Some(ref tls_server_name) = endpoint.tls_server_name {
                endpoint_tbl["tls_server_name"] = value(tls_server_name.as_str());
            }
            endpoint_tbl["enabled"] = value(endpoint.enabled);
            if let Some(timeout_ms) = endpoint.timeout_ms {
                endpoint_tbl["timeout_ms"] = value(timeout_ms as i64);
            }
            endpoints.push(endpoint_tbl);
        }
        tbl["validation_endpoints"] = Item::ArrayOfTables(endpoints);
    }

    if let Some(ref cluster) = server.cluster {
        tbl["cluster"] = value(cluster.as_str());
    }
    if let Some(ref dns) = server.dns {
        let mut dns_tbl = Table::new();
        dns_tbl["enabled"] = value(dns.enabled);
        if let Some(ref addr) = dns.addr {
            dns_tbl["addr"] = value(addr.as_str());
        }
        if let Some(timeout_ms) = dns.timeout_ms {
            dns_tbl["timeout_ms"] = value(timeout_ms as i64);
        }
        tbl["dns"] = Item::Table(dns_tbl);
    }
    if let Some(ref dot) = server.dot {
        let mut dot_tbl = Table::new();
        dot_tbl["enabled"] = value(dot.enabled);
        if let Some(ref addr) = dot.addr {
            dot_tbl["addr"] = value(addr.as_str());
        }
        if let Some(ref server_name) = dot.server_name {
            dot_tbl["server_name"] = value(server_name.as_str());
        }
        if let Some(timeout_ms) = dot.timeout_ms {
            dot_tbl["timeout_ms"] = value(timeout_ms as i64);
        }
        tbl["dot"] = Item::Table(dot_tbl);
    }
    if let Some(ref doh) = server.doh {
        let mut doh_tbl = Table::new();
        doh_tbl["enabled"] = value(doh.enabled);
        if let Some(ref url) = doh.url {
            doh_tbl["url"] = value(url.as_str());
        }
        if let Some(ref addr) = doh.addr {
            doh_tbl["addr"] = value(addr.as_str());
        }
        if let Some(ref server_name) = doh.server_name {
            doh_tbl["server_name"] = value(server_name.as_str());
        }
        if let Some(timeout_ms) = doh.timeout_ms {
            doh_tbl["timeout_ms"] = value(timeout_ms as i64);
        }
        tbl["doh"] = Item::Table(doh_tbl);
    }
    if let Some(ref doq) = server.doq {
        let mut doq_tbl = Table::new();
        doq_tbl["enabled"] = value(doq.enabled);
        if let Some(ref addr) = doq.addr {
            doq_tbl["addr"] = value(addr.as_str());
        }
        if let Some(ref server_name) = doq.server_name {
            doq_tbl["server_name"] = value(server_name.as_str());
        }
        if let Some(timeout_ms) = doq.timeout_ms {
            doq_tbl["timeout_ms"] = value(timeout_ms as i64);
        }
        tbl["doq"] = Item::Table(doq_tbl);
    }

    match doc.entry("servers") {
        toml_edit::Entry::Occupied(mut e) => {
            if let Some(aot) = e.get_mut().as_array_of_tables_mut() {
                aot.push(tbl);
            }
        }
        toml_edit::Entry::Vacant(e) => {
            let mut aot = ArrayOfTables::new();
            aot.push(tbl);
            e.insert(Item::ArrayOfTables(aot));
        }
    }
}

/// Append a `[[sync]]` profile entry to a toml_edit document without touching
/// any existing content.
fn append_sync_entry(doc: &mut toml_edit::DocumentMut, profile: &SyncProfile) {
    use toml_edit::{Array, ArrayOfTables, Item, Table, value};

    let mut tbl = Table::new();
    // Blank line before each [[sync]] header for readability.
    tbl.decor_mut().set_prefix("\n");

    tbl["name"] = value(profile.name.as_str());
    tbl["from"] = value(profile.from.as_str());
    tbl["to"] = value(profile.to.as_str());

    let mut zones = Array::new();
    for zone in &profile.zones {
        zones.push(zone.as_str());
    }
    tbl["zones"] = value(zones);

    if !profile.ip_map.is_empty() {
        let mut map_tbl = Table::new();
        for (src, dst) in &profile.ip_map {
            map_tbl[src.as_str()] = value(dst.as_str());
        }
        tbl["ip_map"] = Item::Table(map_tbl);
    }

    match doc.entry("sync") {
        toml_edit::Entry::Occupied(mut e) => {
            if let Some(aot) = e.get_mut().as_array_of_tables_mut() {
                aot.push(tbl);
            }
        }
        toml_edit::Entry::Vacant(e) => {
            let mut aot = ArrayOfTables::new();
            aot.push(tbl);
            e.insert(Item::ArrayOfTables(aot));
        }
    }
}

/// Validate a single `ip_map` entry: both sides must parse as IP addresses of
/// the same family.
fn validate_ip_pair(profile: &str, src: &str, dst: &str) -> Result<()> {
    let source: IpAddr = src.parse().map_err(|_| {
        Error::config(format!(
            "sync profile '{profile}': '{src}' is not a valid IP address"
        ))
    })?;
    let dest: IpAddr = dst.parse().map_err(|_| {
        Error::config(format!(
            "sync profile '{profile}': '{dst}' is not a valid IP address"
        ))
    })?;
    if source.is_ipv4() != dest.is_ipv4() {
        return Err(Error::config(format!(
            "sync profile '{profile}': IP mapping '{src}' = '{dst}' mixes IPv4 and IPv6"
        )));
    }
    Ok(())
}

fn write_default_config(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(Error::config(format!(
            "config file '{}' already exists; pass --force to overwrite it",
            path.display()
        )));
    }

    ensure_config_dir(path)?;
    let contents = AppConfig::render_starter_toml()?;
    write_private_file(path, &contents)
}

fn ensure_config_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::io(
                format!("creating config directory '{}'", parent.display()),
                e,
            )
        })?;
        restrict_dir_permissions(parent)?;
    }
    Ok(())
}

fn load_from_path(path: &Path) -> Result<AppConfig> {
    check_config_permissions(path)?;
    let contents = std::fs::read_to_string(path)
        .map_err(|e| Error::io(format!("reading config file '{}'", path.display()), e))?;
    let config: AppConfig = toml::from_str(&contents).map_err(|e| {
        Error::config(format!(
            "could not parse config file '{}': {e}",
            path.display()
        ))
    })?;
    config.validate()?;
    Ok(config)
}

fn append_cluster_entries(
    doc: &mut toml_edit::DocumentMut,
    clusters: &BTreeMap<String, ClusterConfig>,
) {
    use toml_edit::{Array, Item, Table, value};

    if clusters.is_empty() {
        return;
    }

    let mut clusters_tbl = Table::new();
    clusters_tbl.decor_mut().set_prefix("\n");

    for (id, cluster) in clusters {
        let mut tbl = Table::new();
        tbl["vendor"] = value(match cluster.vendor {
            VendorKind::Technitium => "technitium",
            VendorKind::Pangolin => "pangolin",
            VendorKind::Cloudflare => "cloudflare",
            VendorKind::Unifi => "unifi",
        });
        let mut members = Array::new();
        for member in &cluster.members {
            members.push(member.as_str());
        }
        tbl["members"] = value(members);
        tbl["write_policy"] = value(match cluster.write_policy {
            ClusterWritePolicy::PrimaryOnly => "primary_only",
        });
        if let Some(ref primary) = cluster.primary {
            tbl["primary"] = value(primary.as_str());
        }
        if let Some(ref catalog_zone) = cluster.catalog_zone {
            tbl["catalog_zone"] = value(catalog_zone.as_str());
        }
        if let Some(ref preferred_writer) = cluster.preferred_writer {
            tbl["preferred_writer"] = value(preferred_writer.as_str());
        }
        clusters_tbl[id] = Item::Table(tbl);
    }

    doc["clusters"] = Item::Table(clusters_tbl);
}

/// Write `contents` to `path` with owner-only permissions (0o600 on Unix).
/// Uses `OpenOptions::mode` so the file is never created world-readable,
/// then explicitly sets permissions to handle the overwrite (force) case.
#[cfg(unix)]
fn write_private_file(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| Error::io(format!("creating config file '{}'", path.display()), e))?;

    file.write_all(contents.as_bytes())
        .map_err(|e| Error::io(format!("writing config file '{}'", path.display()), e))?;

    // mode() only applies when the file is newly created; set explicitly for overwrites.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::io(format!("setting permissions on '{}'", path.display()), e))
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents)
        .map_err(|e| Error::io(format!("creating config file '{}'", path.display()), e))
}

/// Restrict the config directory to owner-only access (0o700 on Unix).
#[cfg(unix)]
fn restrict_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::io(format!("setting permissions on '{}'", path.display()), e))
}

#[cfg(not(unix))]
fn restrict_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Error if the config file is readable by anyone other than the owner.
#[cfg(unix)]
fn check_config_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)
        .map_err(|e| Error::io(format!("reading metadata for '{}'", path.display()), e))?;
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::config(format!(
            "config file '{}' has permissions {:04o} — group or world can read it.\n\
             API tokens must be owner-readable only. Fix with:\n\
             \n    chmod 600 {}",
            path.display(),
            mode,
            path.display(),
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_config_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

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
            .as_deref()
            .filter(|t| !t.is_empty())
            .map(ApiToken::new)
            .ok_or_else(|| {
                Error::config(format!(
                    "DNS server '{}' has no token configured; set token or token_env in config, or pass --token",
                    self.id
                ))
            })
    }
}

/// Extracts the host portion (no port, no brackets around IPv6 literals) from a URL.
fn url_host(url: &str) -> &str {
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

fn is_local_ip(ip: IpAddr) -> bool {
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
async fn url_is_local(url: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

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

                [[servers]]
                id = "lab"
                vendor = "technitium"
                base_url = "http://lab.local:5380"
                token_env = "LAB_TOKEN"
            "#,
        )
        .expect("config should parse")
    }

    #[test]
    fn parses_per_server_mcp_permissions() {
        let config = config();
        let home = config.selected_server(Some("home")).unwrap();

        assert_eq!(home.id, "home");
        assert_eq!(home.vendor, VendorKind::Technitium);
        assert_eq!(home.base_url.as_deref(), Some("http://home.local:5380"));
        assert_eq!(home.mcp.access, vec![PolicyRule::Read]);
        assert_eq!(home.mcp.allowed_zones, ["example.com", "internal.lan"]);
    }

    #[test]
    fn requires_server_selection_when_multiple_servers_exist() {
        let err = config().selected_server(None).unwrap_err();

        assert!(err.to_string().contains("multiple DNS servers"));
    }

    #[test]
    fn rejects_duplicate_server_ids_case_insensitively() {
        let config: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "home"

                [[servers]]
                id = "HOME"
            "#,
        )
        .expect("config should parse before validation");

        let err = config.validate().unwrap_err();

        assert!(err.to_string().contains("duplicate DNS server id"));
    }

    #[test]
    fn rejects_unknown_mcp_permission_fields() {
        let err = toml::from_str::<AppConfig>(
            r#"
                [[servers]]
                id = "home"

                [servers.mcp]
                read_only = true
            "#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn selected_server_matches_case_insensitively() {
        let config = config();

        assert_eq!(config.selected_server(Some("HOME")).unwrap().id, "home");
    }

    #[test]
    fn load_creates_missing_config_with_defaults() {
        let path = temp_config_path("missing-default");

        let config = AppConfig::load(Some(path.clone()))
            .expect("missing config should be created and loaded")
            .expect("created config should load");

        let server = config.selected_server(None).unwrap();
        assert_eq!(server.id, "default");
        assert_eq!(server.vendor, VendorKind::Technitium);
        assert_eq!(server.base_url.as_deref(), Some("http://localhost:5380"));
        assert_eq!(
            server.token_env.as_deref(),
            Some("DNSYNC_TECHNITIUM_API_TOKEN")
        );
        assert!(server.token.is_none());
        {
            use std::collections::HashSet;
            let full: HashSet<PolicyRule> =
                [PolicyRule::Read, PolicyRule::Write, PolicyRule::Delete]
                    .into_iter()
                    .collect();
            let actual: HashSet<PolicyRule> = server.mcp.access.iter().cloned().collect();
            assert_eq!(actual, full);
        }
        assert!(server.mcp.allowed_zones.is_empty());

        // Verify the written file round-trips and uses token_env, not token
        let written = std::fs::read_to_string(&path).unwrap();
        let reparsed: AppConfig =
            toml::from_str(&written).expect("written config should be valid TOML");
        let reparsed_server = reparsed.selected_server(None).unwrap();
        assert_eq!(
            reparsed_server.token_env.as_deref(),
            Some("DNSYNC_TECHNITIUM_API_TOKEN")
        );
        assert!(reparsed_server.token.is_none());

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn load_does_not_overwrite_existing_config() {
        let path = temp_config_path("existing-config");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"
                [[servers]]
                id = "custom"
                token = "custom-token"
            "#,
        )
        .unwrap();
        // match the permissions the production code sets so the load check passes
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let config = AppConfig::load(Some(path.clone()))
            .expect("existing config should load")
            .expect("config should be present");

        assert_eq!(config.selected_server(None).unwrap().id, "custom");
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("custom-token")
        );

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn init_config_refuses_to_overwrite_existing_config() {
        let path = temp_config_path("init-existing-config");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "existing = true\n").unwrap();

        let err = init_config(Some(path.clone()), false).unwrap_err();

        assert!(err.to_string().contains("already exists"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "existing = true\n");

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn init_config_force_overwrites_existing_config() {
        let path = temp_config_path("init-force-config");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "existing = true\n").unwrap();

        let written_path = init_config(Some(path.clone()), true).unwrap();

        assert_eq!(written_path, path);

        let written = std::fs::read_to_string(&written_path).unwrap();
        let config: AppConfig =
            toml::from_str(&written).expect("written config should be valid TOML");
        let server = config.selected_server(None).unwrap();
        assert_eq!(server.id, "default");
        assert_eq!(
            server.token_env.as_deref(),
            Some("DNSYNC_TECHNITIUM_API_TOKEN")
        );
        assert!(server.token.is_none());

        std::fs::remove_dir_all(written_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn cli_base_url_override_wins_over_config() {
        let server = config().selected_server(Some("home")).unwrap().clone();

        assert_eq!(
            server.resolved_base_url(Some("http://override.local:5380")),
            "http://override.local:5380"
        );
    }

    #[test]
    fn technitium_base_url_defaults_to_localhost() {
        let server = DnsServerConfig {
            id: "home".to_string(),
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

        assert_eq!(server.resolved_base_url(None), TECHNITIUM_DEFAULT_BASE_URL);
    }

    #[test]
    fn pangolin_base_url_defaults_to_cloud_api() {
        let server = DnsServerConfig {
            id: "cloud".to_string(),
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

        assert_eq!(server.resolved_base_url(None), PANGOLIN_DEFAULT_BASE_URL);
    }

    #[test]
    fn cli_token_override_wins_over_config() {
        let server = config().selected_server(Some("home")).unwrap().clone();

        assert_eq!(
            server
                .resolved_token(Some("override-token"))
                .unwrap()
                .expose_for_auth(),
            "override-token"
        );
    }

    #[test]
    fn debug_default_config_path_uses_repo_root() {
        let path = default_config_path().expect("debug builds should have a default config path");

        assert_eq!(
            path,
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join(".config")
                .join("dnsync")
                .join("config.toml")
        );
    }

    #[test]
    fn starter_config_contains_token_env() {
        let toml = AppConfig::render_starter_toml().unwrap();
        assert!(
            toml.contains(r#"token_env = "DNSYNC_TECHNITIUM_API_TOKEN""#),
            "starter TOML should contain token_env assignment"
        );
    }

    #[test]
    fn starter_config_does_not_contain_literal_token() {
        let toml = AppConfig::render_starter_toml().unwrap();
        assert!(
            !toml.lines().any(|l| l.trim_start().starts_with("token =")),
            "starter TOML must not contain a bare `token = ...` key"
        );
    }

    #[test]
    fn starter_config_round_trips() {
        let toml = AppConfig::render_starter_toml().unwrap();
        let reparsed: AppConfig = toml::from_str(&toml).expect("starter TOML should parse back");
        let server = reparsed.selected_server(None).unwrap();
        assert_eq!(server.id, "default");
        assert_eq!(server.vendor, VendorKind::Technitium);
        assert_eq!(server.base_url.as_deref(), Some("http://localhost:5380"));
        assert_eq!(
            server.token_env.as_deref(),
            Some("DNSYNC_TECHNITIUM_API_TOKEN")
        );
        assert!(server.token.is_none());
        {
            use std::collections::HashSet;
            let full: HashSet<PolicyRule> =
                [PolicyRule::Read, PolicyRule::Write, PolicyRule::Delete]
                    .into_iter()
                    .collect();
            let actual: HashSet<PolicyRule> = server.mcp.access.iter().cloned().collect();
            assert_eq!(actual, full);
        }
        assert!(server.mcp.allowed_zones.is_empty());
    }

    #[test]
    fn starter_config_validates() {
        AppConfig::starter()
            .validate()
            .expect("starter config should pass validation");
    }

    #[cfg(unix)]
    #[test]
    fn written_config_file_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_config_path("perms-file");

        init_config(Some(path.clone()), false).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "config file should be owner read/write only (0600)"
        );

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn written_config_dir_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_config_path("perms-dir");

        init_config(Some(path.clone()), false).unwrap();

        let dir = path.parent().unwrap();
        let mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "config directory should be owner-only (0700)");

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn redact_replaces_token_but_preserves_token_env() {
        let cfg: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "home"
                token = "secret"
                token_env = "MY_TOKEN_VAR"
            "#,
        )
        .unwrap();

        let redacted = cfg.redact();
        let server = redacted.selected_server(None).unwrap();
        assert_eq!(server.token.as_deref(), Some("[redacted]"));
        assert_eq!(server.token_env.as_deref(), Some("MY_TOKEN_VAR"));
    }

    #[test]
    fn redact_leaves_none_token_as_none() {
        let cfg: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "home"
                token_env = "MY_TOKEN_VAR"
            "#,
        )
        .unwrap();

        let redacted = cfg.redact();
        assert!(redacted.selected_server(None).unwrap().token.is_none());
    }

    #[test]
    fn config_validation_endpoint_roundtrip() {
        let cfg: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "home"
                token_env = "MY_TOKEN_VAR"

                [[servers.validation_endpoints]]
                name = "router"
                transport = "dns"
                address = "192.168.1.1"
                port = 53
                enabled = true
                timeout_ms = 1500

                [[servers.validation_endpoints]]
                name = "cloudflare-doh"
                transport = "doh"
                url = "https://cloudflare-dns.com/dns-query"
                enabled = true

                [[servers.validation_endpoints]]
                name = "quad9-dot"
                transport = "dot"
                address = "9.9.9.9"
                port = 853
                tls_server_name = "dns.quad9.net"
            "#,
        )
        .unwrap();

        cfg.validate().unwrap();
        let rendered = cfg.render_toml().unwrap();
        let reparsed: AppConfig = toml::from_str(&rendered).unwrap();
        let endpoints = &reparsed.selected_server(None).unwrap().validation_endpoints;

        assert_eq!(endpoints.len(), 3);
        assert_eq!(endpoints[0].name, "router");
        assert_eq!(endpoints[0].transport, ValidationTransport::Dns);
        assert_eq!(
            endpoints[1].url.as_deref(),
            Some("https://cloudflare-dns.com/dns-query")
        );
        assert_eq!(
            endpoints[2].tls_server_name.as_deref(),
            Some("dns.quad9.net")
        );
        assert!(rendered.contains("[[servers.validation_endpoints]]"));
    }

    #[test]
    fn server_transport_blocks_roundtrip() {
        let cfg: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "dns1"
                vendor = "technitium"
                cluster = "home-dns"

                [servers.dns]
                enabled = true
                addr = "10.5.0.53:53"
                timeout_ms = 1500

                [servers.dot]
                enabled = true
                addr = "10.5.0.53:853"
                server_name = "dns1.hankin.io"

                [servers.doh]
                enabled = true
                url = "https://dns1.hankin.io/dns-query"
                addr = "10.5.0.53:443"
                server_name = "dns1.hankin.io"

                [servers.doq]
                enabled = true
                addr = "10.5.0.53:853"
                server_name = "dns1.hankin.io"
                timeout_ms = 2000

                [clusters.home-dns]
                members = ["dns1"]
            "#,
        )
        .unwrap();

        cfg.validate().unwrap();
        let rendered = cfg.render_toml().unwrap();
        let reparsed: AppConfig = toml::from_str(&rendered).unwrap();
        let server = reparsed.selected_server(None).unwrap();

        assert_eq!(server.cluster.as_deref(), Some("home-dns"));
        assert_eq!(
            server.dns.as_ref().unwrap().addr.as_deref(),
            Some("10.5.0.53:53")
        );
        assert_eq!(
            server.dot.as_ref().unwrap().server_name.as_deref(),
            Some("dns1.hankin.io")
        );
        assert_eq!(
            server.doh.as_ref().unwrap().url.as_deref(),
            Some("https://dns1.hankin.io/dns-query")
        );
        let doq = server.doq.as_ref().unwrap();
        assert!(doq.enabled);
        assert_eq!(doq.addr.as_deref(), Some("10.5.0.53:853"));
        assert_eq!(doq.server_name.as_deref(), Some("dns1.hankin.io"));
        assert_eq!(doq.timeout_ms, Some(2000));
        assert!(rendered.contains("[servers.dns]"));
        assert!(rendered.contains("[servers.dot]"));
        assert!(rendered.contains("[servers.doh]"));
        assert!(rendered.contains("[servers.doq]"));
    }

    #[test]
    fn validate_rejects_doq_without_addr() {
        let cfg: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "dns1"

                [servers.doq]
                enabled = true
            "#,
        )
        .unwrap();

        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("enabled doq transport without addr"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn disabled_doq_block_does_not_require_addr() {
        let cfg: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "dns1"

                [servers.doq]
                enabled = false
            "#,
        )
        .unwrap();

        cfg.validate().unwrap();
    }

    #[test]
    fn disabled_transport_blocks_can_omit_endpoints() {
        let cfg: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "dns1"

                [servers.dns]
                enabled = false

                [servers.dot]
                enabled = false

                [servers.doh]
                enabled = false
            "#,
        )
        .unwrap();

        cfg.validate().unwrap();
        let rendered = cfg.render_toml().unwrap();

        assert!(rendered.contains("[servers.dns]"));
        assert!(rendered.contains("enabled = false"));
        assert!(!rendered.contains("addr = \"\""));
        assert!(!rendered.contains("url = \"\""));
    }

    #[test]
    fn cluster_config_roundtrip() {
        let cfg: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "dns1"
                vendor = "technitium"
                cluster = "home-dns"

                [[servers]]
                id = "dns2"
                vendor = "technitium"
                cluster = "home-dns"

                [clusters.home-dns]
                vendor = "technitium"
                members = ["dns1", "dns2"]
                write_policy = "primary_only"
                primary = "auto"
                catalog_zone = "auto"
                preferred_writer = "dns1"
            "#,
        )
        .unwrap();

        cfg.validate().unwrap();
        let rendered = cfg.render_toml().unwrap();
        let reparsed: AppConfig = toml::from_str(&rendered).unwrap();
        let cluster = reparsed.clusters.get("home-dns").unwrap();

        assert_eq!(cluster.members, ["dns1", "dns2"]);
        assert_eq!(cluster.write_policy, ClusterWritePolicy::PrimaryOnly);
        assert_eq!(cluster.primary.as_deref(), Some("auto"));
        assert_eq!(cluster.catalog_zone.as_deref(), Some("auto"));
        assert_eq!(cluster.preferred_writer.as_deref(), Some("dns1"));
        assert!(rendered.contains("[clusters.home-dns]"));
    }

    #[test]
    fn cluster_rejects_unknown_members() {
        let cfg: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "dns1"

                [clusters.home-dns]
                members = ["dns1", "dns2"]
            "#,
        )
        .unwrap();

        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("unknown DNS server 'dns2'"));
    }

    #[test]
    fn server_rejects_unknown_cluster_reference() {
        let cfg: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "dns1"
                cluster = "missing"
            "#,
        )
        .unwrap();

        let err = cfg.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("DNS server 'dns1' references unknown cluster 'missing'")
        );
    }

    #[test]
    fn config_rejects_invalid_validation_endpoint() {
        let cfg: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "home"
                token_env = "MY_TOKEN_VAR"

                [[servers.validation_endpoints]]
                name = ""
                transport = "dns"
                address = "192.168.1.1"
            "#,
        )
        .unwrap();

        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("empty name"));

        let cfg: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "home"
                token_env = "MY_TOKEN_VAR"

                [[servers.validation_endpoints]]
                name = "missing-url"
                transport = "doh"
            "#,
        )
        .unwrap();

        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("requires url"));
    }

    #[test]
    fn config_print_redacts_tokens_but_keeps_validation_endpoints() {
        let cfg: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "home"
                token = "secret"

                [[servers.validation_endpoints]]
                name = "router"
                transport = "dns"
                address = "192.168.1.1"
            "#,
        )
        .unwrap();

        let redacted = cfg.redact();
        let server = redacted.selected_server(None).unwrap();

        assert_eq!(server.token.as_deref(), Some("[redacted]"));
        assert_eq!(
            server.validation_endpoints,
            cfg.servers[0].validation_endpoints
        );
    }

    #[test]
    fn load_if_exists_returns_none_when_no_file() {
        let path = temp_config_path("load-if-exists-missing");
        assert!(!path.exists());

        let result = AppConfig::load_if_exists(Some(path)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn load_if_exists_returns_config_when_file_present() {
        let path = temp_config_path("load-if-exists-present");
        // Use init_config so the file is created with correct permissions
        init_config(Some(path.clone()), false).unwrap();

        let config = AppConfig::load_if_exists(Some(path.clone()))
            .expect("should load")
            .expect("should be Some");
        assert_eq!(config.selected_server(None).unwrap().id, "default");

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn add_server_creates_config_with_single_server() {
        let path = temp_config_path("add-server-new");
        let server = DnsServerConfig {
            id: "myserver".to_string(),
            vendor: VendorKind::Technitium,
            location: None,
            base_url: Some("http://192.168.1.10:5380".to_string()),
            base_url_env: None,
            token: None,
            token_env: Some("MY_API_TOKEN".to_string()),
            org_id: None,
            cluster: None,
            dns: None,
            dot: None,
            doh: None,
            doq: None,
            mcp: McpPermissions::default(),
            validation_endpoints: Vec::new(),
        };

        let written = add_server(Some(path.clone()), server).unwrap();
        assert_eq!(written, path);

        let config = AppConfig::load(Some(path.clone())).unwrap().unwrap();
        let s = config.selected_server(None).unwrap();
        assert_eq!(s.id, "myserver");
        assert_eq!(s.token_env.as_deref(), Some("MY_API_TOKEN"));

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn add_server_appends_to_existing_config() {
        let path = temp_config_path("add-server-existing");
        init_config(Some(path.clone()), false).unwrap();

        let server = DnsServerConfig {
            id: "lab".to_string(),
            vendor: VendorKind::Technitium,
            location: None,
            base_url: Some("http://192.168.1.20:5380".to_string()),
            base_url_env: None,
            token: None,
            token_env: Some("LAB_TOKEN".to_string()),
            org_id: None,
            cluster: None,
            dns: None,
            dot: None,
            doh: None,
            doq: None,
            mcp: McpPermissions::default(),
            validation_endpoints: Vec::new(),
        };

        add_server(Some(path.clone()), server).unwrap();

        let config = AppConfig::load(Some(path.clone())).unwrap().unwrap();
        assert_eq!(config.servers.len(), 2);
        assert!(config.selected_server(Some("default")).is_ok());
        assert!(config.selected_server(Some("lab")).is_ok());

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn add_server_preserves_comments_in_existing_config() {
        let path = temp_config_path("add-server-comments");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = concat!(
            "# My DNS servers\n",
            "[[servers]]\n",
            "id = \"home\"\n",
            "# Home server uses its own env var\n",
            "token_env = \"HOME_TOKEN\"\n",
        );
        std::fs::write(&path, original).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let server = DnsServerConfig {
            id: "lab".to_string(),
            vendor: VendorKind::Technitium,
            location: None,
            base_url: None,
            base_url_env: None,
            token: None,
            token_env: Some("LAB_TOKEN".to_string()),
            org_id: None,
            cluster: None,
            dns: None,
            dot: None,
            doh: None,
            doq: None,
            mcp: McpPermissions::default(),
            validation_endpoints: Vec::new(),
        };
        add_server(Some(path.clone()), server).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.contains("# My DNS servers"),
            "top-level comment should be preserved"
        );
        assert!(
            written.contains("# Home server uses its own env var"),
            "inline comment should be preserved"
        );
        assert!(
            written.contains("id = \"lab\""),
            "new server should be appended"
        );

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn add_server_rejects_duplicate_id() {
        let path = temp_config_path("add-server-duplicate");
        init_config(Some(path.clone()), false).unwrap();

        let server = DnsServerConfig {
            id: "default".to_string(), // already exists
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

        let err = add_server(Some(path.clone()), server).unwrap_err();
        assert!(err.to_string().contains("duplicate DNS server id"));

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn load_errors_if_config_is_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_config_path("world-readable");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, AppConfig::render_starter_toml().unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = AppConfig::load(Some(path.clone())).unwrap_err();

        assert!(
            err.to_string().contains("chmod 600"),
            "error should include remediation command"
        );

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
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

    // ── sync profiles ─────────────────────────────────────────────────────────

    fn sync_config() -> &'static str {
        r#"
            [[servers]]
            id = "cf"
            token = "tok"

            [[servers]]
            id = "home"
            token = "tok"

            [[sync]]
            name = "split"
            from = "cf"
            to = "home"
            zones = ["example.com"]

            [sync.ip_map]
            "203.0.113.10" = "192.168.1.10"
        "#
    }

    #[test]
    fn parses_and_validates_sync_profile() {
        let config: AppConfig = toml::from_str(sync_config()).expect("should parse");
        config.validate().expect("sync profile should validate");

        assert_eq!(config.sync.len(), 1);
        let profile = &config.sync[0];
        assert_eq!(profile.name, "split");
        assert_eq!(profile.from, "cf");
        assert_eq!(profile.to, "home");
        assert_eq!(profile.zones, ["example.com"]);
        assert_eq!(
            profile.ip_map.get("203.0.113.10").map(String::as_str),
            Some("192.168.1.10")
        );
    }

    #[test]
    fn sync_profile_round_trips_through_render_toml() {
        let config: AppConfig = toml::from_str(sync_config()).expect("should parse");
        let rendered = config.render_toml().expect("should render");
        let reparsed: AppConfig =
            toml::from_str(&rendered).expect("rendered sync config should parse back");
        reparsed
            .validate()
            .expect("reparsed config should validate");
        assert_eq!(reparsed.sync.len(), 1);
        assert_eq!(reparsed.sync[0].name, "split");
        assert_eq!(
            reparsed.sync[0]
                .ip_map
                .get("203.0.113.10")
                .map(String::as_str),
            Some("192.168.1.10")
        );
    }

    #[test]
    fn rejects_sync_profile_with_unknown_server() {
        let config: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "cf"
                token = "tok"

                [[sync]]
                name = "bad"
                from = "cf"
                to = "missing"
            "#,
        )
        .expect("should parse before validation");

        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("unknown destination server"));
    }

    #[test]
    fn rejects_sync_profile_with_family_mismatched_ip_map() {
        let config: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "cf"
                token = "tok"

                [[servers]]
                id = "home"
                token = "tok"

                [[sync]]
                name = "bad"
                from = "cf"
                to = "home"

                [sync.ip_map]
                "203.0.113.10" = "fd00::1"
            "#,
        )
        .expect("should parse before validation");

        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("IPv4 and IPv6"));
    }

    #[test]
    fn rejects_duplicate_sync_profile_names() {
        let config: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "cf"
                token = "tok"

                [[servers]]
                id = "home"
                token = "tok"

                [[sync]]
                name = "dup"
                from = "cf"
                to = "home"

                [[sync]]
                name = "DUP"
                from = "home"
                to = "cf"
            "#,
        )
        .expect("should parse before validation");

        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate sync profile name"));
    }
}
