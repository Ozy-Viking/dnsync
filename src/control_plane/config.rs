use std::{
    collections::{BTreeMap, HashSet},
    env,
    net::IpAddr,
    path::{Path, PathBuf},
};

use hickory_resolver::Resolver;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::control_plane::policy::PolicyRule;
use crate::core::error::{Error, Result};
use crate::core::secret::ApiToken;

pub const TECHNITIUM_DEFAULT_BASE_URL: &str = "http://localhost:5380";
pub const PANGOLIN_DEFAULT_BASE_URL: &str = "https://api.pangolin.net/v1";
pub const CLOUDFLARE_DEFAULT_BASE_URL: &str = "https://api.cloudflare.com/client/v4";
pub const UNIFI_DEFAULT_BASE_URL: &str = "https://192.168.1.1/proxy/network/integration/v1";
pub const PIHOLE_DEFAULT_BASE_URL: &str = "http://pi.hole";

const CLOUDFLARE_RESOLVER_IP: &str = "1.1.1.1";
const CLOUDFLARE_RESOLVER_NAME: &str = "cloudflare-dns.com";
const CLOUDFLARE_DOH_URL: &str = "https://cloudflare-dns.com/dns-query";

/// Supported DNS vendor backends.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum VendorKind {
    #[default]
    Technitium,
    Pangolin,
    Cloudflare,
    Unifi,
    Pihole,
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

    /// Parses a validation endpoint from a `name:transport:address` string.
    ///
    /// The expected input is three colon-separated parts: `name:transport:address`.
    /// Valid transports are `dns`, `doh`, `dot`, and `doq` (case-insensitive).
    /// For the `doh` transport the third part is interpreted as the DoH `url` and the `address` field is left empty;
    /// for the other transports the third part becomes the `address` and the `url` field is left `None`.
    /// Returns an error message when the input is malformed or the transport is unsupported.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use std::str::FromStr;
    ///
    /// let cfg = ValidationEndpointConfig::from_str("google:doh:https://dns.google/dns-query").unwrap();
    /// assert_eq!(cfg.name, "google");
    /// assert!(matches!(cfg.transport, ValidationTransport::Doh));
    /// assert_eq!(cfg.url.as_deref(), Some("https://dns.google/dns-query"));
    ///
    /// let cfg2 = ValidationEndpointConfig::from_str("local:dns:1.1.1.1:53");
    /// assert!(cfg2.is_ok());
    /// ```
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
            Some("doq") => ValidationTransport::Doq,
            Some(other) => {
                return Err(format!(
                    "unsupported validation endpoint transport '{other}'; expected dns, doh, dot, or doq"
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

/// Job kind discriminant — matches the `JobKind` in `daemon::types`.
///
/// Defined here because it is part of the config file schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    RecordSync,
    ZoneSync,
    ZoneExport,
}

/// Provides the default heartbeat interval string used by the daemon.
///
/// # Returns
///
/// A string containing the interval formatted as a duration literal, e.g. `"5s"`.
///
/// # Examples
///
/// ```text
/// let s = default_heartbeat_interval();
/// assert_eq!(s, "5s");
/// ```
fn default_heartbeat_interval() -> String {
    "5s".to_string()
}
/// Default heartbeat timeout value as a string.
///
/// # Examples
///
/// ```text
/// assert_eq!(default_heartbeat_timeout(), "20s");
/// ```
fn default_heartbeat_timeout() -> String {
    "20s".to_string()
}
/// Default shutdown timeout string used by the daemon configuration.

///

/// # Returns

///

/// `"5s"` representing five seconds.

///

/// # Examples

///

/// ```text

/// assert_eq!(default_shutdown_timeout(), "5s");

/// ```
fn default_shutdown_timeout() -> String {
    "5s".to_string()
}
/// Default number of worker threads used by the daemon.
///
/// Returns the default thread count: `4`.
///
/// # Examples
///
/// ```text
/// assert_eq!(default_worker_threads(), 4);
/// ```
fn default_worker_threads() -> usize {
    4
}
/// Default critical failure threshold for the daemon.
///
/// # Returns
///
/// The default threshold value: `5`.
///
/// # Examples
///
/// ```text
/// assert_eq!(default_critical_threshold(), 5);
/// ```
fn default_critical_threshold() -> u32 {
    5
}

/// Daemon runtime configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    /// Path to the SQLite state database.
    ///
    /// Optional here — the runtime resolves `DNSYNC_STATE_DB` if unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_db: Option<PathBuf>,

    /// How often the daemon emits a heartbeat (e.g. `"5s"`).
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: String,

    /// Time after which a missed heartbeat is treated as a fault (e.g. `"20s"`).
    #[serde(default = "default_heartbeat_timeout")]
    pub heartbeat_timeout: String,

    /// Grace period for in-flight jobs during a graceful shutdown (e.g. `"5s"`).
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout: String,

    /// Tokio worker threads dedicated to the daemon.
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,

    /// Number of consecutive critical-job failures before escalating to `Fatal`.
    #[serde(default = "default_critical_threshold")]
    pub critical_failure_threshold: u32,
}

/// A daemon job entry — flat config struct covering all job kinds.
///
/// Exactly one of `schedule` or `interval` must be present.
/// The `from`/`to` fields are required for `RecordSync` and `ZoneSync`.
/// The `output_dir` field is required for `ZoneExport`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobConfig {
    pub id: String,
    pub kind: JobKind,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub critical: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(default)]
    pub run_immediately: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jitter: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
    // RecordSync + ZoneSync fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub ip_map: BTreeMap<String, String>,
    // RecordSync-only fields
    #[serde(default = "default_true")]
    pub create_missing: bool,
    #[serde(default = "default_true")]
    pub overwrite_existing: bool,
    #[serde(default)]
    pub delete_destination_only: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore: Vec<String>,
    // ZoneExport-only fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_dir: Option<String>,
}

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

fn apply_provider_transport_defaults(server: &mut DnsServerConfig) {
    let inferred_local = server.location.is_none()
        && server.base_url.as_deref().is_some_and(|url| {
            let host = url_host(url);
            host.eq_ignore_ascii_case("localhost")
                || host.parse::<IpAddr>().ok().is_some_and(is_local_ip)
        });
    if server.location == Some(ServerLocation::Local) || inferred_local {
        return;
    }

    match server.vendor {
        VendorKind::Cloudflare => apply_cloudflare_transport_defaults(server),
        VendorKind::Technitium | VendorKind::Pangolin | VendorKind::Unifi | VendorKind::Pihole => {}
    }
}

fn apply_cloudflare_transport_defaults(server: &mut DnsServerConfig) {
    server.dns.get_or_insert_with(|| DnsTransportConfig {
        enabled: true,
        addr: Some(format!("{CLOUDFLARE_RESOLVER_IP}:53")),
        timeout_ms: None,
    });
    server.dot.get_or_insert_with(|| DotTransportConfig {
        enabled: true,
        addr: Some(format!("{CLOUDFLARE_RESOLVER_IP}:853")),
        server_name: Some(CLOUDFLARE_RESOLVER_NAME.to_string()),
        timeout_ms: None,
    });
    server.doh.get_or_insert_with(|| DohTransportConfig {
        enabled: true,
        url: Some(CLOUDFLARE_DOH_URL.to_string()),
        addr: Some(format!("{CLOUDFLARE_RESOLVER_IP}:443")),
        server_name: Some(CLOUDFLARE_RESOLVER_NAME.to_string()),
        timeout_ms: None,
    });
    server.doq.get_or_insert_with(|| DoqTransportConfig {
        enabled: true,
        addr: Some(format!("{CLOUDFLARE_RESOLVER_IP}:853")),
        server_name: Some(CLOUDFLARE_RESOLVER_NAME.to_string()),
        timeout_ms: None,
    });
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

impl AppConfig {
    /// Create a starter `AppConfig` populated with one default server for bootstrapping.
    ///
    /// The returned configuration contains:
    /// - a single `DnsServerConfig` with `id = "default"`, vendor `Technitium`,
    ///   `base_url` set to the Technitium default, `token_env = "DNSYNC_TECHNITIUM_API_TOKEN"`,
    ///   and default MCP permissions;
    /// - empty `clusters`;
    /// - no `daemon`;
    /// - no `jobs`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let cfg = AppConfig::starter();
    /// assert_eq!(cfg.servers.len(), 1);
    /// let srv = &cfg.servers[0];
    /// assert_eq!(srv.id, "default");
    /// assert_eq!(srv.vendor, VendorKind::Technitium);
    /// assert_eq!(srv.token_env.as_deref(), Some("DNSYNC_TECHNITIUM_API_TOKEN"));
    /// ```
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
            daemon: None,
            jobs: Vec::new(),
        }
    }

    pub fn render_starter_toml() -> Result<String> {
        Self::starter().render_toml()
    }

    /// Render the configuration as a TOML document string.
    ///
    /// The output includes serialized `servers` (`[[servers]]` entries), a `[clusters]` table
    /// (when clusters exist), an optional `[daemon]` table, and `[[jobs]]` entries in that order.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let cfg = AppConfig::starter();
    /// let toml = cfg.render_toml().unwrap();
    /// assert!(toml.contains("[[servers]]"));
    /// assert!(toml.contains("token_env"));
    /// ```
    pub fn render_toml(&self) -> Result<String> {
        let mut doc = toml_edit::DocumentMut::new();
        for server in &self.servers {
            append_server_entry(&mut doc, server);
        }
        append_cluster_entries(&mut doc, &self.clusters);
        if let Some(ref daemon) = self.daemon {
            append_daemon_entry(&mut doc, daemon);
        }
        for job in &self.jobs {
            append_job_entry(&mut doc, job);
        }
        Ok(doc.to_string())
    }

    /// Create a copy of the configuration with any literal server `token` values replaced by `"[redacted]"`.
    ///
    /// Literal `token` fields are replaced; `token_env` (environment variable names) are preserved unchanged.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let cfg = AppConfig {
    ///     servers: vec![DnsServerConfig { id: "s".into(), token: Some("secret".into()), token_env: None, ..Default::default() }],
    ///     ..Default::default()
    /// };
    /// let redacted = cfg.redact();
    /// assert_eq!(redacted.servers[0].token.as_deref(), Some("[redacted]"));
    /// assert_eq!(redacted.servers[0].token_env, cfg.servers[0].token_env);
    /// ```
    pub fn redact(&self) -> Self {
        AppConfig {
            servers: self
                .servers
                .iter()
                .map(|s| DnsServerConfig {
                    token: s.token.as_ref().map(|_| ApiToken::new("[redacted]")),
                    ..s.clone()
                })
                .collect(),
            clusters: self.clusters.clone(),
            daemon: self.daemon.clone(),
            jobs: self.jobs.clone(),
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

    /// Performs semantic validation of the configuration.
    ///
    /// This checks each server for a non-empty, unique (case-insensitive) id; verifies any
    /// server `cluster` references exist; validates configured transport endpoints and
    /// validation endpoints for each server; validates cluster definitions and job entries
    /// (including job id uniqueness, scheduling rules, server references, IP-map consistency,
    /// and regex compilation).
    ///
    /// Returns `Ok(())` when all checks pass, or an `Error::config(...)` describing the first
    /// validation failure encountered.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let cfg = AppConfig::default();
    /// // starter/default config should validate
    /// cfg.validate().unwrap();
    /// ```
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
        validate_jobs(&self.jobs, &ids)?;

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
            ValidationTransport::Dns | ValidationTransport::Dot | ValidationTransport::Doq
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateDefaultsReport {
    pub path: PathBuf,
    pub updated_servers: usize,
    pub added_values: usize,
}

/// Add currently-known default values to existing server entries without
/// overwriting any field or sub-table already present in the config file.
pub fn update_defaults(path: Option<PathBuf>) -> Result<UpdateDefaultsReport> {
    let Some(path) = path.or_else(default_config_path) else {
        return Err(Error::config(
            "could not determine a default config path; pass --config <path>",
        ));
    };

    let config = load_from_path(&path)?;
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| Error::io(format!("reading config file '{}'", path.display()), e))?;
    let mut doc: toml_edit::DocumentMut = raw.parse().map_err(|e| {
        Error::config(format!(
            "could not parse config file '{}': {e}",
            path.display()
        ))
    })?;

    let servers = doc
        .get_mut("servers")
        .and_then(|v| v.as_array_of_tables_mut())
        .ok_or_else(|| Error::config("config file has no [[servers]] entries"))?;

    let mut updated_servers = 0usize;
    let mut added_values = 0usize;

    for server_tbl in servers.iter_mut() {
        let Some(id) = server_tbl
            .get("id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
        else {
            continue;
        };
        let Some(server) = config
            .servers
            .iter()
            .find(|server| server.id.eq_ignore_ascii_case(&id))
        else {
            continue;
        };

        let before = added_values;
        added_values += add_missing_server_defaults(server_tbl, server);
        if added_values > before {
            updated_servers += 1;
        }
    }

    if added_values > 0 {
        let updated: AppConfig = toml::from_str(&doc.to_string())
            .map_err(|e| Error::config(format!("updated config would be invalid: {e}")))?;
        updated.validate()?;
        write_private_file(&path, &doc.to_string())?;
    }

    Ok(UpdateDefaultsReport {
        path,
        updated_servers,
        added_values,
    })
}

/// Specifies which transport endpoint on a server to create, replace, or remove.
///
/// `None` removes the transport block entirely. `Some(config)` creates or replaces it.
pub enum EndpointUpdate {
    Dns(Option<DnsTransportConfig>),
    Dot(Option<DotTransportConfig>),
    Doh(Option<DohTransportConfig>),
    Doq(Option<DoqTransportConfig>),
}

fn add_missing_server_defaults(
    server_tbl: &mut toml_edit::Table,
    server: &DnsServerConfig,
) -> usize {
    use toml_edit::{Array, Item, value};

    let mut added = 0usize;

    if !server_tbl.contains_key("vendor") {
        server_tbl["vendor"] = value(vendor_name(server.vendor));
        added += 1;
    }

    if !server_tbl.contains_key("base_url") && !server_tbl.contains_key("base_url_env") {
        server_tbl["base_url"] = value(default_base_url(server.vendor));
        added += 1;
    }

    if !server_tbl.contains_key("mcp_access") && !server_tbl.contains_key("mcp") {
        let mut access = Array::new();
        for rule in &server.mcp.access {
            access.push(policy_rule_name(*rule));
        }
        server_tbl["mcp_access"] = value(access);
        added += 1;
    } else if let Some(mcp) = server_tbl
        .get_mut("mcp")
        .and_then(|item| item.as_table_mut())
        && !mcp.contains_key("access")
    {
        let mut access = Array::new();
        for rule in &server.mcp.access {
            access.push(policy_rule_name(*rule));
        }
        mcp["access"] = value(access);
        added += 1;
    }

    if let Some(mcp) = server_tbl
        .get_mut("mcp")
        .and_then(|item| item.as_table_mut())
        && !mcp.contains_key("show_settings_secrets")
    {
        mcp["show_settings_secrets"] = value(server.mcp.show_settings_secrets);
        added += 1;
    }

    if !server_tbl.contains_key("dns")
        && let Some(ref dns) = server.dns
    {
        server_tbl["dns"] = Item::Table(dns_transport_table(dns));
        added += 1;
    }
    if !server_tbl.contains_key("dot")
        && let Some(ref dot) = server.dot
    {
        server_tbl["dot"] = Item::Table(dot_transport_table(dot));
        added += 1;
    }
    if !server_tbl.contains_key("doh")
        && let Some(ref doh) = server.doh
    {
        server_tbl["doh"] = Item::Table(doh_transport_table(doh));
        added += 1;
    }
    if !server_tbl.contains_key("doq")
        && let Some(ref doq) = server.doq
    {
        server_tbl["doq"] = Item::Table(doq_transport_table(doq));
        added += 1;
    }

    added
}

fn default_base_url(vendor: VendorKind) -> &'static str {
    match vendor {
        VendorKind::Technitium => TECHNITIUM_DEFAULT_BASE_URL,
        VendorKind::Pangolin => PANGOLIN_DEFAULT_BASE_URL,
        VendorKind::Cloudflare => CLOUDFLARE_DEFAULT_BASE_URL,
        VendorKind::Unifi => UNIFI_DEFAULT_BASE_URL,
        VendorKind::Pihole => PIHOLE_DEFAULT_BASE_URL,
    }
}

fn vendor_name(vendor: VendorKind) -> &'static str {
    match vendor {
        VendorKind::Technitium => "technitium",
        VendorKind::Pangolin => "pangolin",
        VendorKind::Cloudflare => "cloudflare",
        VendorKind::Unifi => "unifi",
        VendorKind::Pihole => "pihole",
    }
}

fn policy_rule_name(rule: PolicyRule) -> &'static str {
    match rule {
        PolicyRule::Read => "read",
        PolicyRule::Write => "write",
        PolicyRule::Delete => "delete",
    }
}

fn dns_transport_table(cfg: &DnsTransportConfig) -> toml_edit::Table {
    use toml_edit::{Table, value};

    let mut tbl = Table::new();
    tbl["enabled"] = value(cfg.enabled);
    if let Some(ref addr) = cfg.addr {
        tbl["addr"] = value(addr.as_str());
    }
    if let Some(ms) = cfg.timeout_ms {
        tbl["timeout_ms"] = value(ms as i64);
    }
    tbl
}

fn dot_transport_table(cfg: &DotTransportConfig) -> toml_edit::Table {
    use toml_edit::{Table, value};

    let mut tbl = Table::new();
    tbl["enabled"] = value(cfg.enabled);
    if let Some(ref addr) = cfg.addr {
        tbl["addr"] = value(addr.as_str());
    }
    if let Some(ref sn) = cfg.server_name {
        tbl["server_name"] = value(sn.as_str());
    }
    if let Some(ms) = cfg.timeout_ms {
        tbl["timeout_ms"] = value(ms as i64);
    }
    tbl
}

fn doh_transport_table(cfg: &DohTransportConfig) -> toml_edit::Table {
    use toml_edit::{Table, value};

    let mut tbl = Table::new();
    tbl["enabled"] = value(cfg.enabled);
    if let Some(ref url) = cfg.url {
        tbl["url"] = value(url.as_str());
    }
    if let Some(ref addr) = cfg.addr {
        tbl["addr"] = value(addr.as_str());
    }
    if let Some(ref sn) = cfg.server_name {
        tbl["server_name"] = value(sn.as_str());
    }
    if let Some(ms) = cfg.timeout_ms {
        tbl["timeout_ms"] = value(ms as i64);
    }
    tbl
}

fn doq_transport_table(cfg: &DoqTransportConfig) -> toml_edit::Table {
    use toml_edit::{Table, value};

    let mut tbl = Table::new();
    tbl["enabled"] = value(cfg.enabled);
    if let Some(ref addr) = cfg.addr {
        tbl["addr"] = value(addr.as_str());
    }
    if let Some(ref sn) = cfg.server_name {
        tbl["server_name"] = value(sn.as_str());
    }
    if let Some(ms) = cfg.timeout_ms {
        tbl["timeout_ms"] = value(ms as i64);
    }
    tbl
}

/// Update a single transport endpoint on an existing server entry in the config file.
///
/// The server is matched by ID (case-insensitive). Existing file content — including
/// comments and formatting — is preserved; only the targeted transport sub-table is
/// added, replaced, or removed.
pub fn update_server_endpoint(
    path: Option<PathBuf>,
    server_id: &str,
    update: EndpointUpdate,
) -> Result<PathBuf> {
    let Some(path) = path.or_else(default_config_path) else {
        return Err(Error::config(
            "could not determine a default config path; pass --config <path>",
        ));
    };

    // Validate via the serde types first so we catch bad values early.
    let mut config = load_from_path(&path)?;
    let pos = config
        .servers
        .iter()
        .position(|s| s.id.eq_ignore_ascii_case(server_id))
        .ok_or_else(|| {
            Error::config(format!(
                "config does not define a DNS server named '{server_id}'"
            ))
        })?;
    match &update {
        EndpointUpdate::Dns(cfg) => config.servers[pos].dns = cfg.clone(),
        EndpointUpdate::Dot(cfg) => config.servers[pos].dot = cfg.clone(),
        EndpointUpdate::Doh(cfg) => config.servers[pos].doh = cfg.clone(),
        EndpointUpdate::Doq(cfg) => config.servers[pos].doq = cfg.clone(),
    }
    config.validate()?;

    // Read the raw file so toml_edit can preserve comments and formatting.
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| Error::io(format!("reading config file '{}'", path.display()), e))?;
    let mut doc: toml_edit::DocumentMut = raw.parse().map_err(|e| {
        Error::config(format!(
            "could not parse config file '{}': {e}",
            path.display()
        ))
    })?;

    let servers = doc
        .get_mut("servers")
        .and_then(|v| v.as_array_of_tables_mut())
        .ok_or_else(|| Error::config("config file has no [[servers]] entries"))?;

    let server_tbl = servers
        .iter_mut()
        .find(|tbl| {
            tbl.get("id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| id.eq_ignore_ascii_case(server_id))
        })
        .ok_or_else(|| {
            Error::config(format!(
                "config does not define a DNS server named '{server_id}'"
            ))
        })?;

    use toml_edit::{Item, Table, value};

    match update {
        EndpointUpdate::Dns(None) => {
            server_tbl.remove("dns");
        }
        EndpointUpdate::Dns(Some(cfg)) => {
            let mut tbl = Table::new();
            tbl["enabled"] = value(cfg.enabled);
            if let Some(ref addr) = cfg.addr {
                tbl["addr"] = value(addr.as_str());
            }
            if let Some(ms) = cfg.timeout_ms {
                tbl["timeout_ms"] = value(ms as i64);
            }
            server_tbl["dns"] = Item::Table(tbl);
        }
        EndpointUpdate::Dot(None) => {
            server_tbl.remove("dot");
        }
        EndpointUpdate::Dot(Some(cfg)) => {
            let mut tbl = Table::new();
            tbl["enabled"] = value(cfg.enabled);
            if let Some(ref addr) = cfg.addr {
                tbl["addr"] = value(addr.as_str());
            }
            if let Some(ref sn) = cfg.server_name {
                tbl["server_name"] = value(sn.as_str());
            }
            if let Some(ms) = cfg.timeout_ms {
                tbl["timeout_ms"] = value(ms as i64);
            }
            server_tbl["dot"] = Item::Table(tbl);
        }
        EndpointUpdate::Doh(None) => {
            server_tbl.remove("doh");
        }
        EndpointUpdate::Doh(Some(cfg)) => {
            let mut tbl = Table::new();
            tbl["enabled"] = value(cfg.enabled);
            if let Some(ref url) = cfg.url {
                tbl["url"] = value(url.as_str());
            }
            if let Some(ref addr) = cfg.addr {
                tbl["addr"] = value(addr.as_str());
            }
            if let Some(ref sn) = cfg.server_name {
                tbl["server_name"] = value(sn.as_str());
            }
            if let Some(ms) = cfg.timeout_ms {
                tbl["timeout_ms"] = value(ms as i64);
            }
            server_tbl["doh"] = Item::Table(tbl);
        }
        EndpointUpdate::Doq(None) => {
            server_tbl.remove("doq");
        }
        EndpointUpdate::Doq(Some(cfg)) => {
            let mut tbl = Table::new();
            tbl["enabled"] = value(cfg.enabled);
            if let Some(ref addr) = cfg.addr {
                tbl["addr"] = value(addr.as_str());
            }
            if let Some(ref sn) = cfg.server_name {
                tbl["server_name"] = value(sn.as_str());
            }
            if let Some(ms) = cfg.timeout_ms {
                tbl["timeout_ms"] = value(ms as i64);
            }
            server_tbl["doq"] = Item::Table(tbl);
        }
    }

    write_private_file(&path, &doc.to_string())?;
    Ok(path)
}

/// Append a new `[[servers]]` table to a `toml_edit::DocumentMut` without modifying any
/// existing tables or other content in the document.
///
/// The function writes a complete server table derived from `server` and either pushes it
/// onto an existing `servers` array-of-tables or creates that array if it does not exist.
///
/// # Examples
///
/// ```text
/// let mut doc = toml_edit::DocumentMut::new();
/// // `AppConfig::starter()` provides a minimal starter server suitable for examples/tests.
/// let server = crate::control_plane::config::AppConfig::starter().servers.into_iter().next().unwrap();
/// crate::control_plane::config::append_server_entry(&mut doc, &server);
/// assert!(doc.to_string().contains("[[servers]]"));
/// ```
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
        VendorKind::Pihole => "pihole",
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
    match server.token.as_ref().map(ApiToken::expose_for_auth) {
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

/// Validate a single `ip_map` entry by ensuring both endpoints are valid IPs and belong to the same IP family.
///
/// Returns an `Err(Error::config(...))` if either `src` or `dst` is not a valid IP address, or if one is IPv4 and the other is IPv6.
///
/// # Examples
///
/// ```text
/// # use std::net::IpAddr;
/// # fn validate_ip_pair_for_job(_job_id: &str, _src: &str, _dst: &str) -> Result<(), ()> { Ok(()) }
/// // Basic usage: IPv4 pair is accepted
/// let res = validate_ip_pair_for_job("job1", "192.0.2.1", "198.51.100.2");
/// assert!(res.is_ok());
/// ```
fn validate_ip_pair_for_job(job_id: &str, src: &str, dst: &str) -> Result<()> {
    let source: IpAddr = src
        .parse()
        .map_err(|_| Error::config(format!("job '{job_id}': '{src}' is not a valid IP address")))?;
    let dest: IpAddr = dst
        .parse()
        .map_err(|_| Error::config(format!("job '{job_id}': '{dst}' is not a valid IP address")))?;
    if source.is_ipv4() != dest.is_ipv4() {
        return Err(Error::config(format!(
            "job '{job_id}': IP mapping '{src}' = '{dst}' mixes IPv4 and IPv6"
        )));
    }
    Ok(())
}

/// Validate job definitions and their references.
///
/// Performs semantic checks on each `JobConfig`:
/// - each job must have a non-empty, unique id (case-insensitive);
/// - exactly one of `schedule` or `interval` must be present (whitespace-only counts as absent);
/// - for `RecordSync` and `ZoneSync` jobs, `from` and `to` must be present, refer to known servers,
///   and must not be the same server (comparison is case-insensitive);
/// - for `ZoneExport` jobs, `output_dir` must be present and non-empty;
/// - every entry in `ip_map` must parse as an IP address and use a consistent IP family per pair;
/// - every `ignore` pattern must compile as a valid regular expression.
///
/// `server_ids` should contain the set of known server ids (lowercased) used to validate `from`/`to`.
///
/// # Errors
///
/// Returns an `Err(Error::config(...))` describing the first validation failure encountered.
///
/// # Examples
///
/// ```text
/// use std::collections::HashSet;
///
/// // empty job list is valid
/// let jobs: Vec<crate::control_plane::config::JobConfig> = Vec::new();
/// let server_ids: HashSet<String> = HashSet::new();
/// assert!(crate::control_plane::config::validate_jobs(&jobs, &server_ids).is_ok());
/// ```
fn validate_jobs(jobs: &[JobConfig], server_ids: &HashSet<String>) -> Result<()> {
    let mut job_ids: HashSet<String> = HashSet::new();
    for job in jobs {
        if job.id.trim().is_empty() {
            return Err(Error::config("config contains a job with an empty id"));
        }
        if !job_ids.insert(job.id.to_lowercase()) {
            return Err(Error::config(format!(
                "config contains duplicate job id '{}'",
                job.id
            )));
        }

        // Exactly one of schedule / interval (whitespace-only strings count as absent).
        let has_schedule = job
            .schedule
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        let has_interval = job
            .interval
            .as_deref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        match (has_schedule, has_interval) {
            (true, true) => {
                return Err(Error::config(format!(
                    "job '{}' specifies both 'schedule' and 'interval'; use only one",
                    job.id
                )));
            }
            (false, false) => {
                return Err(Error::config(format!(
                    "job '{}' must specify either 'schedule' or 'interval'",
                    job.id
                )));
            }
            _ => {}
        }

        match job.kind {
            JobKind::RecordSync | JobKind::ZoneSync => {
                let from = job.from.as_deref().unwrap_or("").trim();
                let to = job.to.as_deref().unwrap_or("").trim();

                if from.is_empty() {
                    return Err(Error::config(format!(
                        "job '{}' of kind {:?} requires 'from'",
                        job.id, job.kind
                    )));
                }
                if to.is_empty() {
                    return Err(Error::config(format!(
                        "job '{}' of kind {:?} requires 'to'",
                        job.id, job.kind
                    )));
                }
                if !server_ids.contains(&from.to_lowercase()) {
                    return Err(Error::config(format!(
                        "job '{}' references unknown source server '{from}'",
                        job.id
                    )));
                }
                if !server_ids.contains(&to.to_lowercase()) {
                    return Err(Error::config(format!(
                        "job '{}' references unknown destination server '{to}'",
                        job.id
                    )));
                }
                if from.to_lowercase() == to.to_lowercase() {
                    return Err(Error::config(format!(
                        "job '{}' has identical source and destination server '{from}'",
                        job.id
                    )));
                }
            }
            JobKind::ZoneExport => {
                if job
                    .output_dir
                    .as_deref()
                    .is_none_or(|s| s.trim().is_empty())
                {
                    return Err(Error::config(format!(
                        "job '{}' of kind zone_export requires 'output_dir'",
                        job.id
                    )));
                }
            }
        }

        for (src, dst) in &job.ip_map {
            validate_ip_pair_for_job(&job.id, src, dst)?;
        }

        for pattern in &job.ignore {
            Regex::new(pattern).map_err(|e| {
                Error::config(format!(
                    "job '{}': ignore pattern '{pattern}' is not valid regex: {e}",
                    job.id
                ))
            })?;
        }
    }
    Ok(())
}

/// Append a `[daemon]` table containing daemon runtime settings to the given TOML document.
///
/// The table will include `state_db` (if present), `heartbeat_interval`, `heartbeat_timeout`,
/// `shutdown_timeout`, `worker_threads`, and `critical_failure_threshold`.
///
/// # Examples
///
/// ```text
/// use toml_edit::Document;
/// use std::str::FromStr;
/// // Construct a DaemonConfig by deserializing a small TOML snippet.
/// let daemon: DaemonConfig = toml::from_str(r#"
/// state_db = "/tmp/state.db"
/// heartbeat_interval = "5s"
/// heartbeat_timeout = "20s"
/// shutdown_timeout = "5s"
/// worker_threads = 4
/// critical_failure_threshold = 5
/// "#).unwrap();
///
/// let mut doc = Document::new();
/// append_daemon_entry(&mut doc, &daemon);
/// assert!(doc.to_string().contains("[daemon]"));
/// ```
fn append_daemon_entry(doc: &mut toml_edit::DocumentMut, daemon: &DaemonConfig) {
    use toml_edit::{Item, Table, value};

    let mut tbl = Table::new();
    tbl.decor_mut().set_prefix("\n");

    if let Some(ref p) = daemon.state_db {
        tbl["state_db"] = value(p.to_string_lossy().as_ref());
    }
    tbl["heartbeat_interval"] = value(daemon.heartbeat_interval.as_str());
    tbl["heartbeat_timeout"] = value(daemon.heartbeat_timeout.as_str());
    tbl["shutdown_timeout"] = value(daemon.shutdown_timeout.as_str());
    tbl["worker_threads"] = value(daemon.worker_threads as i64);
    tbl["critical_failure_threshold"] = value(daemon.critical_failure_threshold as i64);

    doc["daemon"] = Item::Table(tbl);
}

/// Append a `[[jobs]]` entry to a toml_edit document.
fn append_job_entry(doc: &mut toml_edit::DocumentMut, job: &JobConfig) {
    use toml_edit::{Array, ArrayOfTables, Item, Table, value};

    let mut tbl = Table::new();
    tbl.decor_mut().set_prefix("\n");

    tbl["id"] = value(job.id.as_str());
    tbl["kind"] = value(match job.kind {
        JobKind::RecordSync => "record_sync",
        JobKind::ZoneSync => "zone_sync",
        JobKind::ZoneExport => "zone_export",
    });
    tbl["enabled"] = value(job.enabled);
    tbl["critical"] = value(job.critical);

    if let Some(ref s) = job.schedule {
        tbl["schedule"] = value(s.as_str());
    }
    if let Some(ref i) = job.interval {
        tbl["interval"] = value(i.as_str());
    }
    if let Some(ref tz) = job.timezone {
        tbl["timezone"] = value(tz.as_str());
    }
    tbl["run_immediately"] = value(job.run_immediately);
    if let Some(ref j) = job.jitter {
        tbl["jitter"] = value(j.as_str());
    }
    tbl["dry_run"] = value(job.dry_run);

    if let Some(ref f) = job.from {
        tbl["from"] = value(f.as_str());
    }
    if let Some(ref t) = job.to {
        tbl["to"] = value(t.as_str());
    }
    if !job.zones.is_empty() {
        let mut zones = Array::new();
        for z in &job.zones {
            zones.push(z.as_str());
        }
        tbl["zones"] = value(zones);
    }
    if !job.ip_map.is_empty() {
        let mut map_tbl = Table::new();
        for (src, dst) in &job.ip_map {
            map_tbl[src.as_str()] = value(dst.as_str());
        }
        tbl["ip_map"] = Item::Table(map_tbl);
    }
    tbl["create_missing"] = value(job.create_missing);
    tbl["overwrite_existing"] = value(job.overwrite_existing);
    tbl["delete_destination_only"] = value(job.delete_destination_only);
    if !job.ignore.is_empty() {
        let mut ignore = Array::new();
        for p in &job.ignore {
            ignore.push(p.as_str());
        }
        tbl["ignore"] = value(ignore);
    }
    if let Some(ref out) = job.output_dir {
        tbl["output_dir"] = value(out.as_str());
    }

    match doc.entry("jobs") {
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

/// Write the starter application configuration to `path`, creating parent directories as needed.

///

/// If a config file already exists at `path` this returns an error unless `force` is `true`,

/// in which case the file is overwritten. The function ensures the configuration directory

/// is present (with restrictive permissions on supported platforms) and writes the default

/// TOML contents using secure file permissions.

///

/// # Errors

///

/// Returns an `Error::config` if the file exists and `force` is `false`. Other I/O or

/// serialization errors are returned as appropriate.

///

/// # Examples

///

/// ```text

/// use std::path::Path;

/// # fn try_example() -> Result<(), Box<dyn std::error::Error>> {

/// let path = Path::new("/tmp/dnsync_config.toml");

/// // Write default config, overwriting if it already exists

/// crate::control_plane::config::write_default_config(path, true)?;

/// # Ok(()) }

/// ```

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
            VendorKind::Pihole => "pihole",
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

    #[test]
    fn parses_per_server_mcp_permissions() {
        let config = config();
        let home = config.selected_server(Some("home")).unwrap();

        assert_eq!(home.id, "home");
        assert_eq!(home.vendor, VendorKind::Technitium);
        assert_eq!(home.base_url.as_deref(), Some("http://home.local:5380"));
        assert_eq!(home.mcp.access, vec![PolicyRule::Read]);
        assert_eq!(home.mcp.allowed_zones, ["example.com", "internal.lan"]);
        assert!(home.mcp.show_settings_secrets);

        let lab = config.selected_server(Some("lab")).unwrap();
        assert!(!lab.mcp.show_settings_secrets);
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
        assert_eq!(
            server.token.as_ref().map(ApiToken::expose_for_auth),
            Some("[redacted]")
        );
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
    fn cloudflare_external_server_gets_provider_transport_defaults() {
        let cfg: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "cf"
                vendor = "cloudflare"
                token_env = "DNSYNC_CLOUDFLARE_API_TOKEN"
            "#,
        )
        .unwrap();

        cfg.validate().unwrap();
        let server = cfg.selected_server(None).unwrap();

        assert_eq!(
            server.dns.as_ref().unwrap().addr.as_deref(),
            Some("1.1.1.1:53")
        );
        assert_eq!(
            server.dot.as_ref().unwrap().server_name.as_deref(),
            Some("cloudflare-dns.com")
        );
        let doh = server.doh.as_ref().unwrap();
        assert_eq!(
            doh.url.as_deref(),
            Some("https://cloudflare-dns.com/dns-query")
        );
        assert_eq!(doh.addr.as_deref(), Some("1.1.1.1:443"));
        assert_eq!(
            server.doq.as_ref().unwrap().server_name.as_deref(),
            Some("cloudflare-dns.com")
        );
    }

    #[test]
    fn cloudflare_transport_blocks_override_provider_defaults() {
        let cfg: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "cf"
                vendor = "cloudflare"
                token_env = "DNSYNC_CLOUDFLARE_API_TOKEN"

                [servers.dns]
                enabled = false

                [servers.doh]
                enabled = true
                url = "https://security.cloudflare-dns.com/dns-query"
                addr = "1.1.1.2:443"
                server_name = "security.cloudflare-dns.com"
                timeout_ms = 2500
            "#,
        )
        .unwrap();

        cfg.validate().unwrap();
        let server = cfg.selected_server(None).unwrap();

        let dns = server.dns.as_ref().unwrap();
        assert!(!dns.enabled);
        assert_eq!(dns.addr, None);

        let doh = server.doh.as_ref().unwrap();
        assert_eq!(
            doh.url.as_deref(),
            Some("https://security.cloudflare-dns.com/dns-query")
        );
        assert_eq!(doh.addr.as_deref(), Some("1.1.1.2:443"));
        assert_eq!(
            doh.server_name.as_deref(),
            Some("security.cloudflare-dns.com")
        );
        assert_eq!(doh.timeout_ms, Some(2500));

        assert_eq!(
            server.dot.as_ref().unwrap().addr.as_deref(),
            Some("1.1.1.1:853")
        );
        assert_eq!(
            server.doq.as_ref().unwrap().addr.as_deref(),
            Some("1.1.1.1:853")
        );
    }

    #[test]
    fn cloudflare_local_server_does_not_get_provider_transport_defaults() {
        let cfg: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "cf-local"
                vendor = "cloudflare"
                location = "local"
                token_env = "DNSYNC_CLOUDFLARE_API_TOKEN"
            "#,
        )
        .unwrap();

        cfg.validate().unwrap();
        let server = cfg.selected_server(None).unwrap();

        assert!(server.dns.is_none());
        assert!(server.dot.is_none());
        assert!(server.doh.is_none());
        assert!(server.doq.is_none());
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

        assert_eq!(
            server.token.as_ref().map(ApiToken::expose_for_auth),
            Some("[redacted]")
        );
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

    /// Regression guard for the token leak via instrumentation: a populated
    /// config must never reveal the token through `Debug` (used by `?value`
    /// tracing fields / `#[instrument]`) or through serde serialisation, while
    /// the real value is still reachable for authentication.
    #[test]
    fn config_never_leaks_token_via_debug_or_serialize() {
        const SECRET: &str = "super-secret-token-value";
        let config = AppConfig {
            servers: vec![DnsServerConfig {
                id: "leaky".to_string(),
                vendor: VendorKind::Technitium,
                location: None,
                base_url: Some("http://192.168.1.10:5380".to_string()),
                base_url_env: None,
                token: Some(ApiToken::new(SECRET)),
                token_env: None,
                org_id: None,
                cluster: None,
                dns: None,
                dot: None,
                doh: None,
                doq: None,
                mcp: McpPermissions::default(),
                validation_endpoints: Vec::new(),
            }],
            ..AppConfig::default()
        };

        let debug = format!("{config:?}");
        assert!(!debug.contains(SECRET), "Debug leaked token: {debug}");
        assert!(debug.contains("ApiToken([REDACTED])"));

        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains(SECRET), "Serialize leaked token: {json}");

        // The real value is still available at the auth boundary.
        let token = config.servers[0].token.as_ref().unwrap();
        assert_eq!(token.expose_for_auth(), SECRET);
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
    fn update_defaults_adds_missing_values_without_overwriting_existing_ones() {
        let path = temp_config_path("update-defaults");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = concat!(
            "# Existing config\n",
            "[[servers]]\n",
            "id = \"cf\"\n",
            "vendor = \"cloudflare\"\n",
            "token_env = \"CF_TOKEN\"\n",
            "\n",
            "[servers.dns]\n",
            "enabled = false\n",
            "\n",
            "[[servers]]\n",
            "id = \"home\"\n",
            "base_url_env = \"HOME_URL\"\n",
            "token_env = \"HOME_TOKEN\"\n",
        );
        write_private_file(&path, original).unwrap();

        let report = update_defaults(Some(path.clone())).unwrap();

        assert_eq!(report.updated_servers, 2);
        assert!(report.added_values >= 1);

        let updated = std::fs::read_to_string(&path).unwrap();
        assert!(updated.contains("# Existing config"));
        assert!(updated.contains("base_url = \"https://api.cloudflare.com/client/v4\""));
        assert!(updated.contains("[servers.dot]"));
        assert!(updated.contains("server_name = \"cloudflare-dns.com\""));
        assert!(updated.contains("[servers.doh]"));
        assert!(updated.contains("[servers.doq]"));
        assert!(updated.contains("base_url_env = \"HOME_URL\""));
        assert!(!updated.contains("base_url = \"http://localhost:5380\""));

        let parsed = AppConfig::load(Some(path.clone())).unwrap().unwrap();
        let cf = parsed.selected_server(Some("cf")).unwrap();
        assert_eq!(cf.dns.as_ref().unwrap().enabled, false);
        assert_eq!(cf.dns.as_ref().unwrap().addr, None);

        let second = update_defaults(Some(path.clone())).unwrap();
        assert_eq!(second.updated_servers, 0);
        assert_eq!(second.added_values, 0);

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

    /// Verifies that a server's explicit `location` value is preserved when parsing from TOML.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let toml = r#"
    ///     [[servers]]
    ///     id = "home"
    ///     vendor = "technitium"
    ///     location = "external"
    ///     token = "tok"
    /// "#;
    /// let config: AppConfig = toml::from_str(toml).expect("should parse");
    /// let server = config.selected_server(None).unwrap();
    /// assert_eq!(server.location, Some(ServerLocation::External));
    /// ```
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

    /// Verifies that a minimal `record_sync` job deserializes from TOML and passes validation.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let toml = r#"
    /// [[servers]]
    /// id = "cf"
    /// token = "tok"
    ///
    /// [[servers]]
    /// id = "home"
    /// token = "tok"
    ///
    /// [[jobs]]
    /// id = "sync-cf-home"
    /// kind = "record_sync"
    /// interval = "5m"
    /// from = "cf"
    /// to = "home"
    /// "#;
    /// let config: AppConfig = toml::from_str(toml).expect("should parse");
    /// config.validate().expect("should validate");
    /// assert_eq!(config.jobs.len(), 1);
    /// let job = &config.jobs[0];
    /// assert_eq!(job.kind, JobKind::RecordSync);
    /// ```
    #[test]
    fn parses_minimal_record_sync_job() {
        let toml = concat!(
            r#"
            [[servers]]
            id = "cf"
            token = "tok"

            [[servers]]
            id = "home"
            token = "tok"

            [[jobs]]
            id = "sync-cf-home"
            kind = "record_sync"
            interval = "5m"
            from = "cf"
            to = "home"
            "#
        );
        let config: AppConfig = toml::from_str(toml).expect("should parse");
        config.validate().expect("should validate");
        assert_eq!(config.jobs.len(), 1);
        let job = &config.jobs[0];
        assert_eq!(job.id, "sync-cf-home");
        assert_eq!(job.kind, JobKind::RecordSync);
        assert_eq!(job.interval.as_deref(), Some("5m"));
        assert_eq!(job.from.as_deref(), Some("cf"));
        assert_eq!(job.to.as_deref(), Some("home"));
        assert!(job.enabled);
        assert!(!job.critical);
    }

    #[test]
    fn parses_full_record_sync_job_with_all_fields() {
        let toml = concat!(
            r#"
            [[servers]]
            id = "src"
            token = "tok"

            [[servers]]
            id = "dst"
            token = "tok"

            [[jobs]]
            id = "full-job"
            kind = "record_sync"
            enabled = true
            critical = true
            schedule = "*/5 * * * *"
            timezone = "America/New_York"
            run_immediately = true
            jitter = "30s"
            dry_run = true
            from = "src"
            to = "dst"
            zones = ["example.com", "internal.lan"]
            create_missing = false
            overwrite_existing = false
            delete_destination_only = true
            ignore = ["^_dmarc\\."]

            [jobs.ip_map]
            "203.0.113.10" = "192.168.1.10"
            "#
        );
        let config: AppConfig = toml::from_str(toml).expect("should parse");
        config.validate().expect("should validate");
        let job = &config.jobs[0];
        assert_eq!(job.id, "full-job");
        assert!(job.critical);
        assert_eq!(job.schedule.as_deref(), Some("*/5 * * * *"));
        assert_eq!(job.timezone.as_deref(), Some("America/New_York"));
        assert!(job.run_immediately);
        assert_eq!(job.jitter.as_deref(), Some("30s"));
        assert!(job.dry_run);
        assert_eq!(job.zones, ["example.com", "internal.lan"]);
        assert!(!job.create_missing);
        assert!(!job.overwrite_existing);
        assert!(job.delete_destination_only);
        assert_eq!(job.ignore, ["^_dmarc\\."]);
        assert_eq!(
            job.ip_map.get("203.0.113.10").map(String::as_str),
            Some("192.168.1.10")
        );
    }

    #[test]
    fn parses_zone_sync_job() {
        let toml = concat!(
            r#"
            [[servers]]
            id = "primary"
            token = "tok"

            [[servers]]
            id = "secondary"
            token = "tok"

            [[jobs]]
            id = "zone-sync"
            kind = "zone_sync"
            interval = "1h"
            from = "primary"
            to = "secondary"
            zones = ["example.com"]
            "#
        );
        let config: AppConfig = toml::from_str(toml).expect("should parse");
        config.validate().expect("should validate");
        let job = &config.jobs[0];
        assert_eq!(job.kind, JobKind::ZoneSync);
    }

    #[test]
    fn parses_zone_export_job() {
        let toml = concat!(
            r#"
            [[servers]]
            id = "primary"
            token = "tok"

            [[jobs]]
            id = "zone-export"
            kind = "zone_export"
            interval = "1d"
            output_dir = "/tmp/zones"
            "#
        );
        let config: AppConfig = toml::from_str(toml).expect("should parse");
        config.validate().expect("should validate");
        let job = &config.jobs[0];
        assert_eq!(job.kind, JobKind::ZoneExport);
        assert_eq!(job.output_dir.as_deref(), Some("/tmp/zones"));
    }

    #[test]
    fn parses_daemon_config() {
        let toml = concat!(
            r#"
            [[servers]]
            id = "home"
            token = "tok"

            [daemon]
            state_db = "/var/lib/dnsync/state.db"
            heartbeat_interval = "10s"
            worker_threads = 8
            critical_failure_threshold = 3
            "#
        );
        let config: AppConfig = toml::from_str(toml).expect("should parse");
        config.validate().expect("should validate");
        let daemon = config.daemon.as_ref().expect("daemon should be present");
        assert_eq!(
            daemon
                .state_db
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .as_deref(),
            Some("/var/lib/dnsync/state.db")
        );
        assert_eq!(daemon.heartbeat_interval, "10s");
        assert_eq!(daemon.worker_threads, 8);
        assert_eq!(daemon.critical_failure_threshold, 3);
        // defaults
        assert_eq!(daemon.heartbeat_timeout, "20s");
        assert_eq!(daemon.shutdown_timeout, "5s");
    }

    #[test]
    fn rejects_duplicate_job_ids() {
        let toml = concat!(
            r#"
            [[servers]]
            id = "cf"
            token = "tok"

            [[servers]]
            id = "home"
            token = "tok"

            [[jobs]]
            id = "sync"
            kind = "record_sync"
            interval = "5m"
            from = "cf"
            to = "home"

            [[jobs]]
            id = "SYNC"
            kind = "record_sync"
            interval = "5m"
            from = "home"
            to = "cf"
            "#
        );
        let config: AppConfig = toml::from_str(toml).expect("should parse");
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate job id"));
    }

    #[test]
    fn rejects_job_with_both_schedule_and_interval() {
        let toml = concat!(
            r#"
            [[servers]]
            id = "cf"
            token = "tok"

            [[servers]]
            id = "home"
            token = "tok"

            [[jobs]]
            id = "both"
            kind = "record_sync"
            schedule = "*/5 * * * *"
            interval = "5m"
            from = "cf"
            to = "home"
            "#
        );
        let config: AppConfig = toml::from_str(toml).expect("should parse");
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("both 'schedule' and 'interval'"));
    }

    #[test]
    fn rejects_job_with_neither_schedule_nor_interval() {
        let toml = concat!(
            r#"
            [[servers]]
            id = "cf"
            token = "tok"

            [[servers]]
            id = "home"
            token = "tok"

            [[jobs]]
            id = "neither"
            kind = "record_sync"
            from = "cf"
            to = "home"
            "#
        );
        let config: AppConfig = toml::from_str(toml).expect("should parse");
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("either 'schedule' or 'interval'"));
    }

    #[test]
    fn rejects_record_sync_job_missing_from() {
        let toml = concat!(
            r#"
            [[servers]]
            id = "home"
            token = "tok"

            [[jobs]]
            id = "no-from"
            kind = "record_sync"
            interval = "5m"
            to = "home"
            "#
        );
        let config: AppConfig = toml::from_str(toml).expect("should parse");
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("requires 'from'"));
    }

    #[test]
    fn rejects_record_sync_job_missing_to() {
        let toml = concat!(
            r#"
            [[servers]]
            id = "home"
            token = "tok"

            [[jobs]]
            id = "no-to"
            kind = "record_sync"
            interval = "5m"
            from = "home"
            "#
        );
        let config: AppConfig = toml::from_str(toml).expect("should parse");
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("requires 'to'"));
    }

    #[test]
    fn rejects_record_sync_job_same_from_to() {
        let toml = concat!(
            r#"
            [[servers]]
            id = "home"
            token = "tok"

            [[jobs]]
            id = "same"
            kind = "record_sync"
            interval = "5m"
            from = "home"
            to = "home"
            "#
        );
        let config: AppConfig = toml::from_str(toml).expect("should parse");
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("identical source and destination"));
    }

    /// Verifies that a `zone_export` job without `output_dir` fails validation.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let toml = concat!(
    ///     r#"
    ///     [[servers]]
    ///     id = "home"
    ///     token = "tok"
    ///
    ///     [[jobs]]
    ///     id = "no-output"
    ///     kind = "zone_export"
    ///     interval = "1d"
    ///     "#
    /// );
    /// let config: AppConfig = toml::from_str(toml).expect("should parse");
    /// let err = config.validate().unwrap_err();
    /// assert!(err.to_string().contains("requires 'output_dir'"));
    /// ```
    #[test]
    fn rejects_zone_export_job_missing_output_dir() {
        let toml = concat!(
            r#"
            [[servers]]
            id = "home"
            token = "tok"

            [[jobs]]
            id = "no-output"
            kind = "zone_export"
            interval = "1d"
            "#
        );
        let config: AppConfig = toml::from_str(toml).expect("should parse");
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("requires 'output_dir'"));
    }

    #[test]
    fn rejects_invalid_ip_map_entry_in_job() {
        let toml = concat!(
            r#"
            [[servers]]
            id = "cf"
            token = "tok"

            [[servers]]
            id = "home"
            token = "tok"

            [[jobs]]
            id = "bad-ip"
            kind = "record_sync"
            interval = "5m"
            from = "cf"
            to = "home"

            [jobs.ip_map]
            "203.0.113.10" = "fd00::1"
            "#
        );
        let config: AppConfig = toml::from_str(toml).expect("should parse");
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("IPv4 and IPv6"));
    }
    #[test]
    fn cloudflare_inferred_local_server_does_not_get_provider_transport_defaults() {
        let cfg: AppConfig = toml::from_str(
            r#"
              [[servers]]
              id = "cf-localhost"
              vendor = "cloudflare"
              base_url = "http://localhost:5380"
              token_env = "TOKEN"
          "#,
        )
        .unwrap();

        let server = cfg.selected_server(None).unwrap();
        assert!(server.dns.is_none());
        assert!(server.dot.is_none());
        assert!(server.doh.is_none());
        assert!(server.doq.is_none());
    }
}
