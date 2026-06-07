//! Configuration schema: vendor/transport/cluster/validation/daemon/job types.

use super::*;

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
pub(crate) fn default_heartbeat_interval() -> String {
    "5s".to_string()
}
/// Default heartbeat timeout value as a string.
///
/// # Examples
///
/// ```text
/// assert_eq!(default_heartbeat_timeout(), "20s");
/// ```
pub(crate) fn default_heartbeat_timeout() -> String {
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
pub(crate) fn default_shutdown_timeout() -> String {
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
pub(crate) fn default_worker_threads() -> usize {
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
pub(crate) fn default_critical_threshold() -> u32 {
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
    /// Ownership pruning: remove records this job previously created on the
    /// destination once they disappear from the source. Unlike
    /// `delete_destination_only` (a blunt mirror that deletes any unmatched
    /// destination record), this only ever removes records the job itself
    /// synced, tracked in the state DB. Off by default.
    #[serde(default)]
    pub prune_synced: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore: Vec<String>,
    // ZoneExport-only fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_dir: Option<String>,
}
