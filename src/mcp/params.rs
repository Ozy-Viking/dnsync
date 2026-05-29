//! MCP parameter DTOs — all tool parameter structs and enums.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::core::dns::zones::ZoneImportOptions;
use crate::core::dns::{
    logs::{LogLevel, LogsOptions},
    records::{RecordData, RecordSelector},
};

fn default_true() -> bool {
    true
}

// ─── Shared server scope ───────────────────────────────────────────────────

#[derive(Deserialize, JsonSchema)]
pub struct ServerScopeParams {
    /// The DNS server ID to run this command against (see dns_list_servers)
    pub server_id: String,
}

// ─── Zone params ───────────────────────────────────────────────────────────

#[derive(Deserialize, JsonSchema)]
pub struct ZoneParams {
    /// The DNS server ID to run this command against (see dns_list_servers)
    pub server_id: String,
    /// The zone name, e.g. "example.com"
    pub zone: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct ListZonesParams {
    /// The DNS server ID to run this command against (see dns_list_servers)
    pub server_id: String,
    /// Page number for pagination (default: 1)
    pub page_number: Option<u32>,
    /// Zones per page (default: 50)
    pub zones_per_page: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
pub struct CreateZoneParams {
    /// The DNS server ID to run this command against (see dns_list_servers)
    pub server_id: String,
    /// Zone name, e.g. "example.com"
    pub zone: String,
    /// Zone type: Primary, Secondary, Stub, Forwarder
    pub zone_type: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct ExportZoneFileParams {
    /// The DNS server ID to run this command against (see dns_list_servers)
    pub server_id: String,
    /// Zone name to export, e.g. "example.com"
    pub zone: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct ImportZoneFileParams {
    /// The DNS server ID to run this command against (see dns_list_servers)
    pub server_id: String,
    /// Zone name the file will be imported into (must already exist)
    pub zone: String,
    /// Full RFC 1035 zone file content as a string
    pub content: String,
    /// Filename shown in API logs (default: zone.txt)
    pub file_name: Option<String>,
    #[serde(flatten)]
    pub options: ZoneImportOptions,
}

#[derive(Deserialize, JsonSchema)]
pub struct TransferZoneParams {
    /// Zone name to transfer, e.g. "example.com"
    pub zone: String,
    /// Source server ID.
    pub from: String,
    /// Destination server ID.
    pub to: String,
    /// Overwrite existing record sets in the destination for imported types (default: true)
    #[serde(default = "default_true")]
    pub overwrite: bool,
    /// Delete all existing records in the destination before importing (default: false)
    #[serde(default)]
    pub overwrite_zone: bool,
}

// ─── Record params ─────────────────────────────────────────────────────────

#[derive(Deserialize, JsonSchema)]
pub struct ListRecordsParams {
    /// The DNS server ID to run this command against (see dns_list_servers)
    pub server_id: String,
    /// Domain to list records for. Omit to list records for all hosted zones.
    #[serde(default)]
    pub domain: Option<String>,
    /// Zone name (if different from domain)
    pub zone: Option<String>,
    /// Also show records for every subdomain of the given domain
    #[serde(default)]
    pub all_subdomains: Option<bool>,
    /// Prefer a locally-resolved private IP over the provider's public A/AAAA value
    #[serde(default, rename = "useLocalIp", alias = "use_local_ip")]
    pub use_local_ip: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct AddRecordParams {
    /// The DNS server ID to run this command against (see dns_list_servers)
    pub server_id: String,
    pub zone: String,
    pub domain: String,
    /// TTL in seconds (default: 3600)
    pub ttl: Option<u32>,
    /// Typed record data, e.g. {"type":"A","ip":"1.2.3.4"} or
    /// {"type":"MX","exchange":"mail.example.com","preference":10}
    pub record: RecordData,
}

#[derive(Deserialize, JsonSchema)]
pub struct DeleteRecordParams {
    /// The DNS server ID to run this command against (see dns_list_servers)
    pub server_id: String,
    pub zone: String,
    pub domain: String,
    /// Which record(s) to delete. Only the `type` field is required.
    /// Omitting value fields deletes ALL records of that type for the domain.
    /// e.g. {"type":"A"} deletes all A records; {"type":"A","ipAddress":"1.2.3.4"} deletes one.
    pub record: RecordSelector,
}

#[derive(Deserialize, JsonSchema)]
pub struct DomainParams {
    /// The DNS server ID to run this command against (see dns_list_servers)
    pub server_id: String,
    pub domain: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct StatsParams {
    /// The DNS server ID to run this command against (see dns_list_servers)
    pub server_id: String,
    /// LastHour, LastDay, LastWeek, LastMonth, LastYear (default: LastDay)
    pub stats_type: Option<String>,
}

// ─── Logs params ──────────────────────────────────────────────────────────

#[derive(Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LogLevelParam {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

impl From<LogLevelParam> for LogLevel {
    fn from(value: LogLevelParam) -> Self {
        match value {
            LogLevelParam::Trace => LogLevel::Trace,
            LogLevelParam::Debug => LogLevel::Debug,
            LogLevelParam::Info => LogLevel::Info,
            LogLevelParam::Warning => LogLevel::Warning,
            LogLevelParam::Error => LogLevel::Error,
            LogLevelParam::Critical => LogLevel::Critical,
        }
    }
}

#[derive(Deserialize, JsonSchema)]
pub struct LogsParams {
    /// The DNS server ID to run this command against (see dns_list_servers)
    pub server_id: String,
    /// Maximum number of log lines to return. Provider default is used when omitted.
    pub lines: Option<u32>,
    /// Optional provider-specific start timestamp/filter.
    pub start: Option<String>,
    /// Optional provider-specific end timestamp/filter.
    pub end: Option<String>,
    /// Minimum log level to return.
    pub level: Option<LogLevelParam>,
}

impl From<LogsParams> for LogsOptions {
    fn from(value: LogsParams) -> Self {
        Self {
            lines: value.lines.unwrap_or_default(),
            start: value.start,
            end: value.end,
            level: value.level.map(Into::into),
        }
    }
}

// ─── Sync params ───────────────────────────────────────────────────────────

#[derive(Deserialize, JsonSchema)]
pub struct SyncParams {
    /// Named sync profile from the config file.
    #[serde(default)]
    pub profile: Option<String>,
    /// Source server ID, overriding the profile.
    #[serde(default)]
    pub from: Option<String>,
    /// Destination server ID, overriding the profile.
    #[serde(default)]
    pub to: Option<String>,
    /// Zones to sync, overriding the profile.
    #[serde(default)]
    pub zones: Vec<String>,
    /// IP rewrite entries in SRC=DST form.
    #[serde(default)]
    pub map: Vec<String>,
    /// Write the changes. False/default is dry-run.
    #[serde(default)]
    pub apply: bool,
}

// ─── Resolve params ────────────────────────────────────────────────────────

/// Parameters for `dns_resolve` — the MCP equivalent of `dns query`.
///
/// At most one of `server_id` / `at` should be set; if both are omitted
/// the host's system resolver is used. Transport selection mirrors the
/// CLI: leave `transports` empty and `all_transports` unset to let the
/// server pick the first enabled block (precedence: doh → dot → dns →
/// doq); supply a list of transports to fan out across those; or set
/// `all_transports = true` (requires `server_id`) to query every
/// enabled block.
#[derive(Deserialize, JsonSchema)]
pub struct ResolveParams {
    /// Name to resolve (FQDN).
    pub domain: String,

    /// Record types to look up (default: all supported standard types).
    /// Standard mnemonics:
    /// A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, PTR, SOA, ANY.
    #[serde(default)]
    pub types: Option<Vec<String>>,

    /// A configured [[servers]] entry to query. Matched case-
    /// insensitively against `server.id`. Mutually exclusive with `at`.
    #[serde(default)]
    pub server_id: Option<String>,

    /// Ad-hoc resolver. `host[:port]` or
    /// `scheme://host[:port][/path]` (udp/tcp/dns/tls/dot/https/doh/
    /// quic/doq). Mutually exclusive with `server_id`.
    #[serde(default)]
    pub at: Option<String>,

    /// Subset of ["dns","dot","doh","doq"] to query. Empty means
    /// "single best" (precedence pick) for `server_id`, or the
    /// scheme-implied transport for `at`. Multiple values fan out.
    #[serde(default)]
    pub transports: Option<Vec<String>>,

    /// Equivalent to specifying every transport flag. Requires
    /// `server_id`. Mutually exclusive with non-empty `transports`.
    #[serde(default)]
    pub all_transports: Option<bool>,

    /// Override port for ad-hoc targets only.
    #[serde(default)]
    pub port: Option<u16>,

    /// SNI override for ad-hoc DoT/DoH/DoQ.
    #[serde(default)]
    pub tls_server_name: Option<String>,

    /// Per-attempt timeout in milliseconds (default 5000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}
