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

// ─── Settings write params ─────────────────────────────────────────────────

#[derive(Deserialize, JsonSchema)]
pub struct SetSettingsParams {
    /// The DNS server ID to run this command against (see dns_list_servers)
    pub server_id: String,
    /// Partial or full settings as a JSON object — only provided keys are changed (Technitium only)
    pub settings: serde_json::Value,
}

// ─── Zone options params ───────────────────────────────────────────────────

#[derive(Deserialize, JsonSchema)]
pub struct SetZoneOptionsParams {
    /// The DNS server ID to run this command against (see dns_list_servers)
    pub server_id: String,
    /// Zone name, e.g. "example.com"
    pub zone: String,
    /// Zone options as a JSON object — keys map to Technitium zone option names (Technitium only)
    pub options: serde_json::Value,
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
            lines: value.lines,
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
/// server pick the first enabled block (precedence: dns → dot → doh →
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
    /// For multiple servers (or a cluster), use `server_ids`.
    #[serde(default)]
    pub server_id: Option<String>,

    /// Configured `[[servers]]` entries and/or cluster ids to query,
    /// repeatable. Cluster ids expand to their members. Takes precedence
    /// over `server_id` when both are set. Mutually exclusive with `at`.
    #[serde(default)]
    pub server_ids: Option<Vec<String>>,

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

    /// Follow CNAME/DNAME chains to their terminal address records. With
    /// a specific `types` filter (e.g. just `CNAME`) this is what
    /// surfaces the chain's terminal A/AAAA; otherwise off.
    #[serde(default)]
    pub chase: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Deserialize a JSON `Value` into the requested type, panicking if deserialization fails.
    ///
    /// # Panics
    ///
    /// Panics with "params should deserialize" if `value` cannot be deserialized into `T`.
    ///
    /// # Examples
    ///
    /// ```
    /// use serde::Deserialize;
    /// use serde_json::json;
    ///
    /// #[derive(Deserialize, Debug, PartialEq)]
    /// struct S { x: i32 }
    ///
    /// let v = json!({ "x": 10 });
    /// let s: S = de(v);
    /// assert_eq!(s, S { x: 10 });
    /// ```
    fn de<T: for<'de> Deserialize<'de>>(value: serde_json::Value) -> T {
        serde_json::from_value(value).expect("params should deserialize")
    }

    /// Verifies that pagination fields are omitted when not provided in the input.
    ///
    /// Deserializes a minimal JSON object into `ListZonesParams` and asserts that
    /// `page_number` and `zones_per_page` are `None` by default.
    ///
    /// # Examples
    ///
    /// ```
    /// let p: ListZonesParams = de(json!({"server_id": "home"}));
    /// assert_eq!(p.server_id, "home");
    /// assert_eq!(p.page_number, None);
    /// assert_eq!(p.zones_per_page, None);
    /// ```
    #[test]
    fn list_zones_pagination_is_optional() {
        let p: ListZonesParams = de(json!({"server_id": "home"}));
        assert_eq!(p.server_id, "home");
        assert_eq!(p.page_number, None);
        assert_eq!(p.zones_per_page, None);
    }

    #[test]
    fn transfer_zone_overwrite_defaults() {
        // overwrite defaults to true, overwrite_zone defaults to false.
        let p: TransferZoneParams = de(json!({"zone": "example.com", "from": "a", "to": "b"}));
        assert!(p.overwrite);
        assert!(!p.overwrite_zone);

        let p: TransferZoneParams =
            de(json!({"zone": "z", "from": "a", "to": "b", "overwrite": false}));
        assert!(!p.overwrite);
    }

    #[test]
    fn import_zone_file_flattens_options_with_defaults() {
        let p: ImportZoneFileParams = de(json!({
            "server_id": "home",
            "zone": "example.com",
            "content": "$ORIGIN example.com.\n",
        }));
        assert_eq!(p.file_name, None);
        // flattened ZoneImportOptions defaults: overwrite true, others false.
        assert!(p.options.overwrite);
        assert!(!p.options.overwrite_zone);
        assert!(!p.options.overwrite_soa_serial);
    }

    #[test]
    fn import_zone_file_reads_flattened_overrides() {
        let p: ImportZoneFileParams = de(json!({
            "server_id": "home",
            "zone": "example.com",
            "content": "data",
            "file_name": "custom.txt",
            "overwrite": false,
            "overwrite_zone": true,
        }));
        assert_eq!(p.file_name.as_deref(), Some("custom.txt"));
        assert!(!p.options.overwrite);
        assert!(p.options.overwrite_zone);
    }

    #[test]
    fn list_records_accepts_camel_and_snake_local_ip_aliases() {
        let camel: ListRecordsParams = de(json!({"server_id": "home", "useLocalIp": true}));
        assert_eq!(camel.use_local_ip, Some(true));

        let snake: ListRecordsParams = de(json!({"server_id": "home", "use_local_ip": true}));
        assert_eq!(snake.use_local_ip, Some(true));

        let omitted: ListRecordsParams = de(json!({"server_id": "home"}));
        assert_eq!(omitted.use_local_ip, None);
        assert_eq!(omitted.domain, None);
    }

    #[test]
    fn add_record_parses_typed_record_payload() {
        let p: AddRecordParams = de(json!({
            "server_id": "home",
            "zone": "example.com",
            "domain": "www.example.com",
            "ttl": 300,
            "record": {"type": "A", "ipAddress": "1.2.3.4"},
        }));
        assert_eq!(p.ttl, Some(300));
        assert!(matches!(p.record, RecordData::A { .. }));
    }

    #[test]
    fn log_level_param_uses_lowercase_tags_and_maps_to_log_level() {
        let p: LogLevelParam = de(json!("warning"));
        assert!(matches!(p, LogLevelParam::Warning));
        assert!(matches!(
            LogLevel::from(LogLevelParam::Critical),
            LogLevel::Critical
        ));
    }

    #[test]
    fn logs_params_convert_into_logs_options() {
        let p: LogsParams = de(json!({
            "server_id": "home",
            "lines": 25,
            "level": "error",
        }));
        let opts: LogsOptions = p.into();
        assert_eq!(opts.lines, Some(25));
        assert!(matches!(opts.level, Some(LogLevel::Error)));
        assert_eq!(opts.start, None);
    }

    #[test]
    fn sync_params_default_to_dry_run_with_empty_collections() {
        let p: SyncParams = de(json!({}));
        assert!(!p.apply, "sync must default to dry-run");
        assert!(p.zones.is_empty());
        assert!(p.map.is_empty());
        assert_eq!(p.profile, None);
    }
}
