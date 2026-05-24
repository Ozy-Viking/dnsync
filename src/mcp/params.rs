//! MCP parameter DTOs — all tool parameter structs and enums.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::core::dns::records::{RecordData, RecordSelector};
use crate::core::dns::zones::ZoneImportOptions;

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

// ─── Record params ─────────────────────────────────────────────────────────

#[derive(Deserialize, JsonSchema)]
pub struct ListRecordsParams {
    /// The DNS server ID to run this command against (see dns_list_servers)
    pub server_id: String,
    /// Domain to list records for
    pub domain: String,
    /// Zone name (if different from domain)
    pub zone: Option<String>,
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
