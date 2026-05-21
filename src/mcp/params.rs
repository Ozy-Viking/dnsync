//! MCP parameter DTOs — all tool parameter structs and enums.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::core::dns::records::RecordData;

// ─── Zone params ───────────────────────────────────────────────────────────

#[derive(Deserialize, JsonSchema)]
pub struct ZoneParams {
    /// The zone name, e.g. "example.com"
    pub zone: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct ListZonesParams {
    /// Page number for pagination (default: 1)
    pub page_number: Option<u32>,
    /// Zones per page (default: 50)
    pub zones_per_page: Option<u32>,
}

#[derive(Deserialize, JsonSchema)]
pub struct CreateZoneParams {
    /// Zone name, e.g. "example.com"
    pub zone: String,
    /// Zone type: Primary, Secondary, Stub, Forwarder
    pub zone_type: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct ExportZoneFileParams {
    /// Zone name to export, e.g. "example.com"
    pub zone: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct ImportZoneFileParams {
    /// Zone name the file will be imported into (must already exist)
    pub zone: String,
    /// Full RFC 1035 zone file content as a string
    pub content: String,
    /// Filename shown in API logs (default: zone.txt)
    pub file_name: Option<String>,
    /// Overwrite existing record sets for imported types (default: true)
    pub overwrite: Option<bool>,
    /// Delete all existing records before importing \u2014 clean replace (default: false)
    pub overwrite_zone: Option<bool>,
    /// Use the SOA serial from the file instead of auto-incrementing (default: false)
    pub overwrite_soa_serial: Option<bool>,
}

// ─── Record params ─────────────────────────────────────────────────────────

#[derive(Deserialize, JsonSchema)]
pub struct ListRecordsParams {
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
    pub zone: String,
    pub domain: String,
    /// Which record(s) to delete. Only the `type` field is required.
    /// Omitting value fields deletes ALL records of that type for the domain.
    /// e.g. {"type":"A"} deletes all A records; {"type":"A","ipAddress":"1.2.3.4"} deletes one.
    pub record: RecordDeleteData,
}

/// Typed record selector for deletion. All value fields are optional.
#[derive(Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "UPPERCASE")]
pub enum RecordDeleteData {
    A { #[serde(rename = "ipAddress")] ip: Option<std::net::Ipv4Addr> },
    Aaaa { #[serde(rename = "ipAddress")] ip: Option<std::net::Ipv6Addr> },
    Aname { aname: Option<String> },
    App { #[serde(rename = "appName")] app_name: Option<String> },
    Caa { value: Option<String> },
    Cname { #[serde(rename = "cname")] target: Option<String> },
    Dname { dname: Option<String> },
    Ds { #[serde(rename = "keyTag")] key_tag: Option<u16> },
    Fwd { forwarder: Option<String> },
    Https { #[serde(rename = "svcTargetName")] svc_target_name: Option<String> },
    Mx { exchange: Option<String> },
    Naptr { #[serde(rename = "naptrReplacement")] replacement: Option<String> },
    Ns { #[serde(rename = "nameServer")] nameserver: Option<String> },
    Ptr { #[serde(rename = "ptrName")] name: Option<String> },
    Sshfp { #[serde(rename = "sshfpFingerprint")] fingerprint: Option<String> },
    Srv { target: Option<String>, port: Option<u16>, priority: Option<u16>, weight: Option<u16> },
    Svcb { #[serde(rename = "svcTargetName")] svc_target_name: Option<String> },
    Tlsa { #[serde(rename = "tlsaCertificateAssociationData")] cert_association_data: Option<String> },
    Txt { text: Option<String> },
    Uri { uri: Option<String> },
    Unknown { rdata: Option<String> },
}

impl RecordDeleteData {
    pub fn to_api_params(&self) -> Vec<(&'static str, String)> {
        let type_name = match self {
            Self::A { .. } => "A",
            Self::Aaaa { .. } => "AAAA",
            Self::Aname { .. } => "ANAME",
            Self::App { .. } => "APP",
            Self::Caa { .. } => "CAA",
            Self::Cname { .. } => "CNAME",
            Self::Dname { .. } => "DNAME",
            Self::Ds { .. } => "DS",
            Self::Fwd { .. } => "FWD",
            Self::Https { .. } => "HTTPS",
            Self::Mx { .. } => "MX",
            Self::Naptr { .. } => "NAPTR",
            Self::Ns { .. } => "NS",
            Self::Ptr { .. } => "PTR",
            Self::Sshfp { .. } => "SSHFP",
            Self::Srv { .. } => "SRV",
            Self::Svcb { .. } => "SVCB",
            Self::Tlsa { .. } => "TLSA",
            Self::Txt { .. } => "TXT",
            Self::Uri { .. } => "URI",
            Self::Unknown { .. } => "UNKNOWN",
        };
        let mut p = vec![("type", type_name.into())];
        match self {
            Self::A { ip } => { if let Some(v) = ip { p.push(("ipAddress", v.to_string())); } }
            Self::Aaaa { ip } => { if let Some(v) = ip { p.push(("ipAddress", v.to_string())); } }
            Self::Aname { aname } => { if let Some(v) = aname { p.push(("aname", v.clone())); } }
            Self::App { app_name } => { if let Some(v) = app_name { p.push(("appName", v.clone())); } }
            Self::Caa { value } => { if let Some(v) = value { p.push(("value", v.clone())); } }
            Self::Cname { target } => { if let Some(v) = target { p.push(("cname", v.clone())); } }
            Self::Dname { dname } => { if let Some(v) = dname { p.push(("dname", v.clone())); } }
            Self::Ds { key_tag } => { if let Some(v) = key_tag { p.push(("keyTag", v.to_string())); } }
            Self::Fwd { forwarder } => { if let Some(v) = forwarder { p.push(("forwarder", v.clone())); } }
            Self::Https { svc_target_name } | Self::Svcb { svc_target_name } => { if let Some(v) = svc_target_name { p.push(("svcTargetName", v.clone())); } }
            Self::Mx { exchange } => { if let Some(v) = exchange { p.push(("exchange", v.clone())); } }
            Self::Naptr { replacement } => { if let Some(v) = replacement { p.push(("naptrReplacement", v.clone())); } }
            Self::Ns { nameserver } => { if let Some(v) = nameserver { p.push(("nameServer", v.clone())); } }
            Self::Ptr { name } => { if let Some(v) = name { p.push(("ptrName", v.clone())); } }
            Self::Sshfp { fingerprint } => { if let Some(v) = fingerprint { p.push(("sshfpFingerprint", v.clone())); } }
            Self::Srv { target, port, priority, weight } => {
                if let Some(v) = target { p.push(("target", v.clone())); }
                if let Some(v) = port { p.push(("port", v.to_string())); }
                if let Some(v) = priority { p.push(("priority", v.to_string())); }
                if let Some(v) = weight { p.push(("weight", v.to_string())); }
            }
            Self::Tlsa { cert_association_data } => { if let Some(v) = cert_association_data { p.push(("tlsaCertificateAssociationData", v.clone())); } }
            Self::Txt { text } => { if let Some(v) = text { p.push(("text", v.clone())); } }
            Self::Uri { uri } => { if let Some(v) = uri { p.push(("uri", v.clone())); } }
            Self::Unknown { rdata } => { if let Some(v) = rdata { p.push(("rdata", v.clone())); } }
        }
        p
    }
}

#[derive(Deserialize, JsonSchema)]
pub struct DomainParams {
    pub domain: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct StatsParams {
    /// LastHour, LastDay, LastWeek, LastMonth, LastYear (default: LastDay)
    pub stats_type: Option<String>,
}
