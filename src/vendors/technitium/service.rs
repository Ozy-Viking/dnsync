//! Technitium implementations of the vendor-neutral DNS service traits.

use serde_json::Value;
use tracing::instrument;

use crate::control_plane::config::VendorKind;
use crate::core::dns::capabilities::VendorCapabilities;
use crate::core::dns::records::RecordData;
use crate::core::dns::responses::ListRecordsResponse;
use crate::core::dns::service::{
    AccessListRead, AccessListWrite, CacheRead, CacheWrite, DnsVendor, ListRecordsOptions,
    RecordWrite, SettingsRead, StatsRead, ZoneExport, ZoneImport, ZoneRead, ZoneWrite,
};
use crate::core::dns::logs::{LogLevel, LogLine, LogsOptions, LogsRead};
use crate::core::error::{Error, Result};
use crate::vendors::technitium::client::TechnitiumClient;

impl DnsVendor for TechnitiumClient {
    fn kind(&self) -> VendorKind {
        VendorKind::Technitium
    }

    fn capabilities(&self) -> VendorCapabilities {
        VendorCapabilities {
            zones: true,
            records: true,
            cache: true,
            access_lists: true,
            settings: true,
            zone_import: true,
            zone_export: true,
            logs: true,
        }
    }
}

impl ZoneRead for TechnitiumClient {
    #[instrument(skip(self), fields(vendor = "technitium", operation = "list_zones"))]
    async fn list_zones(&self, page: u32, per_page: u32) -> Result<Value> {
        self.get(
            "/api/zones/list",
            &[
                ("pageNumber", &page.to_string()),
                ("zonesPerPage", &per_page.to_string()),
            ],
        )
        .await
    }

    #[instrument(
        skip(self, options),
        fields(vendor = "technitium", operation = "list_records")
    )]
    async fn list_records(
        &self,
        domain: &str,
        zone: Option<&str>,
        options: ListRecordsOptions,
    ) -> Result<ListRecordsResponse> {
        // When fetching all subdomains we need every record in the zone, so query
        // the zone apex instead of the specific domain and let the caller filter.
        let query_domain = if options.all_subdomains {
            zone.unwrap_or(domain)
        } else {
            domain
        };
        let mut params = vec![("domain", query_domain)];
        if let Some(z) = zone {
            params.push(("zone", z));
        }
        if options.all_subdomains {
            params.push(("listZone", "true"));
        }
        let raw = self.get("/api/zones/records/get", &params).await?;
        ListRecordsResponse::from_value(&raw)
    }
}

impl ZoneWrite for TechnitiumClient {
    #[instrument(skip(self), fields(vendor = "technitium", operation = "create_zone"))]
    async fn create_zone(&self, zone: &str, zone_type: &str) -> Result<Value> {
        self.post("/api/zones/create", &[("zone", zone), ("type", zone_type)])
            .await
    }

    #[instrument(skip(self), fields(vendor = "technitium", operation = "delete_zone"))]
    async fn delete_zone(&self, zone: &str) -> Result<Value> {
        self.post("/api/zones/delete", &[("zone", zone)]).await
    }

    #[instrument(skip(self), fields(vendor = "technitium", operation = "enable_zone"))]
    async fn enable_zone(&self, zone: &str) -> Result<Value> {
        self.post("/api/zones/enable", &[("zone", zone)]).await
    }

    #[instrument(skip(self), fields(vendor = "technitium", operation = "disable_zone"))]
    async fn disable_zone(&self, zone: &str) -> Result<Value> {
        self.post("/api/zones/disable", &[("zone", zone)]).await
    }
}

impl RecordWrite for TechnitiumClient {
    #[instrument(
        skip(self, record),
        fields(vendor = "technitium", operation = "add_record")
    )]
    async fn add_record(
        &self,
        zone: &str,
        domain: &str,
        ttl: u32,
        record: &RecordData,
    ) -> Result<Value> {
        let ttl_s = ttl.to_string();
        let type_params = record.to_api_params();

        let mut form: Vec<(&str, &str)> = vec![("zone", zone), ("domain", domain), ("ttl", &ttl_s)];
        let type_refs: Vec<(&str, &str)> =
            type_params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        form.extend(type_refs);

        self.post("/api/zones/records/add", &form).await
    }

    #[instrument(
        skip(self, type_params),
        fields(vendor = "technitium", operation = "delete_record")
    )]
    async fn delete_record(
        &self,
        zone: &str,
        domain: &str,
        type_params: &[(&str, String)],
    ) -> Result<Value> {
        let mut form: Vec<(&str, &str)> = vec![("zone", zone), ("domain", domain)];
        let type_refs: Vec<(&str, &str)> =
            type_params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        form.extend(type_refs);
        self.post("/api/zones/records/delete", &form).await
    }
}

impl CacheRead for TechnitiumClient {
    #[instrument(skip(self), fields(vendor = "technitium", operation = "list_cache"))]
    async fn list_cache(&self, domain: &str) -> Result<Value> {
        self.get("/api/cache/list", &[("domain", domain)]).await
    }
}

impl CacheWrite for TechnitiumClient {
    #[instrument(
        skip(self),
        fields(vendor = "technitium", operation = "delete_cache_zone")
    )]
    async fn delete_cache_zone(&self, domain: &str) -> Result<Value> {
        self.post("/api/cache/delete", &[("domain", domain)]).await
    }

    #[instrument(skip(self), fields(vendor = "technitium", operation = "flush_cache"))]
    async fn flush_cache(&self) -> Result<Value> {
        self.get("/api/cache/flush", &[]).await
    }
}

impl StatsRead for TechnitiumClient {
    #[instrument(skip(self), fields(vendor = "technitium", operation = "get_stats"))]
    async fn get_stats(&self, stats_type: &str) -> Result<Value> {
        self.get("/api/dashboard/stats/get", &[("type", stats_type)])
            .await
    }
}

impl AccessListRead for TechnitiumClient {
    #[instrument(skip(self), fields(vendor = "technitium", operation = "list_blocked"))]
    async fn list_blocked(&self) -> Result<Value> {
        self.get("/api/blocked/list", &[]).await
    }

    #[instrument(skip(self), fields(vendor = "technitium", operation = "list_allowed"))]
    async fn list_allowed(&self) -> Result<Value> {
        self.get("/api/allowed/list", &[]).await
    }
}

impl AccessListWrite for TechnitiumClient {
    #[instrument(skip(self), fields(vendor = "technitium", operation = "add_blocked"))]
    async fn add_blocked(&self, domain: &str) -> Result<Value> {
        self.post("/api/blocked/add", &[("domain", domain)]).await
    }

    #[instrument(
        skip(self),
        fields(vendor = "technitium", operation = "delete_blocked")
    )]
    async fn delete_blocked(&self, domain: &str) -> Result<Value> {
        self.post("/api/blocked/delete", &[("domain", domain)])
            .await
    }

    #[instrument(skip(self), fields(vendor = "technitium", operation = "add_allowed"))]
    async fn add_allowed(&self, domain: &str) -> Result<Value> {
        self.post("/api/allowed/add", &[("domain", domain)]).await
    }

    #[instrument(
        skip(self),
        fields(vendor = "technitium", operation = "delete_allowed")
    )]
    async fn delete_allowed(&self, domain: &str) -> Result<Value> {
        self.post("/api/allowed/delete", &[("domain", domain)])
            .await
    }
}

impl ZoneImport for TechnitiumClient {
    #[instrument(
        skip(self, file_bytes),
        fields(vendor = "technitium", operation = "import_zone_file")
    )]
    async fn import_zone_file(
        &self,
        zone: &str,
        file_name: String,
        file_bytes: Vec<u8>,
        overwrite: bool,
        overwrite_zone: bool,
        overwrite_soa_serial: bool,
    ) -> Result<Value> {
        self.post_file(
            "/api/zones/import",
            &[
                ("zone", zone),
                ("overwrite", if overwrite { "true" } else { "false" }),
                (
                    "overwriteZone",
                    if overwrite_zone { "true" } else { "false" },
                ),
                (
                    "overwriteSoaSerial",
                    if overwrite_soa_serial {
                        "true"
                    } else {
                        "false"
                    },
                ),
            ],
            file_name,
            file_bytes,
        )
        .await
    }
}

impl ZoneExport for TechnitiumClient {
    #[instrument(
        skip(self),
        fields(vendor = "technitium", operation = "export_zone_file")
    )]
    async fn export_zone_file<'a>(&'a self, zone: &'a str) -> Result<String> {
        self.get_text("/api/zones/export", &[("zone", zone)]).await
    }
}

impl SettingsRead for TechnitiumClient {
    #[instrument(skip(self), fields(vendor = "technitium", operation = "get_settings"))]
    async fn get_settings(&self) -> Result<Value> {
        self.get("/api/settings/get", &[]).await
    }
}

impl LogsRead for TechnitiumClient {
    #[instrument(skip(self, options), fields(vendor = "technitium", operation = "get_logs"))]
    async fn get_logs(&self, options: LogsOptions) -> Result<Vec<LogLine>> {
        let lines = options.lines.to_string();
        let mut params: Vec<(&str, &str)> = vec![("entriesPerPage", &lines)];
        if let Some(ref s) = options.start { params.push(("start", s)); }
        if let Some(ref e) = options.end   { params.push(("end",   e)); }
        let response_type = match options.level {
            Some(LogLevel::Critical) | Some(LogLevel::Error) => Some("Dropped"),
            Some(LogLevel::Warning)                          => Some("Blocked"),
            _                                                => None,
        };
        if let Some(rt) = response_type { params.push(("responseType", rt)); }
        let raw = self.get("/api/log/query", &params).await?;
        parse_log_lines(&raw)
    }
}

fn parse_log_lines(raw: &Value) -> Result<Vec<LogLine>> {
    let entries = raw["response"]["entries"]
        .as_array()
        .ok_or_else(|| Error::parse("log query response missing entries array"))?;
    let lines = entries.iter().map(|e| {
        let response_type = e["responseType"].as_str().unwrap_or("");
        let level = match response_type {
            "Dropped"                                                    => LogLevel::Error,
            "Blocked"                                                    => LogLevel::Warning,
            "Cached" | "Recursive" | "Authoritative" | "LocallyServed"  => LogLevel::Info,
            _                                                            => LogLevel::Debug,
        };
        let name  = e["question"]["name"].as_str().unwrap_or("");
        let qtype = e["question"]["type"].as_str().unwrap_or("");
        let title = if name.is_empty() { None } else { Some(format!("{name} ({qtype})")) };
        let rcode     = e["rCode"].as_str().unwrap_or("");
        let client_ip = e["clientIpAddress"].as_str().unwrap_or("");
        let message   = format!("{response_type}: {rcode} from {client_ip}");
        let timestamp = e["timestamp"].as_str().unwrap_or("").to_string();
        LogLine { timestamp, level, title, message }
    }).collect();
    Ok(lines)
}
