//! Technitium implementations of the vendor-neutral DNS service traits.

use serde_json::Value;
use tracing::instrument;

use crate::control_plane::config::VendorKind;
use crate::core::dns::capabilities::VendorCapabilities;
use crate::core::dns::logs::{LogLevel, LogLine, LogsOptions, LogsRead};
use crate::core::dns::records::RecordData;
use crate::core::dns::responses::ListRecordsResponse;
use crate::core::dns::service::{
    AccessListRead, AccessListWrite, CacheRead, CacheWrite, DnsVendor, ListRecordsOptions,
    RecordWrite, SettingsRead, SettingsWrite, StatsRead, ZoneExport, ZoneImport, ZoneOptionsRead,
    ZoneOptionsWrite, ZoneRead, ZoneWrite,
};
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
            zone_options: true,
            settings_write: true,
        }
    }
}

impl ZoneRead for TechnitiumClient {
    #[instrument(
        skip(self),
        fields(vendor = "technitium", operation = "list_zones", page, per_page)
    )]
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
        fields(vendor = "technitium", operation = "list_records", domain, zone = ?zone)
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
    #[instrument(
        skip(self),
        fields(vendor = "technitium", operation = "create_zone", zone, zone_type)
    )]
    async fn create_zone(&self, zone: &str, zone_type: &str) -> Result<Value> {
        self.post("/api/zones/create", &[("zone", zone), ("type", zone_type)])
            .await
    }

    #[instrument(
        skip(self),
        fields(vendor = "technitium", operation = "delete_zone", zone)
    )]
    async fn delete_zone(&self, zone: &str) -> Result<Value> {
        self.post("/api/zones/delete", &[("zone", zone)]).await
    }

    #[instrument(
        skip(self),
        fields(vendor = "technitium", operation = "enable_zone", zone)
    )]
    async fn enable_zone(&self, zone: &str) -> Result<Value> {
        self.post("/api/zones/enable", &[("zone", zone)]).await
    }

    #[instrument(
        skip(self),
        fields(vendor = "technitium", operation = "disable_zone", zone)
    )]
    async fn disable_zone(&self, zone: &str) -> Result<Value> {
        self.post("/api/zones/disable", &[("zone", zone)]).await
    }
}

impl RecordWrite for TechnitiumClient {
    #[instrument(
        skip(self, record),
        fields(vendor = "technitium", operation = "add_record", zone, domain)
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
        fields(vendor = "technitium", operation = "delete_record", zone, domain)
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
    #[instrument(
        skip(self),
        fields(vendor = "technitium", operation = "list_cache", domain)
    )]
    async fn list_cache(&self, domain: &str) -> Result<Value> {
        self.get("/api/cache/list", &[("domain", domain)]).await
    }
}

impl CacheWrite for TechnitiumClient {
    #[instrument(
        skip(self),
        fields(vendor = "technitium", operation = "delete_cache_zone", domain)
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
    #[instrument(
        skip(self),
        fields(vendor = "technitium", operation = "get_stats", stats_type)
    )]
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
    #[instrument(
        skip(self),
        fields(vendor = "technitium", operation = "add_blocked", domain)
    )]
    async fn add_blocked(&self, domain: &str) -> Result<Value> {
        self.post("/api/blocked/add", &[("domain", domain)]).await
    }

    #[instrument(
        skip(self),
        fields(vendor = "technitium", operation = "delete_blocked", domain)
    )]
    async fn delete_blocked(&self, domain: &str) -> Result<Value> {
        self.post("/api/blocked/delete", &[("domain", domain)])
            .await
    }

    #[instrument(
        skip(self),
        fields(vendor = "technitium", operation = "add_allowed", domain)
    )]
    async fn add_allowed(&self, domain: &str) -> Result<Value> {
        self.post("/api/allowed/add", &[("domain", domain)]).await
    }

    #[instrument(
        skip(self),
        fields(vendor = "technitium", operation = "delete_allowed", domain)
    )]
    async fn delete_allowed(&self, domain: &str) -> Result<Value> {
        self.post("/api/allowed/delete", &[("domain", domain)])
            .await
    }
}

impl ZoneImport for TechnitiumClient {
    #[instrument(
        skip(self, file_bytes),
        fields(
            vendor = "technitium",
            operation = "import_zone_file",
            zone,
            overwrite,
            overwrite_zone
        )
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
        fields(vendor = "technitium", operation = "export_zone_file", zone)
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

impl SettingsWrite for TechnitiumClient {
    #[instrument(
        skip(self, settings),
        fields(vendor = "technitium", operation = "set_settings")
    )]
    async fn set_settings(&self, settings: &Value) -> Result<Value> {
        let obj = settings
            .as_object()
            .ok_or_else(|| Error::parse("settings must be a JSON object"))?;
        let params: Vec<(String, String)> = obj
            .iter()
            .map(|(k, v)| {
                let s = match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                (k.clone(), s)
            })
            .collect();
        let param_refs: Vec<(&str, &str)> = params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.post("/api/settings/set", &param_refs).await
    }
}

impl ZoneOptionsRead for TechnitiumClient {
    #[instrument(
        skip(self),
        fields(vendor = "technitium", operation = "get_zone_options")
    )]
    async fn get_zone_options(&self, zone: &str) -> Result<Value> {
        self.get("/api/zones/options/get", &[("zone", zone)]).await
    }
}

impl ZoneOptionsWrite for TechnitiumClient {
    #[instrument(
        skip(self, options),
        fields(vendor = "technitium", operation = "set_zone_options")
    )]
    async fn set_zone_options(&self, zone: &str, options: &Value) -> Result<Value> {
        let obj = options
            .as_object()
            .ok_or_else(|| Error::parse("zone options must be a JSON object"))?;
        if obj.contains_key("zone") {
            return Err(Error::parse(
                "zone options payload must not include reserved key 'zone'",
            ));
        }
        let mut params: Vec<(String, String)> = vec![("zone".into(), zone.into())];
        for (k, v) in obj {
            let s = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            params.push((k.clone(), s));
        }
        let param_refs: Vec<(&str, &str)> = params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.post("/api/zones/options/set", &param_refs).await
    }
}

impl LogsRead for TechnitiumClient {
    #[instrument(
        skip(self, options),
        fields(vendor = "technitium", operation = "get_logs")
    )]
    async fn get_logs(&self, options: LogsOptions) -> Result<Vec<LogLine>> {
        let raw = self.get("/api/logs/list", &[]).await?;
        let file_name = latest_log_file_name(&raw)?;
        let text = self
            .get_text(
                "/api/logs/download",
                &[("fileName", file_name.as_str()), ("limit", "1")],
            )
            .await?;
        Ok(parse_log_file(&text, &options))
    }
}

fn latest_log_file_name(raw: &Value) -> Result<String> {
    let entries = raw["response"]["logFiles"]
        .as_array()
        .ok_or_else(|| Error::parse("logs list response missing logFiles array"))?;
    entries
        .iter()
        .filter_map(|entry| entry["fileName"].as_str())
        .max()
        .map(ToOwned::to_owned)
        .ok_or_else(|| Error::parse("logs list response did not include any fileName values"))
}

fn parse_log_file(text: &str, options: &LogsOptions) -> Vec<LogLine> {
    let mut lines: Vec<LogLine> = text
        .lines()
        .filter_map(parse_log_file_line)
        .filter(|line| {
            options
                .level
                .map(|level| line.level >= level)
                .unwrap_or(true)
        })
        .filter(|line| {
            options
                .start
                .as_deref()
                .map(|start| line.timestamp.as_str() >= start)
                .unwrap_or(true)
        })
        .filter(|line| {
            options
                .end
                .as_deref()
                .map(|end| line.timestamp.as_str() <= end)
                .unwrap_or(true)
        })
        .collect();

    if let Some(requested) = options.lines {
        let requested = requested as usize;
        if requested == 0 {
            lines.clear();
        } else if lines.len() > requested {
            lines = lines.split_off(lines.len() - requested);
        }
    }
    lines
}

fn parse_log_file_line(line: &str) -> Option<LogLine> {
    let rest = line.strip_prefix('[')?;
    let (timestamp, rest) = rest.split_once(']')?;
    let message = rest.trim().to_string();
    Some(LogLine {
        timestamp: timestamp.trim().to_string(),
        level: classify_log_level(&message),
        title: log_title(&message),
        message,
    })
}

fn classify_log_level(message: &str) -> LogLevel {
    let lower = message.to_ascii_lowercase();
    if lower.contains("critical") || lower.contains("fatal") {
        LogLevel::Critical
    } else if lower.contains("error")
        || lower.contains("failed")
        || lower.contains("refused")
        || lower.contains("exception")
    {
        LogLevel::Error
    } else if lower.contains("warn") || lower.contains("not allowed") {
        LogLevel::Warning
    } else {
        LogLevel::Info
    }
}

fn log_title(message: &str) -> Option<String> {
    let lower = message.to_ascii_lowercase();
    let title = if lower.contains("zone transfer") {
        "zone transfer"
    } else if lower.contains("notify") {
        "notify"
    } else if lower.contains("configuration") {
        "configuration"
    } else if lower.contains("new record") {
        "record"
    } else {
        return None;
    };
    Some(title.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn latest_log_file_name_picks_latest_file() {
        let raw = json!({
            "response": {
                "logFiles": [
                    {"fileName": "2026-05-28", "size": "1 KB"},
                    {"fileName": "2026-05-29", "size": "2 KB"}
                ]
            },
            "status": "ok"
        });

        assert_eq!(latest_log_file_name(&raw).unwrap(), "2026-05-29");
    }

    #[test]
    fn parse_log_file_extracts_and_filters_recent_lines() {
        let text = "\
[2026-05-29 05:36:25 Local] [10.2.65.122:0] [admin] New record was added to Primary zone 'hankin.io' successfully
[2026-05-29 05:36:30 Local] DNS Server failed to notify name server '10.5.161.84' (RCODE=Refused) for zone: hankin.io
[2026-05-29 05:36:31 Local] Saved zone file for domain: hankin.io
";

        let lines = parse_log_file(
            text,
            &LogsOptions {
                lines: Some(1),
                start: None,
                end: None,
                level: Some(LogLevel::Error),
            },
        );

        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].level, LogLevel::Error);
        assert_eq!(lines[0].title.as_deref(), Some("notify"));
        assert!(lines[0].message.contains("RCODE=Refused"));
    }

    #[test]
    fn parse_log_file_line_ignores_unstructured_lines() {
        assert!(parse_log_file_line("not a technitium log line").is_none());
    }
}
