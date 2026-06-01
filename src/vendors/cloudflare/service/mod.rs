//! Cloudflare implementations of the vendor-neutral DNS service traits.
//!
//! Cloudflare is a cloud DNS provider with full DNS CRUD capability.
//! The integration supports:
//!   - `list_zones`    → GET /zones
//!   - `list_records`  → GET /zones/{id}/dns_records
//!   - `create_zone`   → POST /zones
//!   - `delete_zone`   → DELETE /zones/{id}
//!   - `add_record`    → POST /zones/{id}/dns_records
//!   - `delete_record` → GET /zones/{id}/dns_records?name=&type= → DELETE /zones/{id}/dns_records/{id}
//!   - `get_settings`  → GET /user/tokens/verify
//!
//!   - `import_zone_file` → POST /zones/{id}/dns_records/import
//!   - `export_zone_file` → GET /zones/{id}/dns_records/export
//!
//! Cache, stats, access lists, enable/disable zone return `Error::Unsupported`.

use serde_json::Value;
use tracing::instrument;

use crate::control_plane::config::VendorKind;
use crate::core::dns::capabilities::VendorCapabilities;
use crate::core::dns::logs::{LogLine, LogsOptions, LogsRead};
use crate::core::dns::records::RecordData;
use crate::core::dns::responses::{ListRecordsResponse, ZoneInfo, ZoneRecord};
use crate::core::dns::service::{
    AccessListRead, AccessListWrite, CacheRead, CacheWrite, DnsVendor, ListRecordsOptions,
    RecordWrite, SettingsRead, SettingsWrite, StatsRead, ZoneExport, ZoneImport, ZoneOptionsRead,
    ZoneOptionsWrite, ZoneRead, ZoneWrite,
};
use crate::core::error::{Error, Result};
use crate::vendors::cloudflare::client::CloudflareClient;
use crate::vendors::cloudflare::mapping::*;

// ─── Zone ID resolution ───────────────────────────────────────────────────────

impl CloudflareClient {
    async fn resolve_zone_id(&self, zone_name: &str) -> Result<String> {
        let data = self
            .get("/zones", &[("name", zone_name.to_string())])
            .await?;
        let zones = data
            .as_array()
            .ok_or_else(|| Error::parse("Cloudflare zones response is not an array"))?;
        zones
            .first()
            .and_then(|z| z.get("id"))
            .and_then(|id| id.as_str())
            .map(ToOwned::to_owned)
            .ok_or_else(|| Error::Api {
                message: format!("zone '{zone_name}' not found"),
            })
    }
}

// ─── DnsVendor ────────────────────────────────────────────────────────────────

impl DnsVendor for CloudflareClient {
    fn kind(&self) -> VendorKind {
        VendorKind::Cloudflare
    }

    fn capabilities(&self) -> VendorCapabilities {
        VendorCapabilities {
            zones: true,
            records: true,
            cache: false,
            access_lists: false,
            settings: true,
            zone_import: true,
            zone_export: true,
            logs: false,
            zone_options: false,
            settings_write: false,
        }
    }
}

// ─── ZoneRead ─────────────────────────────────────────────────────────────────

impl ZoneRead for CloudflareClient {
    #[instrument(
        skip(self),
        fields(vendor = "cloudflare", operation = "list_zones", page, per_page)
    )]
    async fn list_zones(&self, page: u32, per_page: u32) -> Result<Value> {
        self.get(
            "/zones",
            &[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ],
        )
        .await
    }

    #[instrument(skip(self), fields(vendor = "cloudflare", operation = "list_records", domain, zone = ?zone))]
    async fn list_records<'a>(
        &'a self,
        domain: &'a str,
        zone: Option<&'a str>,
        _options: ListRecordsOptions,
    ) -> Result<ListRecordsResponse> {
        let zone_name = zone.unwrap_or(domain);
        let zone_id = self.resolve_zone_id(zone_name).await?;

        let data = self
            .get(&format!("/zones/{zone_id}/dns_records"), &[])
            .await?;

        let records_arr = data
            .as_array()
            .ok_or_else(|| Error::parse("Cloudflare dns_records response is not an array"))?;

        let records: Vec<ZoneRecord> = records_arr
            .iter()
            .map(|r| cloudflare_record_to_zone_record(r, zone_name))
            .collect();

        let zone_info = ZoneInfo {
            id: Some(zone_id),
            name: zone_name.to_string(),
            zone_type: "Primary".to_string(),
            disabled: false,
            dnssec_status: None,
        };

        Ok(ListRecordsResponse::single(zone_info, records))
    }
}

// ─── ZoneWrite ────────────────────────────────────────────────────────────────

impl ZoneWrite for CloudflareClient {
    #[instrument(
        skip(self),
        fields(vendor = "cloudflare", operation = "create_zone", zone)
    )]
    async fn create_zone<'a>(&'a self, zone: &'a str, _zone_type: &'a str) -> Result<Value> {
        self.post(
            "/zones",
            &serde_json::json!({ "name": zone, "jump_start": false }),
        )
        .await
    }

    #[instrument(
        skip(self),
        fields(vendor = "cloudflare", operation = "delete_zone", zone)
    )]
    async fn delete_zone<'a>(&'a self, zone: &'a str) -> Result<Value> {
        let zone_id = self.resolve_zone_id(zone).await?;
        self.delete(&format!("/zones/{zone_id}")).await
    }

    async fn enable_zone<'a>(&'a self, _zone: &'a str) -> Result<Value> {
        Err(Error::unsupported("Cloudflare", "enable zone"))
    }

    async fn disable_zone<'a>(&'a self, _zone: &'a str) -> Result<Value> {
        Err(Error::unsupported("Cloudflare", "disable zone"))
    }
}

// ─── RecordWrite ──────────────────────────────────────────────────────────────

impl RecordWrite for CloudflareClient {
    #[instrument(
        skip(self, record),
        fields(vendor = "cloudflare", operation = "add_record", zone, domain)
    )]
    async fn add_record<'a>(
        &'a self,
        zone: &'a str,
        domain: &'a str,
        ttl: u32,
        record: &'a RecordData,
    ) -> Result<Value> {
        let zone_id = self.resolve_zone_id(zone).await?;
        let body = record_data_to_cloudflare_body(domain, ttl, record);
        self.post(&format!("/zones/{zone_id}/dns_records"), &body)
            .await
    }

    #[instrument(
        skip(self, type_params),
        fields(vendor = "cloudflare", operation = "delete_record", zone, domain)
    )]
    async fn delete_record<'a>(
        &'a self,
        zone: &'a str,
        domain: &'a str,
        type_params: &'a [(&'a str, String)],
    ) -> Result<Value> {
        let zone_id = self.resolve_zone_id(zone).await?;

        let record_type = type_params
            .iter()
            .find(|(k, _)| *k == "type")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");

        let fqdn = if domain == "@" {
            zone.to_string()
        } else if domain.ends_with('.') {
            domain.trim_end_matches('.').to_string()
        } else if domain.contains('.') {
            domain.to_string()
        } else {
            format!("{domain}.{zone}")
        };

        let data = self
            .get(
                &format!("/zones/{zone_id}/dns_records"),
                &[("name", fqdn.clone()), ("type", record_type.to_string())],
            )
            .await?;

        let records = data
            .as_array()
            .ok_or_else(|| Error::parse("Cloudflare dns_records response is not an array"))?;

        // If the caller supplied a value-bearing parameter (e.g. `ipAddress`
        // for A/AAAA, `cname` for CNAME), restrict the match to records whose
        // Cloudflare `content` field equals that value. Without this filter an
        // rrset with several values would have its first entry deleted at
        // random rather than the requested one.
        let expected_content = expected_cloudflare_content(record_type, type_params);
        let matched = records
            .iter()
            .find(|r| match expected_content {
                Some(expected) => r.get("content").and_then(|c| c.as_str()) == Some(expected),
                None => true,
            })
            .ok_or_else(|| Error::Api {
                message: match expected_content {
                    Some(value) => {
                        format!("no {record_type} record '{fqdn}' with value '{value}' found")
                    }
                    None => format!("no {record_type} record found for '{fqdn}'"),
                },
            })?;

        let record_id = matched
            .get("id")
            .and_then(|id| id.as_str())
            .ok_or_else(|| Error::parse("Cloudflare dns_records entry missing id"))?
            .to_owned();

        self.delete(&format!("/zones/{zone_id}/dns_records/{record_id}"))
            .await
    }
}

/// Returns the value Cloudflare stores in the `content` field for the given
/// record type, looked up from the canonical `type_params` API payload.
/// Returns `None` for record types whose value lives in a structured `data`
/// object (MX, SRV, CAA, …) — those fall back to first-match behaviour.
fn expected_cloudflare_content<'a>(
    record_type: &str,
    type_params: &'a [(&'a str, String)],
) -> Option<&'a str> {
    let key = match record_type {
        "A" | "AAAA" => "ipAddress",
        "CNAME" => "cname",
        "NS" => "nameserver",
        "TXT" => "text",
        "PTR" => "name",
        "DNAME" => "dname",
        _ => return None,
    };
    type_params
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.as_str())
}

// ─── Unsupported operations ───────────────────────────────────────────────────

impl CacheRead for CloudflareClient {
    async fn list_cache<'a>(&'a self, _domain: &'a str) -> Result<Value> {
        Err(Error::unsupported("Cloudflare", "cache listing"))
    }
}

impl CacheWrite for CloudflareClient {
    async fn delete_cache_zone<'a>(&'a self, _domain: &'a str) -> Result<Value> {
        Err(Error::unsupported("Cloudflare", "cache zone deletion"))
    }

    async fn flush_cache(&self) -> Result<Value> {
        Err(Error::unsupported("Cloudflare", "cache flush"))
    }
}

impl StatsRead for CloudflareClient {
    async fn get_stats<'a>(&'a self, _stats_type: &'a str) -> Result<Value> {
        Err(Error::unsupported("Cloudflare", "stats"))
    }
}

impl AccessListRead for CloudflareClient {
    async fn list_blocked(&self) -> Result<Value> {
        Err(Error::unsupported("Cloudflare", "blocked list"))
    }

    async fn list_allowed(&self) -> Result<Value> {
        Err(Error::unsupported("Cloudflare", "allowed list"))
    }
}

impl AccessListWrite for CloudflareClient {
    async fn add_blocked<'a>(&'a self, _domain: &'a str) -> Result<Value> {
        Err(Error::unsupported("Cloudflare", "add blocked"))
    }

    async fn delete_blocked<'a>(&'a self, _domain: &'a str) -> Result<Value> {
        Err(Error::unsupported("Cloudflare", "delete blocked"))
    }

    async fn add_allowed<'a>(&'a self, _domain: &'a str) -> Result<Value> {
        Err(Error::unsupported("Cloudflare", "add allowed"))
    }

    async fn delete_allowed<'a>(&'a self, _domain: &'a str) -> Result<Value> {
        Err(Error::unsupported("Cloudflare", "delete allowed"))
    }
}

impl ZoneImport for CloudflareClient {
    #[instrument(
        skip(self, file_bytes),
        fields(
            vendor = "cloudflare",
            operation = "import_zone_file",
            zone,
            overwrite,
            overwrite_zone
        )
    )]
    async fn import_zone_file<'a>(
        &'a self,
        zone: &'a str,
        file_name: String,
        file_bytes: Vec<u8>,
        overwrite: bool,
        overwrite_zone: bool,
        _overwrite_soa_serial: bool,
    ) -> Result<Value> {
        if overwrite_zone {
            tracing::warn!(
                "overwrite_zone is not supported by Cloudflare — import will be additive; \
                 delete records manually first if a clean replace is needed"
            );
        }
        if !overwrite {
            tracing::warn!(
                "overwrite=false is not supported by Cloudflare — \
                 existing records will still be updated by the import"
            );
        }
        let zone_id = self.resolve_zone_id(zone).await?;
        self.post_multipart(
            &format!("/zones/{zone_id}/dns_records/import"),
            file_name,
            file_bytes,
        )
        .await
    }
}

impl ZoneExport for CloudflareClient {
    #[instrument(
        skip(self),
        fields(vendor = "cloudflare", operation = "export_zone_file", zone)
    )]
    async fn export_zone_file<'a>(&'a self, zone: &'a str) -> Result<String> {
        let zone_id = self.resolve_zone_id(zone).await?;
        self.get_text(&format!("/zones/{zone_id}/dns_records/export"), &[])
            .await
    }
}

impl SettingsRead for CloudflareClient {
    #[instrument(skip(self), fields(vendor = "cloudflare", operation = "get_settings"))]
    async fn get_settings(&self) -> Result<Value> {
        self.get("/user/tokens/verify", &[]).await
    }
}

impl SettingsWrite for CloudflareClient {
    async fn set_settings(&self, _settings: &Value) -> Result<Value> {
        Err(Error::unsupported("Cloudflare", "settings write"))
    }
}

impl ZoneOptionsRead for CloudflareClient {
    async fn get_zone_options(&self, _zone: &str) -> Result<Value> {
        Err(Error::unsupported("Cloudflare", "zone options"))
    }
}

impl ZoneOptionsWrite for CloudflareClient {
    async fn set_zone_options(&self, _zone: &str, _options: &Value) -> Result<Value> {
        Err(Error::unsupported("Cloudflare", "zone options write"))
    }
}

impl LogsRead for CloudflareClient {
    async fn get_logs(&self, _: LogsOptions) -> Result<Vec<LogLine>> {
        Err(Error::unsupported("Cloudflare", "logs"))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
