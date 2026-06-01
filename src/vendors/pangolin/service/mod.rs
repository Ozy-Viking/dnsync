//! Pangolin implementations of the vendor-neutral DNS service traits.
//!
//! Pangolin is a WireGuard reverse-proxy platform, not a traditional DNS server.
//! The integration is **read-only**:
//!   - `list_zones`   → GET /org/{orgId}/domains
//!   - `list_records` → GET /org/{orgId}/domain/{domainId}/dns-records
//!   - `get_settings` → GET /orgs  (org discovery)
//!
//! All write and non-DNS operations return `Error::Unsupported`.

use std::collections::HashSet;

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
use crate::vendors::pangolin::client::PangolinClient;
use crate::vendors::pangolin::mapping;
use crate::vendors::pangolin::responses::PangolinDomain;

// ─── PangolinClient helpers ───────────────────────────────────────────────────

impl PangolinClient {
    /// Fetch DNS records for a single Pangolin domain entry.
    ///
    /// When `name_filter` is Some, only records whose `base_domain` matches it
    /// are included (used when a specific record name is requested within a zone).
    async fn fetch_zone_records(
        &self,
        domain: &PangolinDomain,
        name_filter: Option<&str>,
        options: ListRecordsOptions,
    ) -> Result<crate::core::dns::responses::ZoneRecords> {
        use crate::core::dns::responses::ZoneRecords;

        let records_data = self
            .get(
                &format!(
                    "/org/{}/domain/{}/dns-records",
                    self.org_id, domain.domain_id
                ),
                &[],
            )
            .await?;

        let dns_records = mapping::parse_dns_records(&records_data)?;

        let lookup_names = if options.use_local_ip {
            dns_records
                .iter()
                .filter(|r| matches!(r.record_type.to_uppercase().as_str(), "A" | "AAAA"))
                .map(|r| r.base_domain.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let resolved = mapping::resolve_local_candidates(&lookup_names).await;

        let records: Vec<ZoneRecord> = dns_records
            .iter()
            .filter(|r| r.domain_id == domain.domain_id)
            .filter(|r| {
                name_filter
                    .map(|n| r.base_domain.eq_ignore_ascii_case(n))
                    .unwrap_or(true)
            })
            .map(|r| {
                mapping::dns_record_to_zone_record(
                    r,
                    &domain.base_domain,
                    resolved
                        .get(&r.base_domain)
                        .map(Vec::as_slice)
                        .unwrap_or(&[]),
                    options.use_local_ip,
                )
            })
            .collect();

        let zone_info = ZoneInfo {
            id: Some(domain.domain_id.clone()),
            name: domain.base_domain.clone(),
            zone_type: format!("Pangolin/{}", domain.domain_type),
            disabled: domain.failed || !domain.verified,
            dnssec_status: None,
        };

        Ok(ZoneRecords {
            zone: zone_info,
            records,
        })
    }
}

// ─── DnsVendor ────────────────────────────────────────────────────────────────

impl DnsVendor for PangolinClient {
    fn kind(&self) -> VendorKind {
        VendorKind::Pangolin
    }

    fn capabilities(&self) -> VendorCapabilities {
        VendorCapabilities {
            zones: true,
            records: true,
            cache: false,
            access_lists: false,
            settings: true,
            zone_import: false,
            zone_export: false,
            logs: false,
            zone_options: false,
            settings_write: false,
        }
    }
}

// ─── ZoneRead ─────────────────────────────────────────────────────────────────

impl ZoneRead for PangolinClient {
    #[instrument(
        skip(self),
        fields(vendor = "pangolin", operation = "list_zones", page, per_page)
    )]
    async fn list_zones(&self, page: u32, per_page: u32) -> Result<Value> {
        let limit = per_page.to_string();
        let offset = ((page.saturating_sub(1)) * per_page).to_string();
        self.get(
            &format!("/org/{}/domains", self.org_id),
            &[("limit", limit), ("offset", offset)],
        )
        .await
    }

    #[instrument(
        skip(self, options),
        fields(vendor = "pangolin", operation = "list_records", domain, zone = ?zone)
    )]
    async fn list_records(
        &self,
        domain: &str,
        zone: Option<&str>,
        options: ListRecordsOptions,
    ) -> Result<ListRecordsResponse> {
        // Fetch all domains regardless — needed for both single-zone and all-zones paths.
        let domains_data = self
            .get(
                &format!("/org/{}/domains", self.org_id),
                &[("limit", "1000".to_string()), ("offset", "0".to_string())],
            )
            .await?;
        let domains = mapping::parse_domains(&domains_data)?;

        if let Some(zone_name) = zone {
            // Zone explicitly specified — return records for that zone only.
            let matching = domains
                .iter()
                .find(|d| d.base_domain.eq_ignore_ascii_case(zone_name))
                .ok_or_else(|| {
                    Error::api(format!("zone '{zone_name}' not found in Pangolin domains"))
                })?;
            // When all_subdomains is set, skip the name filter so the caller can
            // filter the full zone record set for the target domain + its subdomains.
            let name_filter = if options.all_subdomains {
                None
            } else {
                Some(domain)
            };
            let zone_records = self
                .fetch_zone_records(matching, name_filter, options)
                .await?;
            Ok(ListRecordsResponse {
                zones: vec![zone_records],
            })
        } else {
            // No zone specified — list records for every domain in the org.
            let mut all_zones = Vec::with_capacity(domains.len());
            for domain_entry in &domains {
                let zone_records = self.fetch_zone_records(domain_entry, None, options).await?;
                all_zones.push(zone_records);
            }
            Ok(ListRecordsResponse { zones: all_zones })
        }
    }
}

// ─── ZoneWrite (unsupported) ──────────────────────────────────────────────────

impl ZoneWrite for PangolinClient {
    #[instrument(skip(self), fields(vendor = "pangolin", operation = "create_zone"))]
    async fn create_zone(&self, _zone: &str, _zone_type: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "zone creation"))
    }

    #[instrument(skip(self), fields(vendor = "pangolin", operation = "delete_zone"))]
    async fn delete_zone(&self, _zone: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "zone deletion"))
    }

    #[instrument(skip(self), fields(vendor = "pangolin", operation = "enable_zone"))]
    async fn enable_zone(&self, _zone: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "zone enable"))
    }

    #[instrument(skip(self), fields(vendor = "pangolin", operation = "disable_zone"))]
    async fn disable_zone(&self, _zone: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "zone disable"))
    }
}

// ─── RecordWrite (unsupported) ────────────────────────────────────────────────

impl RecordWrite for PangolinClient {
    #[instrument(
        skip(self, _record),
        fields(vendor = "pangolin", operation = "add_record")
    )]
    async fn add_record(
        &self,
        _zone: &str,
        _domain: &str,
        _ttl: u32,
        _record: &RecordData,
    ) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "record add"))
    }

    #[instrument(
        skip(self, _type_params),
        fields(vendor = "pangolin", operation = "delete_record")
    )]
    async fn delete_record(
        &self,
        _zone: &str,
        _domain: &str,
        _type_params: &[(&str, String)],
    ) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "record delete"))
    }
}

// ─── CacheRead / CacheWrite (unsupported) ─────────────────────────────────────

impl CacheRead for PangolinClient {
    #[instrument(skip(self), fields(vendor = "pangolin", operation = "list_cache"))]
    async fn list_cache(&self, _domain: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "cache"))
    }
}

impl CacheWrite for PangolinClient {
    #[instrument(
        skip(self),
        fields(vendor = "pangolin", operation = "delete_cache_zone")
    )]
    async fn delete_cache_zone(&self, _domain: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "cache"))
    }

    #[instrument(skip(self), fields(vendor = "pangolin", operation = "flush_cache"))]
    async fn flush_cache(&self) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "cache"))
    }
}

// ─── StatsRead (unsupported) ──────────────────────────────────────────────────

impl StatsRead for PangolinClient {
    #[instrument(skip(self), fields(vendor = "pangolin", operation = "get_stats"))]
    async fn get_stats(&self, _stats_type: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "stats"))
    }
}

// ─── AccessListRead / AccessListWrite (unsupported) ───────────────────────────

impl AccessListRead for PangolinClient {
    #[instrument(skip(self), fields(vendor = "pangolin", operation = "list_blocked"))]
    async fn list_blocked(&self) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "access lists"))
    }

    #[instrument(skip(self), fields(vendor = "pangolin", operation = "list_allowed"))]
    async fn list_allowed(&self) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "access lists"))
    }
}

impl AccessListWrite for PangolinClient {
    #[instrument(skip(self), fields(vendor = "pangolin", operation = "add_blocked"))]
    async fn add_blocked(&self, _domain: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "access lists"))
    }

    #[instrument(skip(self), fields(vendor = "pangolin", operation = "delete_blocked"))]
    async fn delete_blocked(&self, _domain: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "access lists"))
    }

    #[instrument(skip(self), fields(vendor = "pangolin", operation = "add_allowed"))]
    async fn add_allowed(&self, _domain: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "access lists"))
    }

    #[instrument(skip(self), fields(vendor = "pangolin", operation = "delete_allowed"))]
    async fn delete_allowed(&self, _domain: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "access lists"))
    }
}

// ─── ZoneImport / ZoneExport (unsupported) ───────────────────────────────────

impl ZoneImport for PangolinClient {
    #[instrument(
        skip(self, _file_bytes),
        fields(vendor = "pangolin", operation = "import_zone_file")
    )]
    async fn import_zone_file(
        &self,
        _zone: &str,
        _file_name: String,
        _file_bytes: Vec<u8>,
        _overwrite: bool,
        _overwrite_zone: bool,
        _overwrite_soa_serial: bool,
    ) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "zone import"))
    }
}

impl ZoneExport for PangolinClient {
    async fn export_zone_file<'a>(&'a self, _zone: &'a str) -> Result<String> {
        Err(Error::unsupported("Pangolin", "zone export"))
    }
}

// ─── SettingsRead → org discovery ─────────────────────────────────────────────

impl SettingsRead for PangolinClient {
    /// Returns the list of organizations visible to this API token.
    /// Use this to discover the `org_id` value for your dnsync config.
    /// SSH CA key fields are omitted from the output.
    #[instrument(skip(self), fields(vendor = "pangolin", operation = "get_settings"))]
    async fn get_settings(&self) -> Result<Value> {
        let data = self
            .get(
                "/orgs",
                &[("limit", "1000".to_string()), ("offset", "0".to_string())],
            )
            .await?;
        Ok(redact_org_keys(data))
    }
}

impl SettingsWrite for PangolinClient {
    async fn set_settings(&self, _settings: &Value) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "settings write"))
    }
}

impl ZoneOptionsRead for PangolinClient {
    async fn get_zone_options(&self, _zone: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "zone options"))
    }
}

impl ZoneOptionsWrite for PangolinClient {
    async fn set_zone_options(&self, _zone: &str, _options: &Value) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "zone options write"))
    }
}

impl LogsRead for PangolinClient {
    async fn get_logs(&self, _: LogsOptions) -> Result<Vec<LogLine>> {
        Err(Error::unsupported("Pangolin", "logs"))
    }
}

/// Remove sensitive SSH CA key fields from org objects before display.
fn redact_org_keys(mut data: Value) -> Value {
    if let Some(orgs) = data.get_mut("orgs").and_then(|o| o.as_array_mut()) {
        for org in orgs.iter_mut() {
            if let Some(obj) = org.as_object_mut() {
                obj.remove("sshCaPrivateKey");
                obj.remove("sshCaPublicKey");
            }
        }
    }
    data
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
