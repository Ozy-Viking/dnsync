//! UniFi implementations of the vendor-neutral DNS service traits.
//!
//! UniFi DNS policies are site-scoped, so dnsync exposes UniFi sites as
//! vendor-neutral zones. The stable site UUID is stored on `ZoneInfo.id`; the
//! human-readable site label is stored on `ZoneInfo.name`. The integration exposes:
//!   - `list_zones`    → GET /sites
//!   - `list_records`  → GET /sites/{siteId}/dns/policies (paginated)
//!   - `add_record`    → POST /sites/{siteId}/dns/policies
//!   - `delete_record` → list, match by domain+type+value, DELETE by id
//!
//! Cache, access lists, stats, settings writes, and zone import/export are
//! unsupported and return `Error::unsupported`. `FORWARD_DOMAIN` policies
//! are surfaced as provider-specific metadata in listings but cannot be
//! created or deleted through the record API.

use serde_json::Value;
use tracing::instrument;

use crate::control_plane::config::VendorKind;
use crate::core::dns::capabilities::VendorCapabilities;
use crate::core::dns::logs::{LogLine, LogsOptions, LogsRead};
use crate::core::dns::names::domain_matches_zone;
use crate::core::dns::records::RecordData;
use crate::core::dns::responses::{ListRecordsResponse, ZoneInfo, ZoneRecord};
use crate::core::dns::service::{
    AccessListRead, AccessListWrite, CacheRead, CacheWrite, DnsVendor, ListRecordsOptions,
    RecordWrite, SettingsRead, SettingsWrite, StatsRead, ZoneExport, ZoneImport, ZoneOptionsRead,
    ZoneOptionsWrite, ZoneRead, ZoneWrite,
};
use crate::core::error::{Error, Result};

use super::client::UnifiClient;
use super::mapping::{
    policy_matches_delete_params, policy_to_zone_record, record_data_to_unifi_body,
};
use super::responses::match_site;

// ─── DnsVendor ────────────────────────────────────────────────────────────────

impl DnsVendor for UnifiClient {
    fn kind(&self) -> VendorKind {
        VendorKind::Unifi
    }

    fn capabilities(&self) -> VendorCapabilities {
        VendorCapabilities {
            zones: true,
            records: true,
            cache: false,
            access_lists: false,
            // `get_settings` returns the controller's visible site list so
            // users can discover their site name/UUID without leaving the CLI.
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

impl ZoneRead for UnifiClient {
    /// UniFi sites are exposed as dnsync zones. The stable site UUID is stored
    /// as `ZoneInfo.id`; `ZoneInfo.name` remains the operator-facing label.
    async fn list_zones(&self, page: u32, per_page: u32) -> Result<Value> {
        let offset = page.saturating_sub(1).saturating_mul(per_page);
        let page = self.list_sites_page(offset, per_page).await?;
        let zones: Vec<ZoneInfo> = page.data.iter().map(ZoneInfo::from).collect();
        Ok(serde_json::json!({
            "response": {
                "zones": zones,
            }
        }))
    }

    #[instrument(
        skip(self, _options),
        fields(vendor = "unifi", operation = "list_records", domain, zone = ?zone)
    )]
    async fn list_records<'a>(
        &'a self,
        domain: &'a str,
        zone: Option<&'a str>,
        _options: ListRecordsOptions,
    ) -> Result<ListRecordsResponse> {
        let sites = self.list_all_sites().await?;
        let site = zone
            .and_then(|zone| match_site(&sites, zone))
            .or_else(|| match_site(&sites, self.site()))
            .ok_or_else(|| {
                Error::api(format!(
                    "UniFi site '{}' not found on this controller",
                    zone.unwrap_or_else(|| self.site())
                ))
            })?;
        let zone_info = ZoneInfo::from(site);
        let zone_label = zone_info.name.clone();
        let site_id = zone_info.id.as_deref().ok_or_else(|| {
            Error::parse(format!(
                "UniFi site zone '{}' is missing its UUID",
                zone_label
            ))
        })?;
        let policies = self
            .list_all_dns_policies_for_site_id(site_id, None)
            .await?;
        let query_domain = if zone.is_some_and(|zone| domain.eq_ignore_ascii_case(zone)) {
            ""
        } else {
            domain
        };

        let records: Vec<ZoneRecord> = policies
            .iter()
            .filter(|p| query_domain.is_empty() || domain_matches_zone(&p.domain, query_domain))
            .map(|p| policy_to_zone_record(p, &zone_label))
            .collect();

        Ok(ListRecordsResponse::single(zone_info, records))
    }
}

// ─── ZoneWrite (unsupported — UniFi has no zone model) ───────────────────────

impl ZoneWrite for UnifiClient {
    async fn create_zone<'a>(&'a self, _zone: &'a str, _zone_type: &'a str) -> Result<Value> {
        Err(Error::unsupported("UniFi", "zone creation"))
    }

    async fn delete_zone<'a>(&'a self, _zone: &'a str) -> Result<Value> {
        Err(Error::unsupported("UniFi", "zone deletion"))
    }

    async fn enable_zone<'a>(&'a self, _zone: &'a str) -> Result<Value> {
        Err(Error::unsupported("UniFi", "zone enable"))
    }

    async fn disable_zone<'a>(&'a self, _zone: &'a str) -> Result<Value> {
        Err(Error::unsupported("UniFi", "zone disable"))
    }
}

// ─── RecordWrite ──────────────────────────────────────────────────────────────

impl RecordWrite for UnifiClient {
    #[instrument(
        skip(self, record),
        fields(vendor = "unifi", operation = "add_record", zone, domain)
    )]
    async fn add_record<'a>(
        &'a self,
        zone: &'a str,
        domain: &'a str,
        ttl: u32,
        record: &'a RecordData,
    ) -> Result<Value> {
        let fqdn = resolve_fqdn(domain, zone);
        let body = record_data_to_unifi_body(&fqdn, ttl, true, record)?;
        let created = self.create_dns_policy(&body).await?;
        serde_json::to_value(created)
            .map_err(|e| Error::parse(format!("re-encoding UniFi create response: {e}")))
    }

    #[instrument(
        skip(self, type_params),
        fields(vendor = "unifi", operation = "delete_record", zone, domain)
    )]
    async fn delete_record<'a>(
        &'a self,
        zone: &'a str,
        domain: &'a str,
        type_params: &'a [(&'a str, String)],
    ) -> Result<Value> {
        let fqdn = resolve_fqdn(domain, zone);
        let policies = self.list_all_dns_policies(None).await?;

        let matched = policies
            .iter()
            .find(|p| policy_matches_delete_params(p, &fqdn, type_params))
            .ok_or_else(|| Error::Api {
                message: format!("no matching UniFi DNS policy found for '{fqdn}'"),
            })?;

        self.delete_dns_policy(&matched.id).await?;
        Ok(serde_json::json!({
            "id": matched.id,
            "domain": matched.domain,
            "type": matched.policy_type.as_str(),
            "deleted": true,
        }))
    }
}

/// Resolve a relative or absolute name within a zone into a UniFi FQDN.
///
/// A name is treated as already-qualified when it is the zone itself or
/// already sits below the zone (e.g. `"www.example.com"` inside zone
/// `"example.com"`). Multi-label relative names like `"a.b"` are appended to
/// the zone — UniFi DNS policies are flat FQDNs, so silently leaving a
/// relative dotted name unqualified would target the wrong domain.
fn resolve_fqdn(domain: &str, zone: &str) -> String {
    if domain == "@" {
        return zone.to_string();
    }
    let candidate = domain.trim_end_matches('.');
    let zone_lower = zone.to_ascii_lowercase();
    let cand_lower = candidate.to_ascii_lowercase();
    if cand_lower == zone_lower || cand_lower.ends_with(&format!(".{zone_lower}")) {
        candidate.to_string()
    } else {
        format!("{candidate}.{zone}")
    }
}

// ─── Unsupported operations ───────────────────────────────────────────────────

impl CacheRead for UnifiClient {
    async fn list_cache<'a>(&'a self, _domain: &'a str) -> Result<Value> {
        Err(Error::unsupported("UniFi", "cache listing"))
    }
}

impl CacheWrite for UnifiClient {
    async fn delete_cache_zone<'a>(&'a self, _domain: &'a str) -> Result<Value> {
        Err(Error::unsupported("UniFi", "cache zone deletion"))
    }

    async fn flush_cache(&self) -> Result<Value> {
        Err(Error::unsupported("UniFi", "cache flush"))
    }
}

impl StatsRead for UnifiClient {
    async fn get_stats<'a>(&'a self, _stats_type: &'a str) -> Result<Value> {
        Err(Error::unsupported("UniFi", "stats"))
    }
}

impl AccessListRead for UnifiClient {
    async fn list_blocked(&self) -> Result<Value> {
        Err(Error::unsupported("UniFi", "blocked list"))
    }

    async fn list_allowed(&self) -> Result<Value> {
        Err(Error::unsupported("UniFi", "allowed list"))
    }
}

impl AccessListWrite for UnifiClient {
    async fn add_blocked<'a>(&'a self, _domain: &'a str) -> Result<Value> {
        Err(Error::unsupported("UniFi", "add blocked"))
    }

    async fn delete_blocked<'a>(&'a self, _domain: &'a str) -> Result<Value> {
        Err(Error::unsupported("UniFi", "delete blocked"))
    }

    async fn add_allowed<'a>(&'a self, _domain: &'a str) -> Result<Value> {
        Err(Error::unsupported("UniFi", "add allowed"))
    }

    async fn delete_allowed<'a>(&'a self, _domain: &'a str) -> Result<Value> {
        Err(Error::unsupported("UniFi", "delete allowed"))
    }
}

impl ZoneImport for UnifiClient {
    async fn import_zone_file<'a>(
        &'a self,
        _zone: &'a str,
        _file_name: String,
        _file_bytes: Vec<u8>,
        _overwrite: bool,
        _overwrite_zone: bool,
        _overwrite_soa_serial: bool,
    ) -> Result<Value> {
        Err(Error::unsupported("UniFi", "zone import"))
    }
}

impl ZoneExport for UnifiClient {
    async fn export_zone_file<'a>(&'a self, _zone: &'a str) -> Result<String> {
        Err(Error::unsupported("UniFi", "zone export"))
    }
}

impl LogsRead for UnifiClient {
    async fn get_logs(&self, _options: LogsOptions) -> Result<Vec<LogLine>> {
        Err(Error::unsupported("UniFi", "logs"))
    }
}

impl SettingsRead for UnifiClient {
    /// Returns the list of UniFi sites accessible to this API key, plus the
    /// configured site label and whether it resolves to a known site. Use
    /// this to discover the human-readable site name to put in `org_id`.
    #[instrument(skip(self), fields(vendor = "unifi", operation = "get_settings"))]
    async fn get_settings(&self) -> Result<Value> {
        let sites = self.list_all_sites().await?;
        let configured = self.site();
        let resolved = super::responses::match_site(&sites, configured).map(|s| s.id.clone());
        Ok(serde_json::json!({
            "configuredSite": configured,
            "resolvedSiteId": resolved,
            "sites": sites,
        }))
    }
}

impl SettingsWrite for UnifiClient {
    async fn set_settings(&self, _settings: &Value) -> Result<Value> {
        Err(Error::unsupported("UniFi", "settings write"))
    }
}

impl ZoneOptionsRead for UnifiClient {
    async fn get_zone_options(&self, _zone: &str) -> Result<Value> {
        Err(Error::unsupported("UniFi", "zone options"))
    }
}

impl ZoneOptionsWrite for UnifiClient {
    async fn set_zone_options(&self, _zone: &str, _options: &Value) -> Result<Value> {
        Err(Error::unsupported("UniFi", "zone options write"))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
