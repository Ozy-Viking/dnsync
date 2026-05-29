//! Pi-hole v6 implementations of the vendor-neutral DNS service traits.
//!
//! Pi-hole is a DNS sinkhole and ad-blocker with a REST API for managing:
//!   - Local DNS records (A, AAAA, CNAME)
//!   - Domain allow/block lists
//!   - Query cache
//!   - Statistics
//!   - Server configuration
//!
//! Zone management (create/delete/import/export) is not supported.

use serde_json::Value;
use tracing::instrument;

use crate::control_plane::config::VendorKind;
use crate::core::dns::capabilities::VendorCapabilities;
use crate::core::dns::logs::{LogLine, LogsOptions, LogsRead};
use crate::core::dns::records::RecordData;
use crate::core::dns::responses::{ListRecordsResponse, ZoneInfo, ZoneRecord};
use crate::core::dns::service::{
    AccessListRead, AccessListWrite, CacheRead, CacheWrite, DnsVendor, ListRecordsOptions,
    RecordWrite, SettingsRead, StatsRead, ZoneExport, ZoneImport, ZoneRead, ZoneWrite,
};
use crate::core::error::{Error, Result};
use crate::vendors::pihole::client::PiholeClient;
use crate::vendors::pihole::mapping::*;

// ─── DnsVendor ────────────────────────────────────────────────────────────────

impl DnsVendor for PiholeClient {
    fn kind(&self) -> VendorKind {
        VendorKind::Pihole
    }

    fn capabilities(&self) -> VendorCapabilities {
        VendorCapabilities {
            zones: false,
            records: true,
            cache: true,
            access_lists: true,
            settings: true,
            zone_import: false,
            zone_export: false,
            logs: false,
        }
    }
}

// ─── ZoneRead ─────────────────────────────────────────────────────────────────

impl ZoneRead for PiholeClient {
    async fn list_zones<'a>(&'a self, _page: u32, _per_page: u32) -> Result<Value> {
        Err(Error::unsupported("Pi-hole", "zone listing"))
    }

    #[instrument(skip(self), fields(vendor = "pihole", operation = "list_records"))]
    async fn list_records<'a>(
        &'a self,
        domain: &'a str,
        zone: Option<&'a str>,
        options: ListRecordsOptions,
    ) -> Result<ListRecordsResponse> {
        let inferred;
        let zone_name = match zone {
            Some(z) => z,
            None => {
                inferred = infer_zone(domain);
                &inferred
            }
        };

        let dns_data = self.get("/api/dns/local_records", &[]).await?;
        let cname_data = self.get("/api/dns/local_cnames", &[]).await?;

        let mut records: Vec<ZoneRecord> = Vec::new();

        let domain_lc = domain.trim_end_matches('.').to_ascii_lowercase();
        let domain_suffix = format!(".{domain_lc}");

        if let Some(arr) = dns_data.get("dns").and_then(|d| d.as_array()) {
            for entry in arr {
                let host = entry.get("host").and_then(|h| h.as_str()).unwrap_or("");
                let host_lc = host.trim_end_matches('.').to_ascii_lowercase();
                if domain.is_empty()
                    || host_lc == domain_lc
                    || (options.all_subdomains && host_lc.ends_with(&domain_suffix))
                {
                    records.push(local_dns_to_zone_record(entry, zone_name));
                }
            }
        }

        if let Some(arr) = cname_data.get("cnames").and_then(|c| c.as_array()) {
            for entry in arr {
                let cname_domain = entry.get("domain").and_then(|d| d.as_str()).unwrap_or("");
                let cname_lc = cname_domain.trim_end_matches('.').to_ascii_lowercase();
                if domain.is_empty()
                    || cname_lc == domain_lc
                    || (options.all_subdomains && cname_lc.ends_with(&domain_suffix))
                {
                    records.push(local_cname_to_zone_record(entry, zone_name));
                }
            }
        }

        let zone_info = ZoneInfo {
            id: None,
            name: zone_name.to_string(),
            zone_type: "Local".to_string(),
            disabled: false,
            dnssec_status: None,
        };

        Ok(ListRecordsResponse::single(zone_info, records))
    }
}

// ─── ZoneWrite ────────────────────────────────────────────────────────────────

impl ZoneWrite for PiholeClient {
    async fn create_zone<'a>(&'a self, _zone: &'a str, _zone_type: &'a str) -> Result<Value> {
        Err(Error::unsupported("Pi-hole", "zone creation"))
    }

    async fn delete_zone<'a>(&'a self, _zone: &'a str) -> Result<Value> {
        Err(Error::unsupported("Pi-hole", "zone deletion"))
    }

    async fn enable_zone<'a>(&'a self, _zone: &'a str) -> Result<Value> {
        Err(Error::unsupported("Pi-hole", "enable zone"))
    }

    async fn disable_zone<'a>(&'a self, _zone: &'a str) -> Result<Value> {
        Err(Error::unsupported("Pi-hole", "disable zone"))
    }
}

// ─── RecordWrite ──────────────────────────────────────────────────────────────

impl RecordWrite for PiholeClient {
    #[instrument(
        skip(self, record),
        fields(vendor = "pihole", operation = "add_record")
    )]
    async fn add_record<'a>(
        &'a self,
        _zone: &'a str,
        domain: &'a str,
        _ttl: u32,
        record: &'a RecordData,
    ) -> Result<Value> {
        let body = record_data_to_local_dns_body(domain, record).ok_or_else(|| {
            Error::unsupported(
                "Pi-hole",
                "record type — only A, AAAA, and CNAME are supported",
            )
        })?;

        let endpoint = match record {
            RecordData::Cname { .. } => "/api/dns/local_cnames",
            _ => "/api/dns/local_records",
        };

        self.post(endpoint, &body).await
    }

    #[instrument(
        skip(self, type_params),
        fields(vendor = "pihole", operation = "delete_record")
    )]
    async fn delete_record<'a>(
        &'a self,
        _zone: &'a str,
        domain: &'a str,
        type_params: &'a [(&'a str, String)],
    ) -> Result<Value> {
        let record_type = type_params
            .iter()
            .find(|(k, _)| *k == "type")
            .map(|(_, v)| v.as_str())
            .unwrap_or("A");

        let ip = type_params
            .iter()
            .find(|(k, _)| *k == "ipAddress" || *k == "ip")
            .map(|(_, v)| v.clone());

        let target = type_params
            .iter()
            .find(|(k, _)| *k == "cname")
            .map(|(_, v)| v.clone());

        match record_type.to_uppercase().as_str() {
            "A" | "AAAA" => {
                let ip_val = ip.ok_or_else(|| {
                    Error::parse("delete A/AAAA record requires 'ip' or 'ipAddress' parameter")
                })?;
                let body = serde_json::json!({ "ip": ip_val, "host": domain });
                self.delete_with_body("/api/dns/local_records", &body).await
            }
            "CNAME" => {
                let cname_target = target.ok_or_else(|| {
                    Error::parse("delete CNAME record requires 'cname' parameter")
                })?;
                let body = serde_json::json!({ "domain": domain, "target": cname_target });
                self.delete_with_body("/api/dns/local_cnames", &body).await
            }
            _ => Err(Error::unsupported(
                "Pi-hole",
                "record type — only A, AAAA, and CNAME can be deleted",
            )),
        }
    }
}

// ─── CacheRead ────────────────────────────────────────────────────────────────

impl CacheRead for PiholeClient {
    #[instrument(skip(self), fields(vendor = "pihole", operation = "list_cache"))]
    async fn list_cache<'a>(&'a self, _domain: &'a str) -> Result<Value> {
        self.get("/api/cache", &[]).await
    }
}

// ─── CacheWrite ───────────────────────────────────────────────────────────────

impl CacheWrite for PiholeClient {
    async fn delete_cache_zone<'a>(&'a self, _domain: &'a str) -> Result<Value> {
        Err(Error::unsupported("Pi-hole", "per-zone cache deletion"))
    }

    #[instrument(skip(self), fields(vendor = "pihole", operation = "flush_cache"))]
    async fn flush_cache(&self) -> Result<Value> {
        self.post("/api/cache/flush", &serde_json::json!({})).await
    }
}

// ─── StatsRead ────────────────────────────────────────────────────────────────

impl StatsRead for PiholeClient {
    #[instrument(skip(self), fields(vendor = "pihole", operation = "get_stats"))]
    async fn get_stats<'a>(&'a self, stats_type: &'a str) -> Result<Value> {
        match stats_type {
            "overTime" | "overtime" | "history" => {
                self.get("/api/stats/overTime/history", &[]).await
            }
            "clients" => self.get("/api/stats/overTime/clients", &[]).await,
            _ => self.get("/api/stats/summary", &[]).await,
        }
    }
}

// ─── AccessListRead ───────────────────────────────────────────────────────────

impl AccessListRead for PiholeClient {
    #[instrument(skip(self), fields(vendor = "pihole", operation = "list_blocked"))]
    async fn list_blocked(&self) -> Result<Value> {
        self.get("/api/domains", &[("type", "block".to_string())])
            .await
    }

    #[instrument(skip(self), fields(vendor = "pihole", operation = "list_allowed"))]
    async fn list_allowed(&self) -> Result<Value> {
        self.get("/api/domains", &[("type", "allow".to_string())])
            .await
    }
}

// ─── AccessListWrite ──────────────────────────────────────────────────────────

impl AccessListWrite for PiholeClient {
    #[instrument(skip(self), fields(vendor = "pihole", operation = "add_blocked"))]
    async fn add_blocked<'a>(&'a self, domain: &'a str) -> Result<Value> {
        self.post(
            &format!("/api/domains/block/exact/{domain}"),
            &serde_json::json!({}),
        )
        .await
    }

    #[instrument(skip(self), fields(vendor = "pihole", operation = "delete_blocked"))]
    async fn delete_blocked<'a>(&'a self, domain: &'a str) -> Result<Value> {
        self.delete(&format!("/api/domains/block/exact/{domain}"))
            .await
    }

    #[instrument(skip(self), fields(vendor = "pihole", operation = "add_allowed"))]
    async fn add_allowed<'a>(&'a self, domain: &'a str) -> Result<Value> {
        self.post(
            &format!("/api/domains/allow/exact/{domain}"),
            &serde_json::json!({}),
        )
        .await
    }

    #[instrument(skip(self), fields(vendor = "pihole", operation = "delete_allowed"))]
    async fn delete_allowed<'a>(&'a self, domain: &'a str) -> Result<Value> {
        self.delete(&format!("/api/domains/allow/exact/{domain}"))
            .await
    }
}

// ─── ZoneImport / ZoneExport ──────────────────────────────────────────────────

impl ZoneImport for PiholeClient {
    async fn import_zone_file<'a>(
        &'a self,
        _zone: &'a str,
        _file_name: String,
        _file_bytes: Vec<u8>,
        _overwrite: bool,
        _overwrite_zone: bool,
        _overwrite_soa_serial: bool,
    ) -> Result<Value> {
        Err(Error::unsupported("Pi-hole", "zone import"))
    }
}

impl ZoneExport for PiholeClient {
    async fn export_zone_file<'a>(&'a self, _zone: &'a str) -> Result<String> {
        Err(Error::unsupported("Pi-hole", "zone export"))
    }
}

// ─── SettingsRead ─────────────────────────────────────────────────────────────

impl SettingsRead for PiholeClient {
    #[instrument(skip(self), fields(vendor = "pihole", operation = "get_settings"))]
    async fn get_settings(&self) -> Result<Value> {
        self.get("/api/config", &[]).await
    }
}

// ─── LogsRead ─────────────────────────────────────────────────────────────────

impl LogsRead for PiholeClient {
    async fn get_logs(&self, _options: LogsOptions) -> Result<Vec<LogLine>> {
        Err(Error::unsupported("Pi-hole", "logs"))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_client() -> PiholeClient {
        PiholeClient::new(
            "http://pi.hole".to_string(),
            crate::core::secret::ApiToken::new("test-password"),
        )
        .unwrap()
    }

    #[test]
    fn kind_returns_pihole() {
        assert_eq!(make_client().kind(), VendorKind::Pihole);
    }

    #[test]
    fn capabilities_match_supported_operations() {
        let caps = make_client().capabilities();
        assert!(!caps.zones);
        assert!(caps.records);
        assert!(caps.cache);
        assert!(caps.access_lists);
        assert!(caps.settings);
        assert!(!caps.zone_import);
        assert!(!caps.zone_export);
    }

    #[tokio::test]
    async fn list_zones_is_unsupported() {
        let err = make_client().list_zones(1, 100).await.unwrap_err();
        assert!(matches!(
            err,
            Error::Unsupported {
                vendor: "Pi-hole",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn create_zone_is_unsupported() {
        let err = make_client()
            .create_zone("example.com", "Primary")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Unsupported {
                vendor: "Pi-hole",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn delete_zone_is_unsupported() {
        let err = make_client().delete_zone("example.com").await.unwrap_err();
        assert!(matches!(
            err,
            Error::Unsupported {
                vendor: "Pi-hole",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn enable_zone_is_unsupported() {
        let err = make_client().enable_zone("example.com").await.unwrap_err();
        assert!(matches!(
            err,
            Error::Unsupported {
                vendor: "Pi-hole",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn disable_zone_is_unsupported() {
        let err = make_client().disable_zone("example.com").await.unwrap_err();
        assert!(matches!(
            err,
            Error::Unsupported {
                vendor: "Pi-hole",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn delete_cache_zone_is_unsupported() {
        let err = make_client()
            .delete_cache_zone("example.com")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Unsupported {
                vendor: "Pi-hole",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn zone_import_is_unsupported() {
        let err = make_client()
            .import_zone_file("example.com", "zone.txt".into(), vec![], true, false, false)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Unsupported {
                vendor: "Pi-hole",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn zone_export_is_unsupported() {
        let err = make_client()
            .export_zone_file("example.com")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Unsupported {
                vendor: "Pi-hole",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn add_unsupported_record_type_is_unsupported() {
        let record = RecordData::Mx {
            preference: 10,
            exchange: "mail.example.com".into(),
        };
        let err = make_client()
            .add_record("home.lan", "example.com", 300, &record)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Unsupported {
                vendor: "Pi-hole",
                ..
            }
        ));
    }
}
