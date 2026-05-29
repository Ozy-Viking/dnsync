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
    RecordWrite, SettingsRead, StatsRead, ZoneExport, ZoneImport, ZoneRead, ZoneWrite,
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
        }
    }
}

// ─── ZoneRead ─────────────────────────────────────────────────────────────────

impl ZoneRead for PangolinClient {
    #[instrument(skip(self), fields(vendor = "pangolin", operation = "list_zones"))]
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
        fields(vendor = "pangolin", operation = "list_records")
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
mod tests {
    use super::*;
    use serde_json::json;

    use crate::vendors::pangolin::mapping::{
        dns_record_to_zone_record, extract_subdomain, parse_dns_records, parse_domains,
        parse_resources, resource_to_zone_record,
    };
    use crate::vendors::pangolin::responses::{PangolinDnsRecord, PangolinResource};

    // ── extract_subdomain ─────────────────────────────────────────────────────

    #[test]
    fn apex_returns_at() {
        assert_eq!(extract_subdomain("app.hankin.io", "app.hankin.io"), "@");
    }

    #[test]
    fn single_label_subdomain() {
        assert_eq!(
            extract_subdomain("grafana.app.hankin.io", "app.hankin.io"),
            "grafana"
        );
    }

    #[test]
    fn multi_label_subdomain() {
        assert_eq!(
            extract_subdomain("a.b.app.hankin.io", "app.hankin.io"),
            "a.b"
        );
    }

    #[test]
    fn case_insensitive_stripping() {
        assert_eq!(
            extract_subdomain("Grafana.App.Hankin.IO", "app.hankin.io"),
            "Grafana"
        );
    }

    #[test]
    fn unrelated_domain_returned_as_is() {
        assert_eq!(
            extract_subdomain("other.example.com", "app.hankin.io"),
            "other.example.com"
        );
    }

    // ── resource_to_zone_record ───────────────────────────────────────────────

    fn make_resource(
        full_domain: &str,
        http: bool,
        protocol: &str,
        enabled: bool,
    ) -> PangolinResource {
        PangolinResource {
            resource_id: 1,
            name: "Test".to_string(),
            full_domain: full_domain.to_string(),
            http,
            protocol: protocol.to_string(),
            enabled,
            domain_id: "dom1".to_string(),
            health: "healthy".to_string(),
            targets: vec![],
            sites: vec![],
        }
    }

    #[test]
    fn http_resource_maps_to_http_record_type() {
        let r = make_resource("svc.app.hankin.io", true, "tcp", true);
        let rec = resource_to_zone_record(&r, "app.hankin.io");
        assert_eq!(rec.record_type, "HTTP");
        assert_eq!(rec.name, "svc");
        assert!(!rec.disabled);
    }

    #[test]
    fn non_http_resource_uses_uppercased_protocol() {
        let r = make_resource("vpn.app.hankin.io", false, "tcp", true);
        let rec = resource_to_zone_record(&r, "app.hankin.io");
        assert_eq!(rec.record_type, "TCP");
    }

    #[test]
    fn disabled_resource_maps_to_disabled_record() {
        let r = make_resource("off.app.hankin.io", true, "tcp", false);
        let rec = resource_to_zone_record(&r, "app.hankin.io");
        assert!(rec.disabled);
    }

    #[test]
    fn record_data_contains_resource_fields() {
        let r = make_resource("svc.app.hankin.io", true, "tcp", true);
        let rec = resource_to_zone_record(&r, "app.hankin.io");
        assert_eq!(rec.data["resourceId"], 1);
        assert_eq!(rec.data["fullDomain"], "svc.app.hankin.io");
        assert_eq!(rec.data["health"], "healthy");
    }

    // ── parse_domains ─────────────────────────────────────────────────────────

    #[test]
    fn parses_domain_list() {
        let data = json!({
            "domains": [
                {
                    "domainId": "y61yv7gv7qmn2js",
                    "baseDomain": "app.hankin.io",
                    "verified": true,
                    "type": "ns",
                    "failed": false,
                    "tries": 0,
                    "configManaged": false,
                    "certResolver": null,
                    "preferWildcardCert": false,
                    "errorMessage": null
                }
            ],
            "pagination": { "total": "1", "limit": 1000, "offset": 0 }
        });
        let domains = parse_domains(&data).unwrap();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].domain_id, "y61yv7gv7qmn2js");
        assert_eq!(domains[0].base_domain, "app.hankin.io");
        assert_eq!(domains[0].domain_type, "ns");
        assert!(domains[0].verified);
        assert!(!domains[0].failed);
    }

    #[test]
    fn missing_domains_key_returns_parse_error() {
        let err = parse_domains(&json!({})).unwrap_err();
        assert!(matches!(err, Error::Parse { ref context } if context.contains("domains")));
    }

    // ── parse_resources ───────────────────────────────────────────────────────

    #[test]
    fn parses_resource_list() {
        let data = json!({
            "resources": [
                {
                    "resourceId": 13613,
                    "niceId": "granular-greater-naked-tailed-armadillo",
                    "name": "Grafana",
                    "ssl": true,
                    "fullDomain": "grafana.app.hankin.io",
                    "passwordId": null,
                    "sso": true,
                    "pincodeId": null,
                    "whitelist": false,
                    "http": true,
                    "protocol": "tcp",
                    "proxyPort": null,
                    "wildcard": false,
                    "enabled": true,
                    "domainId": "y61yv7gv7qmn2js",
                    "headerAuthId": null,
                    "health": "healthy",
                    "targets": [],
                    "sites": []
                }
            ],
            "pagination": { "total": 1, "pageSize": 5, "page": 1 }
        });
        let resources = parse_resources(&data).unwrap();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].resource_id, 13613);
        assert_eq!(resources[0].full_domain, "grafana.app.hankin.io");
        assert_eq!(resources[0].domain_id, "y61yv7gv7qmn2js");
        assert!(resources[0].http);
        assert!(resources[0].enabled);
    }

    #[test]
    fn missing_resources_key_returns_parse_error() {
        let err = parse_resources(&json!({})).unwrap_err();
        assert!(matches!(err, Error::Parse { ref context } if context.contains("resources")));
    }

    // ── Pangolin DNS records ──────────────────────────────────────────────────

    #[test]
    fn parses_dns_records_array() {
        let records = parse_dns_records(&json!([
            {
                "id": 18720,
                "domainId": "y61yv7gv7qmn2js",
                "recordType": "NS",
                "baseDomain": "app.hankin.io",
                "value": "ns1.pangolin-ns.net",
                "verified": true
            }
        ]))
        .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, 18720);
        assert_eq!(records[0].record_type, "NS");
        assert_eq!(records[0].value, "ns1.pangolin-ns.net");
    }

    #[test]
    fn missing_dns_records_array_returns_parse_error() {
        let err = parse_dns_records(&json!({})).unwrap_err();
        assert!(matches!(err, Error::Parse { ref context } if context.contains("DNS records")));
    }

    #[test]
    fn ns_dns_record_maps_to_normalized_zone_record() {
        let record = PangolinDnsRecord {
            id: 18720,
            domain_id: "y61yv7gv7qmn2js".to_string(),
            record_type: "NS".to_string(),
            base_domain: "app.hankin.io".to_string(),
            value: "ns1.pangolin-ns.net".to_string(),
            verified: true,
        };

        let zone_record = dns_record_to_zone_record(&record, "app.hankin.io", &[], false);

        assert_eq!(zone_record.name, "@");
        assert_eq!(zone_record.record_type, "NS");
        assert_eq!(zone_record.data["nameServer"], "ns1.pangolin-ns.net");
        assert_eq!(zone_record.data["glue"], serde_json::Value::Null);
        assert!(!zone_record.disabled);
    }

    #[test]
    fn a_dns_record_maps_to_normalized_zone_record() {
        let record = PangolinDnsRecord {
            id: 11,
            domain_id: "hankin".to_string(),
            record_type: "A".to_string(),
            base_domain: "*.hankin.io".to_string(),
            value: "144.6.233.253".to_string(),
            verified: true,
        };

        let zone_record = dns_record_to_zone_record(&record, "hankin.io", &[], false);

        assert_eq!(zone_record.name, "*");
        assert_eq!(zone_record.record_type, "A");
        assert_eq!(zone_record.data["ipAddress"], "144.6.233.253");
    }

    #[test]
    fn cname_dns_record_maps_to_normalized_zone_record() {
        let record = PangolinDnsRecord {
            id: 18724,
            domain_id: "4u6jvem261kcg4k".to_string(),
            record_type: "CNAME".to_string(),
            base_domain: "_acme-challenge.huly.hankin.io".to_string(),
            value: "_acme-challenge.4u6jvem261kcg4k.cname.pangolin-ns.net".to_string(),
            verified: true,
        };

        let zone_record = dns_record_to_zone_record(&record, "huly.hankin.io", &[], false);

        assert_eq!(zone_record.name, "_acme-challenge");
        assert_eq!(zone_record.record_type, "CNAME");
        assert_eq!(
            zone_record.data["cname"],
            "_acme-challenge.4u6jvem261kcg4k.cname.pangolin-ns.net"
        );
    }

    #[test]
    fn local_ip_flag_prefers_local_ipv4_for_a_records() {
        let record = PangolinDnsRecord {
            id: 11,
            domain_id: "hankin".to_string(),
            record_type: "A".to_string(),
            base_domain: "hankin.io".to_string(),
            value: "144.6.233.253".to_string(),
            verified: true,
        };
        let resolved = vec![
            "144.6.233.253".parse().unwrap(),
            "192.168.1.10".parse().unwrap(),
        ];

        let zone_record = dns_record_to_zone_record(&record, "hankin.io", &resolved, true);

        assert_eq!(zone_record.data["ipAddress"], "192.168.1.10");
    }

    #[test]
    fn local_ip_flag_does_not_override_ns_records() {
        let record = PangolinDnsRecord {
            id: 18720,
            domain_id: "y61yv7gv7qmn2js".to_string(),
            record_type: "NS".to_string(),
            base_domain: "app.hankin.io".to_string(),
            value: "ns1.pangolin-ns.net".to_string(),
            verified: true,
        };
        let resolved = vec!["192.168.1.10".parse().unwrap()];

        let zone_record = dns_record_to_zone_record(&record, "app.hankin.io", &resolved, true);

        assert_eq!(zone_record.data["nameServer"], "ns1.pangolin-ns.net");
    }

    // ── redact_org_keys ───────────────────────────────────────────────────────

    #[test]
    fn ssh_keys_are_redacted() {
        let data = json!({
            "orgs": [
                {
                    "orgId": "hankin-io",
                    "name": "Hankin.io",
                    "sshCaPrivateKey": "PRIVATE_KEY_DATA",
                    "sshCaPublicKey": "PUBLIC_KEY_DATA"
                }
            ]
        });
        let result = redact_org_keys(data);
        let org = &result["orgs"][0];
        assert!(org.get("sshCaPrivateKey").is_none());
        assert!(org.get("sshCaPublicKey").is_none());
        assert_eq!(org["orgId"], "hankin-io");
    }

    #[test]
    fn redact_handles_missing_orgs_key_gracefully() {
        let data = json!({ "other": "data" });
        let result = redact_org_keys(data.clone());
        assert_eq!(result, data);
    }
}
