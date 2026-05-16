//! Pangolin implementations of the vendor-neutral DNS service traits.
//!
//! Pangolin is a WireGuard reverse-proxy platform, not a traditional DNS server.
//! The integration is **read-only**:
//!   - `list_zones`   → GET /org/{orgId}/domains
//!   - `list_records` → GET /org/{orgId}/domain/{domainId}/dns-records
//!   - `get_settings` → GET /orgs  (org discovery)
//!
//! All write and non-DNS operations return `Error::Unsupported`.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_resolver::Resolver;
use serde::Deserialize;
#[cfg(test)]
use serde::Serialize;
use serde_json::Value;
use tracing::instrument;

use crate::control_plane::config::VendorKind;
use crate::core::dns::capabilities::VendorCapabilities;
use crate::core::dns::records::RecordData;
use crate::core::dns::responses::{ListRecordsResponse, ZoneInfo, ZoneRecord};
use crate::core::dns::service::{
    AccessListRead, AccessListWrite, CacheRead, CacheWrite, DnsVendor, ListRecordsOptions,
    RecordWrite, SettingsRead, StatsRead, ZoneImport, ZoneRead, ZoneWrite,
};
use crate::core::error::{Error, Result};
use crate::vendors::pangolin::client::PangolinClient;

// ─── Internal response types ─────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PangolinDomain {
    domain_id: String,
    base_domain: String,
    #[serde(rename = "type")]
    domain_type: String,
    verified: bool,
    failed: bool,
}

#[cfg(test)]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PangolinTarget {
    target_id: u64,
    resource_id: u64,
    site_id: u64,
    ip: String,
    port: u16,
    enabled: bool,
    health_status: String,
    site_name: String,
    site_online: bool,
}

#[cfg(test)]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PangolinSite {
    site_id: u64,
    site_name: String,
    online: bool,
}

#[cfg(test)]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PangolinResource {
    resource_id: u64,
    name: String,
    full_domain: String,
    http: bool,
    protocol: String,
    enabled: bool,
    domain_id: String,
    health: String,
    #[serde(default)]
    targets: Vec<PangolinTarget>,
    #[serde(default)]
    sites: Vec<PangolinSite>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PangolinDnsRecord {
    id: u64,
    domain_id: String,
    record_type: String,
    base_domain: String,
    value: String,
    verified: bool,
}

// ─── Parsing helpers ──────────────────────────────────────────────────────────

fn parse_domains(data: &Value) -> Result<Vec<PangolinDomain>> {
    let arr = data
        .get("domains")
        .and_then(|d| d.as_array())
        .ok_or_else(|| Error::parse("Pangolin domains response missing 'domains' array"))?;

    arr.iter()
        .filter_map(|v| serde_json::from_value::<PangolinDomain>(v.clone()).ok())
        .collect::<Vec<_>>()
        .pipe(Ok)
}

#[cfg(test)]
fn parse_resources(data: &Value) -> Result<Vec<PangolinResource>> {
    let arr = data
        .get("resources")
        .and_then(|r| r.as_array())
        .ok_or_else(|| Error::parse("Pangolin resources response missing 'resources' array"))?;

    arr.iter()
        .filter_map(|v| serde_json::from_value::<PangolinResource>(v.clone()).ok())
        .collect::<Vec<_>>()
        .pipe(Ok)
}

fn parse_dns_records(data: &Value) -> Result<Vec<PangolinDnsRecord>> {
    let arr = data
        .as_array()
        .ok_or_else(|| Error::parse("Pangolin DNS records response missing data array"))?;

    arr.iter()
        .filter_map(|v| serde_json::from_value::<PangolinDnsRecord>(v.clone()).ok())
        .collect::<Vec<_>>()
        .pipe(Ok)
}

trait Pipe: Sized {
    fn pipe<R>(self, f: impl FnOnce(Self) -> R) -> R {
        f(self)
    }
}
impl<T> Pipe for T {}

// ─── Record conversion ────────────────────────────────────────────────────────

/// Strip `".{base_domain}"` suffix from `full_domain`, returning `"@"` for the apex.
fn extract_subdomain(full_domain: &str, base_domain: &str) -> String {
    let full_lower = full_domain.to_lowercase();
    let base_lower = base_domain.to_lowercase();

    if full_lower == base_lower {
        return "@".to_string();
    }

    let suffix = format!(".{}", base_lower);
    if full_lower.ends_with(&suffix) {
        full_domain[..full_domain.len() - suffix.len()].to_string()
    } else {
        full_domain.to_string()
    }
}

#[cfg(test)]
fn resource_to_zone_record(resource: &PangolinResource, base_domain: &str) -> ZoneRecord {
    let name = extract_subdomain(&resource.full_domain, base_domain);
    let record_type = if resource.http {
        "HTTP".to_string()
    } else {
        resource.protocol.to_uppercase()
    };

    let data = serde_json::json!({
        "resourceId": resource.resource_id,
        "name": resource.name,
        "fullDomain": resource.full_domain,
        "health": resource.health,
        "targets": resource.targets,
        "sites": resource.sites,
    });

    ZoneRecord {
        name,
        record_type,
        ttl: 0,
        disabled: !resource.enabled,
        comments: resource.name.clone(),
        expiry_ttl: 0,
        data,
        parsed: None,
    }
}

fn dns_record_to_zone_record(
    record: &PangolinDnsRecord,
    zone_name: &str,
    resolved_ips: &[IpAddr],
    use_local_ip: bool,
) -> ZoneRecord {
    let record_type = record.record_type.to_uppercase();
    let name = extract_subdomain(&record.base_domain, zone_name);
    let value = preferred_record_value(&record_type, &record.value, resolved_ips, use_local_ip);
    let data = dns_record_data(&record_type, &value);

    ZoneRecord {
        name,
        record_type,
        ttl: 0,
        disabled: !record.verified,
        comments: format!("Pangolin DNS record {}", record.id),
        expiry_ttl: 0,
        data,
        parsed: None,
    }
}

fn preferred_record_value(
    record_type: &str,
    value: &str,
    resolved_ips: &[IpAddr],
    use_local_ip: bool,
) -> String {
    if !use_local_ip {
        return value.to_string();
    }

    match record_type {
        "A" => resolved_ips
            .iter()
            .find_map(|ip| match ip {
                IpAddr::V4(ip) if is_local_ipv4(ip) => Some(ip.to_string()),
                _ => None,
            })
            .unwrap_or_else(|| value.to_string()),
        "AAAA" => resolved_ips
            .iter()
            .find_map(|ip| match ip {
                IpAddr::V6(ip) if is_local_ipv6(ip) => Some(ip.to_string()),
                _ => None,
            })
            .unwrap_or_else(|| value.to_string()),
        _ => value.to_string(),
    }
}

fn dns_record_data(record_type: &str, value: &str) -> Value {
    match record_type {
        "A" | "AAAA" => serde_json::json!({ "ipAddress": value }),
        "NS" => serde_json::json!({ "nameServer": value, "glue": null }),
        "CNAME" => serde_json::json!({ "cname": value }),
        "TXT" => serde_json::json!({ "text": value, "splitText": false }),
        _ => serde_json::json!({ "value": value }),
    }
}

fn is_local_ipv4(ip: &Ipv4Addr) -> bool {
    ip.is_private()
}

fn is_local_ipv6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    (segments[0] & 0xfe00) == 0xfc00
}

async fn resolve_local_candidates(names: &[String]) -> HashMap<String, Vec<IpAddr>> {
    let resolver = match Resolver::builder_tokio() {
        Ok(builder) => match builder.build() {
            Ok(resolver) => resolver,
            Err(error) => {
                tracing::debug!(%error, "failed to build DNS resolver for local IP lookup");
                return HashMap::new();
            }
        },
        Err(error) => {
            tracing::debug!(%error, "failed to load DNS resolver config for local IP lookup");
            return HashMap::new();
        }
    };

    let mut resolved = HashMap::new();
    for name in names {
        match resolver.lookup_ip(name.as_str()).await {
            Ok(lookup) => {
                let ips: Vec<IpAddr> = lookup.iter().filter(is_local_ip).collect();
                if !ips.is_empty() {
                    resolved.insert(name.clone(), ips);
                }
            }
            Err(error) => {
                tracing::debug!(%error, name, "local IP lookup failed");
            }
        }
    }
    resolved
}

fn is_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_local_ipv4(ip),
        IpAddr::V6(ip) => is_local_ipv6(ip),
    }
}

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

        let dns_records = parse_dns_records(&records_data)?;

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
        let resolved = resolve_local_candidates(&lookup_names).await;

        let records: Vec<ZoneRecord> = dns_records
            .iter()
            .filter(|r| r.domain_id == domain.domain_id)
            .filter(|r| {
                name_filter
                    .map(|n| r.base_domain.eq_ignore_ascii_case(n))
                    .unwrap_or(true)
            })
            .map(|r| {
                dns_record_to_zone_record(
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

    #[instrument(skip(self, options), fields(vendor = "pangolin", operation = "list_records"))]
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
        let domains = parse_domains(&domains_data)?;

        if let Some(zone_name) = zone {
            // Zone explicitly specified — return records for that zone only.
            let matching = domains
                .iter()
                .find(|d| d.base_domain.eq_ignore_ascii_case(zone_name))
                .ok_or_else(|| {
                    Error::api(format!("zone '{zone_name}' not found in Pangolin domains"))
                })?;
            let zone_records =
                self.fetch_zone_records(matching, Some(domain), options).await?;
            Ok(ListRecordsResponse {
                zones: vec![zone_records],
            })
        } else {
            // No zone specified — list records for every domain in the org.
            let mut all_zones = Vec::with_capacity(domains.len());
            for domain_entry in &domains {
                let zone_records = self
                    .fetch_zone_records(domain_entry, None, options)
                    .await?;
                all_zones.push(zone_records);
            }
            Ok(ListRecordsResponse { zones: all_zones })
        }
    }
}

// ─── ZoneWrite (unsupported) ──────────────────────────────────────────────────

impl ZoneWrite for PangolinClient {
    async fn create_zone(&self, _zone: &str, _zone_type: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "zone creation"))
    }

    async fn delete_zone(&self, _zone: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "zone deletion"))
    }

    async fn enable_zone(&self, _zone: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "zone enable"))
    }

    async fn disable_zone(&self, _zone: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "zone disable"))
    }
}

// ─── RecordWrite (unsupported) ────────────────────────────────────────────────

impl RecordWrite for PangolinClient {
    async fn add_record(
        &self,
        _zone: &str,
        _domain: &str,
        _ttl: u32,
        _record: &RecordData,
    ) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "record add"))
    }

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
    async fn list_cache(&self, _domain: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "cache"))
    }
}

impl CacheWrite for PangolinClient {
    async fn delete_cache_zone(&self, _domain: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "cache"))
    }

    async fn flush_cache(&self) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "cache"))
    }
}

// ─── StatsRead (unsupported) ──────────────────────────────────────────────────

impl StatsRead for PangolinClient {
    async fn get_stats(&self, _stats_type: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "stats"))
    }
}

// ─── AccessListRead / AccessListWrite (unsupported) ───────────────────────────

impl AccessListRead for PangolinClient {
    async fn list_blocked(&self) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "access lists"))
    }

    async fn list_allowed(&self) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "access lists"))
    }
}

impl AccessListWrite for PangolinClient {
    async fn add_blocked(&self, _domain: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "access lists"))
    }

    async fn delete_blocked(&self, _domain: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "access lists"))
    }

    async fn add_allowed(&self, _domain: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "access lists"))
    }

    async fn delete_allowed(&self, _domain: &str) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "access lists"))
    }
}

// ─── ZoneImport (unsupported) ─────────────────────────────────────────────────

impl ZoneImport for PangolinClient {
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
