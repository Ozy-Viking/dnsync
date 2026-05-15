//! Pangolin implementations of the vendor-neutral DNS service traits.
//!
//! Pangolin is a WireGuard reverse-proxy platform, not a traditional DNS server.
//! The integration is **read-only**:
//!   - `list_zones`   → GET /org/{orgId}/domains
//!   - `list_records` → GET /org/{orgId}/resources  (filtered, then mapped)
//!   - `get_settings` → GET /orgs  (org discovery)
//!
//! All write and non-DNS operations return `Error::Unsupported`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::control_plane::config::VendorKind;
use crate::core::dns::capabilities::VendorCapabilities;
use crate::core::dns::records::RecordData;
use crate::core::dns::responses::{ListRecordsResponse, ZoneInfo, ZoneRecord};
use crate::core::dns::service::{
    AccessListRead, AccessListWrite, CacheRead, CacheWrite, DnsVendor, RecordWrite, SettingsRead,
    StatsRead, ZoneImport, ZoneRead, ZoneWrite,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PangolinSite {
    site_id: u64,
    site_name: String,
    online: bool,
}

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
    async fn list_zones(&self, page: u32, per_page: u32) -> Result<Value> {
        let limit = per_page.to_string();
        let offset = ((page.saturating_sub(1)) * per_page).to_string();
        self.get(
            &format!("/org/{}/domains", self.org_id),
            &[("limit", limit), ("offset", offset)],
        )
        .await
    }

    async fn list_records(&self, domain: &str, zone: Option<&str>) -> Result<ListRecordsResponse> {
        let zone_name = zone.unwrap_or(domain);

        // Step 1 — resolve domainId for the requested zone.
        let domains_data = self
            .get(
                &format!("/org/{}/domains", self.org_id),
                &[("limit", "1000".to_string()), ("offset", "0".to_string())],
            )
            .await?;

        let domains = parse_domains(&domains_data)?;
        let matching = domains
            .iter()
            .find(|d| d.base_domain.eq_ignore_ascii_case(zone_name))
            .ok_or_else(|| {
                Error::api(format!(
                    "zone '{}' not found in Pangolin domains",
                    zone_name
                ))
            })?;

        // Step 2 — fetch all resources (Pangolin has no server-side domain filter).
        let resources_data = self
            .get(
                &format!("/org/{}/resources", self.org_id),
                &[
                    ("pageSize", "1000".to_string()),
                    ("page", "1".to_string()),
                ],
            )
            .await?;

        let all_resources = parse_resources(&resources_data)?;

        // Step 3 — filter by domainId; optionally narrow to a specific fullDomain.
        let specific = zone.is_some() && !domain.eq_ignore_ascii_case(zone_name);
        let records: Vec<ZoneRecord> = all_resources
            .iter()
            .filter(|r| r.domain_id == matching.domain_id)
            .filter(|r| !specific || r.full_domain.eq_ignore_ascii_case(domain))
            .map(|r| resource_to_zone_record(r, &matching.base_domain))
            .collect();

        let zone_info = ZoneInfo {
            name: matching.base_domain.clone(),
            zone_type: format!("Pangolin/{}", matching.domain_type),
            disabled: false,
            dnssec_status: None,
        };

        Ok(ListRecordsResponse {
            zone: zone_info,
            records,
        })
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
    async fn add_record(&self, _zone: &str, _domain: &str, _ttl: u32, _record: &RecordData) -> Result<Value> {
        Err(Error::unsupported("Pangolin", "record add"))
    }

    async fn delete_record(&self, _zone: &str, _domain: &str, _type_params: &[(&str, String)]) -> Result<Value> {
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
    async fn get_settings(&self) -> Result<Value> {
        let data = self.get("/orgs", &[("limit", "1000".to_string()), ("offset", "0".to_string())]).await?;
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

    fn make_resource(full_domain: &str, http: bool, protocol: &str, enabled: bool) -> PangolinResource {
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
