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
use crate::core::dns::records::RecordData;
use crate::core::dns::responses::{ListRecordsResponse, ZoneInfo, ZoneRecord};
use crate::core::dns::service::{
    AccessListRead, AccessListWrite, CacheRead, CacheWrite, DnsVendor, ListRecordsOptions,
    RecordWrite, SettingsRead, StatsRead, ZoneExport, ZoneImport, ZoneRead, ZoneWrite,
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
        }
    }
}

// ─── ZoneRead ─────────────────────────────────────────────────────────────────

impl ZoneRead for CloudflareClient {
    #[instrument(skip(self), fields(vendor = "cloudflare", operation = "list_zones"))]
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

    #[instrument(skip(self), fields(vendor = "cloudflare", operation = "list_records"))]
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
    #[instrument(skip(self), fields(vendor = "cloudflare", operation = "create_zone"))]
    async fn create_zone<'a>(&'a self, zone: &'a str, _zone_type: &'a str) -> Result<Value> {
        self.post(
            "/zones",
            &serde_json::json!({ "name": zone, "jump_start": false }),
        )
        .await
    }

    #[instrument(skip(self), fields(vendor = "cloudflare", operation = "delete_zone"))]
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
        fields(vendor = "cloudflare", operation = "add_record")
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
        fields(vendor = "cloudflare", operation = "delete_record")
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
                Some(expected) => {
                    r.get("content").and_then(|c| c.as_str()) == Some(expected)
                }
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
        fields(vendor = "cloudflare", operation = "import_zone_file")
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
        fields(vendor = "cloudflare", operation = "export_zone_file")
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

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_client() -> CloudflareClient {
        CloudflareClient::new(
            "https://api.cloudflare.com/client/v4".to_string(),
            crate::core::secret::ApiToken::new("test-token"),
        )
        .unwrap()
    }

    // ── VendorKind / capabilities ─────────────────────────────────────────────

    #[test]
    fn kind_returns_cloudflare() {
        let client = make_client();
        assert_eq!(client.kind(), VendorKind::Cloudflare);
    }

    #[test]
    fn capabilities_match_supported_operations() {
        let caps = make_client().capabilities();
        assert!(caps.zones);
        assert!(caps.records);
        assert!(!caps.cache);
        assert!(!caps.access_lists);
        assert!(caps.settings);
        assert!(caps.zone_import);
        assert!(caps.zone_export);
    }

    // ── Unsupported operations return correct error ────────────────────────────

    #[tokio::test]
    async fn enable_zone_is_unsupported() {
        let err = make_client().enable_zone("example.com").await.unwrap_err();
        assert!(matches!(
            err,
            Error::Unsupported {
                vendor: "Cloudflare",
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
                vendor: "Cloudflare",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn list_cache_is_unsupported() {
        let err = make_client().list_cache("example.com").await.unwrap_err();
        assert!(matches!(
            err,
            Error::Unsupported {
                vendor: "Cloudflare",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn flush_cache_is_unsupported() {
        let err = make_client().flush_cache().await.unwrap_err();
        assert!(matches!(
            err,
            Error::Unsupported {
                vendor: "Cloudflare",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn get_stats_is_unsupported() {
        let err = make_client().get_stats("last7days").await.unwrap_err();
        assert!(matches!(
            err,
            Error::Unsupported {
                vendor: "Cloudflare",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn list_blocked_is_unsupported() {
        let err = make_client().list_blocked().await.unwrap_err();
        assert!(matches!(
            err,
            Error::Unsupported {
                vendor: "Cloudflare",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn zone_import_attempts_api_call_with_default_flags() {
        // overwrite=true, overwrite_zone=false — network error confirms it reaches the API
        let err = make_client()
            .import_zone_file("example.com", "zone.txt".into(), vec![], true, false, false)
            .await
            .unwrap_err();
        assert!(!matches!(err, Error::Unsupported { .. }));
    }

    #[tokio::test]
    async fn zone_import_overwrite_zone_warns_and_proceeds() {
        // overwrite_zone=true emits a warning but still reaches the API (not an error)
        let err = make_client()
            .import_zone_file("example.com", "zone.txt".into(), vec![], true, true, false)
            .await
            .unwrap_err();
        assert!(!matches!(err, Error::Unsupported { .. }));
    }

    #[tokio::test]
    async fn zone_import_no_overwrite_warns_and_proceeds() {
        // overwrite=false emits a warning but still reaches the API (not an error)
        let err = make_client()
            .import_zone_file(
                "example.com",
                "zone.txt".into(),
                vec![],
                false,
                false,
                false,
            )
            .await
            .unwrap_err();
        assert!(!matches!(err, Error::Unsupported { .. }));
    }

    // ── Record normalization ──────────────────────────────────────────────────

    #[test]
    fn a_record_normalization() {
        let cf = json!({
            "id": "abc", "name": "www.example.com", "type": "A",
            "content": "1.2.3.4", "ttl": 300, "proxied": false
        });
        let rec = cloudflare_record_to_zone_record(&cf, "example.com");
        assert_eq!(rec.name, "www");
        assert_eq!(rec.record_type, "A");
        assert_eq!(rec.ttl, 300);
        assert!(!rec.disabled);
        assert_eq!(rec.data["ipAddress"], "1.2.3.4");
        assert_eq!(rec.data["proxied"], false);
    }

    #[test]
    fn apex_record_name_becomes_at() {
        let cf = json!({
            "id": "abc", "name": "example.com", "type": "A",
            "content": "1.2.3.4", "ttl": 300, "proxied": false
        });
        let rec = cloudflare_record_to_zone_record(&cf, "example.com");
        assert_eq!(rec.name, "@");
    }

    #[test]
    fn mx_record_normalization() {
        let cf = json!({
            "id": "abc", "name": "example.com", "type": "MX",
            "content": "mail.example.com", "priority": 10, "ttl": 300
        });
        let rec = cloudflare_record_to_zone_record(&cf, "example.com");
        assert_eq!(rec.record_type, "MX");
        assert_eq!(rec.data["preference"], 10);
        assert_eq!(rec.data["exchange"], "mail.example.com");
    }

    #[test]
    fn txt_record_normalization() {
        let cf = json!({
            "id": "abc", "name": "example.com", "type": "TXT",
            "content": "v=spf1 ~all", "ttl": 300
        });
        let rec = cloudflare_record_to_zone_record(&cf, "example.com");
        assert_eq!(rec.data["text"], "v=spf1 ~all");
        assert_eq!(rec.data["splitText"], false);
    }

    #[test]
    fn cname_record_normalization() {
        let cf = json!({
            "id": "abc", "name": "www.example.com", "type": "CNAME",
            "content": "example.com", "ttl": 300, "proxied": false
        });
        let rec = cloudflare_record_to_zone_record(&cf, "example.com");
        assert_eq!(rec.data["cname"], "example.com");
    }

    #[test]
    fn srv_record_normalization() {
        let cf = json!({
            "id": "abc", "name": "_sip._tcp.example.com", "type": "SRV",
            "data": { "priority": 10, "weight": 20, "port": 5060, "target": "sip.example.com" },
            "ttl": 300
        });
        let rec = cloudflare_record_to_zone_record(&cf, "example.com");
        assert_eq!(rec.record_type, "SRV");
        assert_eq!(rec.data["priority"], 10);
        assert_eq!(rec.data["weight"], 20);
        assert_eq!(rec.data["port"], 5060);
        assert_eq!(rec.data["target"], "sip.example.com");
    }

    #[test]
    fn unknown_type_falls_back_to_value_field() {
        let cf = json!({
            "id": "abc", "name": "example.com", "type": "LOC",
            "content": "51 30 0.000 N 0 7 0.000 W 0m", "ttl": 300
        });
        let rec = cloudflare_record_to_zone_record(&cf, "example.com");
        assert_eq!(rec.record_type, "LOC");
        assert!(rec.data.get("value").is_some());
    }

    #[test]
    fn aaaa_record_normalization() {
        let cf = json!({
            "id": "abc", "name": "www.example.com", "type": "AAAA",
            "content": "2001:db8::1", "ttl": 300, "proxied": false
        });
        let rec = cloudflare_record_to_zone_record(&cf, "example.com");
        assert_eq!(rec.name, "www");
        assert_eq!(rec.record_type, "AAAA");
        assert_eq!(rec.data["ipAddress"], "2001:db8::1");
    }

    #[test]
    fn dname_record_normalization() {
        let cf = json!({
            "id": "abc", "name": "example.com", "type": "DNAME",
            "content": "other.example.com", "ttl": 300
        });
        let rec = cloudflare_record_to_zone_record(&cf, "example.com");
        assert_eq!(rec.record_type, "DNAME");
        assert_eq!(rec.data["dname"], "other.example.com");
    }

    #[test]
    fn sshfp_record_normalization() {
        let cf = json!({
            "id": "abc", "name": "example.com", "type": "SSHFP",
            "content": "1 2 abcdef", "ttl": 300,
            "data": { "algorithm": 1, "type": 2, "fingerprint": "abcdef" }
        });
        let rec = cloudflare_record_to_zone_record(&cf, "example.com");
        assert_eq!(rec.record_type, "SSHFP");
        assert_eq!(rec.data["sshfpAlgorithm"], "RSA");
        assert_eq!(rec.data["sshfpFingerprintType"], "SHA256");
        assert_eq!(rec.data["sshfpFingerprint"], "abcdef");
    }

    #[test]
    fn tlsa_record_normalization() {
        let cf = json!({
            "id": "abc", "name": "_443._tcp.example.com", "type": "TLSA",
            "content": "3 1 1 deadbeef", "ttl": 300,
            "data": { "usage": 3, "selector": 1, "matching_type": 1, "certificate": "deadbeef" }
        });
        let rec = cloudflare_record_to_zone_record(&cf, "example.com");
        assert_eq!(rec.record_type, "TLSA");
        assert_eq!(rec.data["tlsaCertificateUsage"], "DANE-EE");
        assert_eq!(rec.data["tlsaSelector"], "SPKI");
        assert_eq!(rec.data["tlsaMatchingType"], "SHA2-256");
        assert_eq!(rec.data["tlsaCertificateAssociationData"], "deadbeef");
    }

    #[test]
    fn ds_record_normalization() {
        let cf = json!({
            "id": "abc", "name": "example.com", "type": "DS",
            "content": "1234 13 2 abcdef", "ttl": 300,
            "data": { "key_tag": 1234, "algorithm": 13, "digest_type": 2, "digest": "abcdef" }
        });
        let rec = cloudflare_record_to_zone_record(&cf, "example.com");
        assert_eq!(rec.record_type, "DS");
        assert_eq!(rec.data["keyTag"], 1234);
        assert_eq!(rec.data["algorithm"], "ECDSAP256SHA256");
        assert_eq!(rec.data["digestType"], "SHA256");
        assert_eq!(rec.data["digest"], "abcdef");
    }

    #[test]
    fn https_record_normalization() {
        let cf = json!({
            "id": "abc", "name": "example.com", "type": "HTTPS",
            "content": "1 . alpn=h2", "ttl": 300,
            "data": { "priority": 1, "target": ".", "value": "alpn=h2" }
        });
        let rec = cloudflare_record_to_zone_record(&cf, "example.com");
        assert_eq!(rec.record_type, "HTTPS");
        assert_eq!(rec.data["svcPriority"], 1);
        assert_eq!(rec.data["svcTargetName"], ".");
        assert_eq!(rec.data["svcParams"], "alpn=h2");
    }

    #[test]
    fn naptr_record_normalization() {
        let cf = json!({
            "id": "abc", "name": "example.com", "type": "NAPTR",
            "content": "100 10 U E2U+sip !^.*$! .", "ttl": 300,
            "data": {
                "order": 100, "preference": 10,
                "flags": "U", "service": "E2U+sip",
                "regexp": "!^.*$!", "replacement": "."
            }
        });
        let rec = cloudflare_record_to_zone_record(&cf, "example.com");
        assert_eq!(rec.record_type, "NAPTR");
        assert_eq!(rec.data["naptrOrder"], 100);
        assert_eq!(rec.data["naptrServices"], "E2U+sip");
        assert_eq!(rec.data["naptrFlags"], "U");
    }

    #[test]
    fn uri_record_normalization() {
        let cf = json!({
            "id": "abc", "name": "example.com", "type": "URI",
            "content": "10 1 https://example.com", "ttl": 300,
            "data": { "priority": 10, "weight": 1, "content": "https://example.com" }
        });
        let rec = cloudflare_record_to_zone_record(&cf, "example.com");
        assert_eq!(rec.record_type, "URI");
        assert_eq!(rec.data["uriPriority"], 10);
        assert_eq!(rec.data["uriWeight"], 1);
        assert_eq!(rec.data["uri"], "https://example.com");
    }

    #[test]
    fn proxied_flag_preserved_in_data() {
        let cf = json!({
            "id": "abc", "name": "www.example.com", "type": "A",
            "content": "1.2.3.4", "ttl": 1, "proxied": true
        });
        let rec = cloudflare_record_to_zone_record(&cf, "example.com");
        assert_eq!(rec.data["proxied"], true);
    }

    #[test]
    fn record_id_preserved_in_data() {
        let cf = json!({
            "id": "record-id-xyz", "name": "www.example.com", "type": "A",
            "content": "1.2.3.4", "ttl": 300, "proxied": false
        });
        let rec = cloudflare_record_to_zone_record(&cf, "example.com");
        assert_eq!(rec.data["id"], "record-id-xyz");
    }

    // ── extract_relative_name ─────────────────────────────────────────────────

    #[test]
    fn subdomain_is_extracted() {
        assert_eq!(
            extract_relative_name("sub.example.com", "example.com"),
            "sub"
        );
    }

    #[test]
    fn apex_returns_at() {
        assert_eq!(extract_relative_name("example.com", "example.com"), "@");
    }

    #[test]
    fn non_matching_fqdn_returned_as_is() {
        assert_eq!(
            extract_relative_name("other.net", "example.com"),
            "other.net"
        );
    }

    // ── record_data_to_cloudflare_body ────────────────────────────────────────

    #[test]
    fn a_record_body() {
        let record = RecordData::A {
            ip: "1.2.3.4".parse().unwrap(),
        };
        let body = record_data_to_cloudflare_body("www.example.com", 300, &record);
        assert_eq!(body["type"], "A");
        assert_eq!(body["content"], "1.2.3.4");
        assert_eq!(body["ttl"], 300);
        assert_eq!(body["proxied"], false);
    }

    #[test]
    fn mx_record_body() {
        let record = RecordData::Mx {
            preference: 10,
            exchange: "mail.example.com".into(),
        };
        let body = record_data_to_cloudflare_body("example.com", 300, &record);
        assert_eq!(body["type"], "MX");
        assert_eq!(body["content"], "mail.example.com");
        assert_eq!(body["priority"], 10);
    }

    #[test]
    fn aaaa_record_body() {
        let record = RecordData::Aaaa {
            ip: "2001:db8::1".parse().unwrap(),
        };
        let body = record_data_to_cloudflare_body("www.example.com", 300, &record);
        assert_eq!(body["type"], "AAAA");
        assert_eq!(body["content"], "2001:db8::1");
        assert_eq!(body["ttl"], 300);
        assert_eq!(body["proxied"], false);
    }

    #[test]
    fn srv_record_body_uses_data_object() {
        let record = RecordData::Srv {
            priority: 10,
            weight: 20,
            port: 5060,
            target: "sip.example.com".into(),
        };
        let body = record_data_to_cloudflare_body("_sip._tcp.example.com", 300, &record);
        assert_eq!(body["type"], "SRV");
        assert_eq!(body["data"]["priority"], 10);
        assert_eq!(body["data"]["port"], 5060);
    }

    #[test]
    fn dname_record_body() {
        let record = RecordData::Dname {
            dname: "other.example.com".into(),
        };
        let body = record_data_to_cloudflare_body("example.com", 300, &record);
        assert_eq!(body["type"], "DNAME");
        assert_eq!(body["content"], "other.example.com");
    }

    #[test]
    fn sshfp_record_body() {
        use crate::core::dns::records::{SshfpAlgorithm, SshfpFingerprintType};
        let record = RecordData::Sshfp {
            algorithm: SshfpAlgorithm::Rsa,
            fingerprint_type: SshfpFingerprintType::Sha256,
            fingerprint: "abcdef".into(),
        };
        let body = record_data_to_cloudflare_body("example.com", 300, &record);
        assert_eq!(body["type"], "SSHFP");
        assert_eq!(body["data"]["algorithm"], 1);
        assert_eq!(body["data"]["type"], 2);
        assert_eq!(body["data"]["fingerprint"], "abcdef");
    }

    #[test]
    fn tlsa_record_body() {
        use crate::core::dns::records::{TlsaCertUsage, TlsaMatchingType, TlsaSelector};
        let record = RecordData::Tlsa {
            cert_usage: TlsaCertUsage::DaneEe,
            selector: TlsaSelector::Spki,
            matching_type: TlsaMatchingType::Sha2_256,
            cert_association_data: "deadbeef".into(),
        };
        let body = record_data_to_cloudflare_body("_443._tcp.example.com", 300, &record);
        assert_eq!(body["type"], "TLSA");
        assert_eq!(body["data"]["usage"], 3);
        assert_eq!(body["data"]["selector"], 1);
        assert_eq!(body["data"]["matching_type"], 1);
        assert_eq!(body["data"]["certificate"], "deadbeef");
    }

    #[test]
    fn ds_record_body() {
        use crate::core::dns::records::{DigestType, DsAlgorithm};
        let record = RecordData::Ds {
            key_tag: 1234,
            algorithm: DsAlgorithm::Ecdsap256sha256,
            digest_type: DigestType::Sha256,
            digest: "abcdef".into(),
        };
        let body = record_data_to_cloudflare_body("example.com", 300, &record);
        assert_eq!(body["type"], "DS");
        assert_eq!(body["data"]["key_tag"], 1234);
        assert_eq!(body["data"]["algorithm"], 13);
        assert_eq!(body["data"]["digest_type"], 2);
        assert_eq!(body["data"]["digest"], "abcdef");
    }

    #[test]
    fn https_record_body() {
        let record = RecordData::Https {
            svc_priority: 1,
            svc_target_name: ".".into(),
            svc_params: Some("alpn=h2".into()),
            auto_ipv4_hint: false,
            auto_ipv6_hint: false,
        };
        let body = record_data_to_cloudflare_body("example.com", 300, &record);
        assert_eq!(body["type"], "HTTPS");
        assert_eq!(body["data"]["priority"], 1);
        assert_eq!(body["data"]["target"], ".");
        assert_eq!(body["data"]["value"], "alpn=h2");
    }

    #[test]
    fn naptr_record_body() {
        let record = RecordData::Naptr {
            order: 100,
            preference: 10,
            flags: "U".into(),
            services: "E2U+sip".into(),
            regexp: "!^.*$!".into(),
            replacement: ".".into(),
        };
        let body = record_data_to_cloudflare_body("example.com", 300, &record);
        assert_eq!(body["type"], "NAPTR");
        assert_eq!(body["data"]["order"], 100);
        assert_eq!(body["data"]["service"], "E2U+sip");
        assert_eq!(body["data"]["flags"], "U");
    }

    #[test]
    fn uri_record_body() {
        let record = RecordData::Uri {
            priority: 10,
            weight: 1,
            uri: "https://example.com".into(),
        };
        let body = record_data_to_cloudflare_body("example.com", 300, &record);
        assert_eq!(body["type"], "URI");
        assert_eq!(body["data"]["priority"], 10);
        assert_eq!(body["data"]["weight"], 1);
        assert_eq!(body["data"]["content"], "https://example.com");
    }

    #[test]
    fn expected_content_extracts_value_for_simple_types() {
        let params = vec![("type", "A".to_string()), ("ipAddress", "1.2.3.4".to_string())];
        assert_eq!(expected_cloudflare_content("A", &params), Some("1.2.3.4"));

        let params = vec![("type", "CNAME".to_string()), ("cname", "x.example.com".to_string())];
        assert_eq!(
            expected_cloudflare_content("CNAME", &params),
            Some("x.example.com")
        );

        let params = vec![("type", "TXT".to_string()), ("text", "v=spf1".to_string())];
        assert_eq!(expected_cloudflare_content("TXT", &params), Some("v=spf1"));
    }

    #[test]
    fn expected_content_returns_none_for_structured_types() {
        let params = vec![
            ("type", "MX".to_string()),
            ("preference", "10".to_string()),
            ("exchange", "mail.example.com".to_string()),
        ];
        assert_eq!(expected_cloudflare_content("MX", &params), None);

        let params = vec![("type", "SRV".to_string())];
        assert_eq!(expected_cloudflare_content("SRV", &params), None);
    }
}
