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
//! Cache, stats, access lists, zone import, enable/disable zone return `Error::Unsupported`.

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
use crate::vendors::cloudflare::client::CloudflareClient;

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

// ─── Record normalization ─────────────────────────────────────────────────────

fn extract_relative_name(fqdn: &str, zone_name: &str) -> String {
    let fqdn_lower = fqdn.to_lowercase();
    let zone_lower = zone_name.to_lowercase();

    if fqdn_lower == zone_lower {
        return "@".to_string();
    }

    let suffix = format!(".{}", zone_lower);
    if fqdn_lower.ends_with(&suffix) {
        fqdn[..fqdn.len() - suffix.len()].to_string()
    } else {
        fqdn.to_string()
    }
}

fn normalize_rdata(record_type: &str, content: &str, cf_record: &Value) -> Value {
    match record_type {
        "A" | "AAAA" => serde_json::json!({ "ipAddress": content }),
        "CNAME" => serde_json::json!({ "cname": content }),
        "MX" => {
            let priority = cf_record
                .get("priority")
                .and_then(|p| p.as_u64())
                .unwrap_or(10);
            serde_json::json!({ "preference": priority, "exchange": content })
        }
        "TXT" => serde_json::json!({ "text": content, "splitText": false }),
        "NS" => serde_json::json!({ "nameServer": content, "glue": null }),
        "PTR" => serde_json::json!({ "ptrName": content }),
        "SRV" => {
            if let Some(data) = cf_record.get("data") {
                let priority = data.get("priority").and_then(|p| p.as_u64()).unwrap_or(0);
                let weight = data.get("weight").and_then(|w| w.as_u64()).unwrap_or(0);
                let port = data.get("port").and_then(|p| p.as_u64()).unwrap_or(0);
                let target = data.get("target").and_then(|t| t.as_str()).unwrap_or("");
                serde_json::json!({
                    "priority": priority,
                    "weight": weight,
                    "port": port,
                    "target": target,
                })
            } else {
                serde_json::json!({ "value": content })
            }
        }
        "CAA" => {
            if let Some(data) = cf_record.get("data") {
                let flags = data.get("flags").and_then(|f| f.as_u64()).unwrap_or(0);
                let tag = data.get("tag").and_then(|t| t.as_str()).unwrap_or("");
                let value = data.get("value").and_then(|v| v.as_str()).unwrap_or("");
                serde_json::json!({ "flags": flags, "tag": tag, "value": value })
            } else {
                serde_json::json!({ "value": content })
            }
        }
        _ => serde_json::json!({ "value": content }),
    }
}

fn cloudflare_record_to_zone_record(cf: &Value, zone_name: &str) -> ZoneRecord {
    let record_type = cf
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("UNKNOWN")
        .to_uppercase();
    let cf_name = cf.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let name = extract_relative_name(cf_name, zone_name);
    let ttl = cf.get("ttl").and_then(|t| t.as_u64()).unwrap_or(0) as u32;
    let content = cf.get("content").and_then(|c| c.as_str()).unwrap_or("");
    let proxied = cf.get("proxied").and_then(|p| p.as_bool()).unwrap_or(false);
    let comment = cf
        .get("comment")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string();
    let cf_id = cf
        .get("id")
        .and_then(|i| i.as_str())
        .unwrap_or("")
        .to_string();

    let mut data = normalize_rdata(&record_type, content, cf);
    if let Some(obj) = data.as_object_mut() {
        obj.insert("proxied".into(), Value::Bool(proxied));
        if !cf_id.is_empty() {
            obj.insert("id".into(), Value::String(cf_id));
        }
    }

    ZoneRecord {
        name,
        record_type,
        ttl,
        disabled: false,
        comments: comment,
        expiry_ttl: 0,
        data,
        parsed: None,
    }
}

fn record_data_to_cloudflare_body(name: &str, ttl: u32, record: &RecordData) -> Value {
    let record_type = record.type_name();
    match record {
        RecordData::A { ip } => serde_json::json!({
            "name": name, "type": record_type,
            "content": ip.to_string(), "ttl": ttl, "proxied": false,
        }),
        RecordData::Aaaa { ip } => serde_json::json!({
            "name": name, "type": record_type,
            "content": ip.to_string(), "ttl": ttl, "proxied": false,
        }),
        RecordData::Cname { target } => serde_json::json!({
            "name": name, "type": record_type,
            "content": target, "ttl": ttl, "proxied": false,
        }),
        RecordData::Mx { preference, exchange } => serde_json::json!({
            "name": name, "type": record_type,
            "content": exchange, "priority": preference, "ttl": ttl,
        }),
        RecordData::Txt { text, .. } => serde_json::json!({
            "name": name, "type": record_type,
            "content": text, "ttl": ttl,
        }),
        RecordData::Ns { nameserver, .. } => serde_json::json!({
            "name": name, "type": record_type,
            "content": nameserver, "ttl": ttl,
        }),
        RecordData::Ptr { name: ptr_name } => serde_json::json!({
            "name": name, "type": record_type,
            "content": ptr_name, "ttl": ttl,
        }),
        RecordData::Srv { priority, weight, port, target } => serde_json::json!({
            "name": name, "type": record_type,
            "data": { "priority": priority, "weight": weight, "port": port, "target": target },
            "ttl": ttl,
        }),
        RecordData::Caa { flags, tag, value } => serde_json::json!({
            "name": name, "type": record_type,
            "data": { "flags": flags, "tag": tag, "value": value },
            "ttl": ttl,
        }),
        _ => {
            let params = record.to_api_params();
            let content = params
                .iter()
                .find(|(k, _)| *k != "type")
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            serde_json::json!({
                "name": name, "type": record_type,
                "content": content, "ttl": ttl,
            })
        }
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
            zone_import: false,
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
    #[instrument(skip(self, record), fields(vendor = "cloudflare", operation = "add_record"))]
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

    #[instrument(skip(self, type_params), fields(vendor = "cloudflare", operation = "delete_record"))]
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
                &[
                    ("name", fqdn.clone()),
                    ("type", record_type.to_string()),
                ],
            )
            .await?;

        let records = data
            .as_array()
            .ok_or_else(|| Error::parse("Cloudflare dns_records response is not an array"))?;

        let record_id = records
            .first()
            .and_then(|r| r.get("id"))
            .and_then(|id| id.as_str())
            .ok_or_else(|| Error::Api {
                message: format!("no {record_type} record found for '{fqdn}'"),
            })?
            .to_owned();

        self.delete(&format!("/zones/{zone_id}/dns_records/{record_id}"))
            .await
    }
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
    async fn import_zone_file<'a>(
        &'a self,
        _zone: &'a str,
        _file_name: String,
        _file_bytes: Vec<u8>,
        _overwrite: bool,
        _overwrite_zone: bool,
        _overwrite_soa_serial: bool,
    ) -> Result<Value> {
        Err(Error::unsupported("Cloudflare", "zone import"))
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
        assert!(!caps.zone_import);
    }

    // ── Unsupported operations return correct error ────────────────────────────

    #[tokio::test]
    async fn enable_zone_is_unsupported() {
        let err = make_client().enable_zone("example.com").await.unwrap_err();
        assert!(matches!(err, Error::Unsupported { vendor: "Cloudflare", .. }));
    }

    #[tokio::test]
    async fn disable_zone_is_unsupported() {
        let err = make_client().disable_zone("example.com").await.unwrap_err();
        assert!(matches!(err, Error::Unsupported { vendor: "Cloudflare", .. }));
    }

    #[tokio::test]
    async fn list_cache_is_unsupported() {
        let err = make_client().list_cache("example.com").await.unwrap_err();
        assert!(matches!(err, Error::Unsupported { vendor: "Cloudflare", .. }));
    }

    #[tokio::test]
    async fn flush_cache_is_unsupported() {
        let err = make_client().flush_cache().await.unwrap_err();
        assert!(matches!(err, Error::Unsupported { vendor: "Cloudflare", .. }));
    }

    #[tokio::test]
    async fn get_stats_is_unsupported() {
        let err = make_client().get_stats("last7days").await.unwrap_err();
        assert!(matches!(err, Error::Unsupported { vendor: "Cloudflare", .. }));
    }

    #[tokio::test]
    async fn list_blocked_is_unsupported() {
        let err = make_client().list_blocked().await.unwrap_err();
        assert!(matches!(err, Error::Unsupported { vendor: "Cloudflare", .. }));
    }

    #[tokio::test]
    async fn zone_import_is_unsupported() {
        let err = make_client()
            .import_zone_file("example.com", "zone.txt".into(), vec![], false, false, false)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Unsupported { vendor: "Cloudflare", .. }));
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
        let record = RecordData::A { ip: "1.2.3.4".parse().unwrap() };
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
}
