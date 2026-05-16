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

// ─── Numeric ↔ string conversions for Cloudflare data objects ────────────────

fn sshfp_algorithm_to_str(n: u64) -> &'static str {
    match n {
        1 => "RSA",
        2 => "DSA",
        3 => "ECDSA",
        4 => "Ed25519",
        6 => "Ed448",
        _ => "RSA",
    }
}

fn sshfp_algorithm_to_num(alg: &crate::core::dns::records::SshfpAlgorithm) -> u8 {
    use crate::core::dns::records::SshfpAlgorithm::*;
    match alg {
        Rsa => 1,
        Dsa => 2,
        Ecdsa => 3,
        Ed25519 => 4,
        Ed448 => 6,
    }
}

fn sshfp_fp_type_to_str(n: u64) -> &'static str {
    match n {
        1 => "SHA1",
        2 => "SHA256",
        _ => "SHA256",
    }
}

fn sshfp_fp_type_to_num(ft: &crate::core::dns::records::SshfpFingerprintType) -> u8 {
    use crate::core::dns::records::SshfpFingerprintType::*;
    match ft {
        Sha1 => 1,
        Sha256 => 2,
    }
}

fn tlsa_cert_usage_to_num(cu: &crate::core::dns::records::TlsaCertUsage) -> u8 {
    use crate::core::dns::records::TlsaCertUsage::*;
    match cu {
        PkixTa => 0,
        PkixEe => 1,
        DaneTa => 2,
        DaneEe => 3,
    }
}

fn tlsa_cert_usage_to_str(n: u64) -> &'static str {
    match n {
        0 => "PKIX-TA",
        1 => "PKIX-EE",
        2 => "DANE-TA",
        3 => "DANE-EE",
        _ => "DANE-EE",
    }
}

fn tlsa_selector_to_num(s: &crate::core::dns::records::TlsaSelector) -> u8 {
    use crate::core::dns::records::TlsaSelector::*;
    match s {
        Cert => 0,
        Spki => 1,
    }
}

fn tlsa_selector_to_str(n: u64) -> &'static str {
    match n {
        0 => "Cert",
        1 => "SPKI",
        _ => "Cert",
    }
}

fn tlsa_matching_type_to_num(mt: &crate::core::dns::records::TlsaMatchingType) -> u8 {
    use crate::core::dns::records::TlsaMatchingType::*;
    match mt {
        Full => 0,
        Sha2_256 => 1,
        Sha2_512 => 2,
    }
}

fn tlsa_matching_type_to_str(n: u64) -> &'static str {
    match n {
        0 => "Full",
        1 => "SHA2-256",
        2 => "SHA2-512",
        _ => "Full",
    }
}

fn ds_algorithm_to_num(alg: &crate::core::dns::records::DsAlgorithm) -> u8 {
    use crate::core::dns::records::DsAlgorithm::*;
    match alg {
        Rsamd5 => 1,
        Dsa => 3,
        Rsasha1 => 5,
        DsaNsec3Sha1 => 6,
        Rsasha1Nsec3Sha1 => 7,
        Rsasha256 => 8,
        Rsasha512 => 10,
        EccGost => 12,
        Ecdsap256sha256 => 13,
        Ecdsap384sha384 => 14,
        Ed25519 => 15,
        Ed448 => 16,
    }
}

fn ds_algorithm_to_str(n: u64) -> &'static str {
    match n {
        1 => "RSAMD5",
        3 => "DSA",
        5 => "RSASHA1",
        6 => "DSA-NSEC3-SHA1",
        7 => "RSASHA1-NSEC3-SHA1",
        8 => "RSASHA256",
        10 => "RSASHA512",
        12 => "ECC-GOST",
        13 => "ECDSAP256SHA256",
        14 => "ECDSAP384SHA384",
        15 => "ED25519",
        16 => "ED448",
        _ => "RSASHA256",
    }
}

fn ds_digest_type_to_num(dt: &crate::core::dns::records::DigestType) -> u8 {
    use crate::core::dns::records::DigestType::*;
    match dt {
        Sha1 => 1,
        Sha256 => 2,
        GostR341194 => 3,
        Sha384 => 4,
    }
}

fn ds_digest_type_to_str(n: u64) -> &'static str {
    match n {
        1 => "SHA1",
        2 => "SHA256",
        3 => "GOST-R-34-11-94",
        4 => "SHA384",
        _ => "SHA256",
    }
}

// ─── rData normalization (Cloudflare → internal) ──────────────────────────────

fn normalize_rdata(record_type: &str, content: &str, cf_record: &Value) -> Value {
    match record_type {
        "A" | "AAAA" => serde_json::json!({ "ipAddress": content }),
        "CNAME" => serde_json::json!({ "cname": content }),
        "DNAME" => serde_json::json!({ "dname": content }),
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
        "SSHFP" => {
            if let Some(data) = cf_record.get("data") {
                let alg = data.get("algorithm").and_then(|a| a.as_u64()).unwrap_or(1);
                let fp_type = data.get("type").and_then(|t| t.as_u64()).unwrap_or(2);
                let fingerprint = data
                    .get("fingerprint")
                    .and_then(|f| f.as_str())
                    .unwrap_or("");
                serde_json::json!({
                    "sshfpAlgorithm": sshfp_algorithm_to_str(alg),
                    "sshfpFingerprintType": sshfp_fp_type_to_str(fp_type),
                    "sshfpFingerprint": fingerprint,
                })
            } else {
                serde_json::json!({ "value": content })
            }
        }
        "TLSA" => {
            if let Some(data) = cf_record.get("data") {
                let usage = data.get("usage").and_then(|u| u.as_u64()).unwrap_or(3);
                let selector = data.get("selector").and_then(|s| s.as_u64()).unwrap_or(1);
                let matching_type =
                    data.get("matching_type").and_then(|m| m.as_u64()).unwrap_or(1);
                let certificate = data
                    .get("certificate")
                    .and_then(|c| c.as_str())
                    .unwrap_or("");
                serde_json::json!({
                    "tlsaCertificateUsage": tlsa_cert_usage_to_str(usage),
                    "tlsaSelector": tlsa_selector_to_str(selector),
                    "tlsaMatchingType": tlsa_matching_type_to_str(matching_type),
                    "tlsaCertificateAssociationData": certificate,
                })
            } else {
                serde_json::json!({ "value": content })
            }
        }
        "DS" => {
            if let Some(data) = cf_record.get("data") {
                let key_tag = data.get("key_tag").and_then(|k| k.as_u64()).unwrap_or(0);
                let algorithm =
                    data.get("algorithm").and_then(|a| a.as_u64()).unwrap_or(13);
                let digest_type =
                    data.get("digest_type").and_then(|d| d.as_u64()).unwrap_or(2);
                let digest = data.get("digest").and_then(|d| d.as_str()).unwrap_or("");
                serde_json::json!({
                    "keyTag": key_tag,
                    "algorithm": ds_algorithm_to_str(algorithm),
                    "digestType": ds_digest_type_to_str(digest_type),
                    "digest": digest,
                })
            } else {
                serde_json::json!({ "value": content })
            }
        }
        "HTTPS" | "SVCB" => {
            if let Some(data) = cf_record.get("data") {
                let priority =
                    data.get("priority").and_then(|p| p.as_u64()).unwrap_or(1);
                let target = data.get("target").and_then(|t| t.as_str()).unwrap_or(".");
                let params = data.get("value").and_then(|v| v.as_str());
                serde_json::json!({
                    "svcPriority": priority,
                    "svcTargetName": target,
                    "svcParams": params,
                    "autoIpv4Hint": false,
                    "autoIpv6Hint": false,
                })
            } else {
                serde_json::json!({ "value": content })
            }
        }
        "NAPTR" => {
            if let Some(data) = cf_record.get("data") {
                let order = data.get("order").and_then(|o| o.as_u64()).unwrap_or(100);
                let preference =
                    data.get("preference").and_then(|p| p.as_u64()).unwrap_or(10);
                let flags = data.get("flags").and_then(|f| f.as_str()).unwrap_or("");
                let services = data.get("service").and_then(|s| s.as_str()).unwrap_or("");
                let regexp = data.get("regexp").and_then(|r| r.as_str()).unwrap_or("");
                let replacement =
                    data.get("replacement").and_then(|r| r.as_str()).unwrap_or(".");
                serde_json::json!({
                    "naptrOrder": order,
                    "naptrPreference": preference,
                    "naptrFlags": flags,
                    "naptrServices": services,
                    "naptrRegexp": regexp,
                    "naptrReplacement": replacement,
                })
            } else {
                serde_json::json!({ "value": content })
            }
        }
        "URI" => {
            if let Some(data) = cf_record.get("data") {
                let priority =
                    data.get("priority").and_then(|p| p.as_u64()).unwrap_or(10);
                let weight = data.get("weight").and_then(|w| w.as_u64()).unwrap_or(1);
                let uri = data.get("content").and_then(|c| c.as_str()).unwrap_or("");
                serde_json::json!({
                    "uriPriority": priority,
                    "uriWeight": weight,
                    "uri": uri,
                })
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
        RecordData::Dname { dname } => serde_json::json!({
            "name": name, "type": record_type,
            "content": dname, "ttl": ttl,
        }),
        RecordData::Sshfp { algorithm, fingerprint_type, fingerprint } => serde_json::json!({
            "name": name, "type": record_type,
            "data": {
                "algorithm": sshfp_algorithm_to_num(algorithm),
                "type": sshfp_fp_type_to_num(fingerprint_type),
                "fingerprint": fingerprint,
            },
            "ttl": ttl,
        }),
        RecordData::Tlsa { cert_usage, selector, matching_type, cert_association_data } => serde_json::json!({
            "name": name, "type": record_type,
            "data": {
                "usage": tlsa_cert_usage_to_num(cert_usage),
                "selector": tlsa_selector_to_num(selector),
                "matching_type": tlsa_matching_type_to_num(matching_type),
                "certificate": cert_association_data,
            },
            "ttl": ttl,
        }),
        RecordData::Ds { key_tag, algorithm, digest_type, digest } => serde_json::json!({
            "name": name, "type": record_type,
            "data": {
                "key_tag": key_tag,
                "algorithm": ds_algorithm_to_num(algorithm),
                "digest_type": ds_digest_type_to_num(digest_type),
                "digest": digest,
            },
            "ttl": ttl,
        }),
        RecordData::Https { svc_priority, svc_target_name, svc_params, .. }
        | RecordData::Svcb { svc_priority, svc_target_name, svc_params, .. } => serde_json::json!({
            "name": name, "type": record_type,
            "data": {
                "priority": svc_priority,
                "target": svc_target_name,
                "value": svc_params,
            },
            "ttl": ttl,
        }),
        RecordData::Naptr { order, preference, flags, services, regexp, replacement } => serde_json::json!({
            "name": name, "type": record_type,
            "data": {
                "order": order,
                "preference": preference,
                "flags": flags,
                "service": services,
                "regexp": regexp,
                "replacement": replacement,
            },
            "ttl": ttl,
        }),
        RecordData::Uri { priority, weight, uri } => serde_json::json!({
            "name": name, "type": record_type,
            "data": { "priority": priority, "weight": weight, "content": uri },
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
    fn aaaa_record_body() {
        let record = RecordData::Aaaa { ip: "2001:db8::1".parse().unwrap() };
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
        let record = RecordData::Dname { dname: "other.example.com".into() };
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
}
