//! Cloudflare-specific DNS record mapping and normalization.
//!
//! Cloudflare's API uses its own JSON payload shapes that differ from the
//! vendor-neutral `core::dns` types. The functions here translate between
//! Cloudflare's format and internal zone-record representations.

use serde_json::Value;

use crate::core::dns::{names::relative_to_zone, records::RecordData, responses::ZoneRecord};

// ─── SSHFP ─────────────────────────────────────────────────────────────────

pub fn sshfp_algorithm_to_str(n: u64) -> &'static str {
    match n {
        1 => "RSA",
        2 => "DSA",
        3 => "ECDSA",
        4 => "Ed25519",
        6 => "Ed448",
        _ => "RSA",
    }
}

pub fn sshfp_algorithm_to_num(alg: &crate::core::dns::records::SshfpAlgorithm) -> u8 {
    use crate::core::dns::records::SshfpAlgorithm::*;
    match alg {
        Rsa => 1,
        Dsa => 2,
        Ecdsa => 3,
        Ed25519 => 4,
        Ed448 => 6,
    }
}

pub fn sshfp_fp_type_to_str(n: u64) -> &'static str {
    match n {
        1 => "SHA1",
        2 => "SHA256",
        _ => "SHA256",
    }
}

pub fn sshfp_fp_type_to_num(ft: &crate::core::dns::records::SshfpFingerprintType) -> u8 {
    use crate::core::dns::records::SshfpFingerprintType::*;
    match ft {
        Sha1 => 1,
        Sha256 => 2,
    }
}

// ─── TLSA ──────────────────────────────────────────────────────────────────

pub fn tlsa_cert_usage_to_num(cu: &crate::core::dns::records::TlsaCertUsage) -> u8 {
    use crate::core::dns::records::TlsaCertUsage::*;
    match cu {
        PkixTa => 0,
        PkixEe => 1,
        DaneTa => 2,
        DaneEe => 3,
    }
}

pub fn tlsa_cert_usage_to_str(n: u64) -> &'static str {
    match n {
        0 => "PKIX-TA",
        1 => "PKIX-EE",
        2 => "DANE-TA",
        3 => "DANE-EE",
        _ => "DANE-EE",
    }
}

pub fn tlsa_selector_to_num(s: &crate::core::dns::records::TlsaSelector) -> u8 {
    use crate::core::dns::records::TlsaSelector::*;
    match s {
        Cert => 0,
        Spki => 1,
    }
}

pub fn tlsa_selector_to_str(n: u64) -> &'static str {
    match n {
        0 => "Cert",
        1 => "SPKI",
        _ => "Cert",
    }
}

pub fn tlsa_matching_type_to_num(mt: &crate::core::dns::records::TlsaMatchingType) -> u8 {
    use crate::core::dns::records::TlsaMatchingType::*;
    match mt {
        Full => 0,
        Sha2_256 => 1,
        Sha2_512 => 2,
    }
}

pub fn tlsa_matching_type_to_str(n: u64) -> &'static str {
    match n {
        0 => "Full",
        1 => "SHA2-256",
        2 => "SHA2-512",
        _ => "Full",
    }
}

// ─── DS ────────────────────────────────────────────────────────────────────

pub fn ds_algorithm_to_num(alg: &crate::core::dns::records::DsAlgorithm) -> u8 {
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

pub fn ds_algorithm_to_str(n: u64) -> &'static str {
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

pub fn ds_digest_type_to_num(dt: &crate::core::dns::records::DigestType) -> u8 {
    use crate::core::dns::records::DigestType::*;
    match dt {
        Sha1 => 1,
        Sha256 => 2,
        GostR341194 => 3,
        Sha384 => 4,
    }
}

pub fn ds_digest_type_to_str(n: u64) -> &'static str {
    match n {
        1 => "SHA1",
        2 => "SHA256",
        3 => "GOST-R-34-11-94",
        4 => "SHA384",
        _ => "SHA256",
    }
}

// ─── rData normalization (Cloudflare → internal) ───────────────────────────

pub fn normalize_rdata(record_type: &str, content: &str, cf_record: &Value) -> Value {
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
                let matching_type = data
                    .get("matching_type")
                    .and_then(|m| m.as_u64())
                    .unwrap_or(1);
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
                let algorithm = data.get("algorithm").and_then(|a| a.as_u64()).unwrap_or(13);
                let digest_type = data
                    .get("digest_type")
                    .and_then(|d| d.as_u64())
                    .unwrap_or(2);
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
                let priority = data.get("priority").and_then(|p| p.as_u64()).unwrap_or(1);
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
                let preference = data
                    .get("preference")
                    .and_then(|p| p.as_u64())
                    .unwrap_or(10);
                let flags = data.get("flags").and_then(|f| f.as_str()).unwrap_or("");
                let services = data.get("service").and_then(|s| s.as_str()).unwrap_or("");
                let regexp = data.get("regexp").and_then(|r| r.as_str()).unwrap_or("");
                let replacement = data
                    .get("replacement")
                    .and_then(|r| r.as_str())
                    .unwrap_or(".");
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
                let priority = data.get("priority").and_then(|p| p.as_u64()).unwrap_or(10);
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

// ─── Record conversion ─────────────────────────────────────────────────────

pub fn cloudflare_record_to_zone_record(cf: &Value, zone_name: &str) -> ZoneRecord {
    let record_type = cf
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("UNKNOWN")
        .to_uppercase();
    let cf_name = cf.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let name = relative_to_zone(cf_name, zone_name);
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

pub fn record_data_to_cloudflare_body(name: &str, ttl: u32, record: &RecordData) -> Value {
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
        RecordData::Mx {
            preference,
            exchange,
        } => serde_json::json!({
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
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => serde_json::json!({
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
        RecordData::Sshfp {
            algorithm,
            fingerprint_type,
            fingerprint,
        } => serde_json::json!({
            "name": name, "type": record_type,
            "data": {
                "algorithm": sshfp_algorithm_to_num(algorithm),
                "type": sshfp_fp_type_to_num(fingerprint_type),
                "fingerprint": fingerprint,
            },
            "ttl": ttl,
        }),
        RecordData::Tlsa {
            cert_usage,
            selector,
            matching_type,
            cert_association_data,
        } => serde_json::json!({
            "name": name, "type": record_type,
            "data": {
                "usage": tlsa_cert_usage_to_num(cert_usage),
                "selector": tlsa_selector_to_num(selector),
                "matching_type": tlsa_matching_type_to_num(matching_type),
                "certificate": cert_association_data,
            },
            "ttl": ttl,
        }),
        RecordData::Ds {
            key_tag,
            algorithm,
            digest_type,
            digest,
        } => serde_json::json!({
            "name": name, "type": record_type,
            "data": {
                "key_tag": key_tag,
                "algorithm": ds_algorithm_to_num(algorithm),
                "digest_type": ds_digest_type_to_num(digest_type),
                "digest": digest,
            },
            "ttl": ttl,
        }),
        RecordData::Https {
            svc_priority,
            svc_target_name,
            svc_params,
            ..
        }
        | RecordData::Svcb {
            svc_priority,
            svc_target_name,
            svc_params,
            ..
        } => serde_json::json!({
            "name": name, "type": record_type,
            "data": {
                "priority": svc_priority,
                "target": svc_target_name,
                "value": svc_params,
            },
            "ttl": ttl,
        }),
        RecordData::Naptr {
            order,
            preference,
            flags,
            services,
            regexp,
            replacement,
        } => serde_json::json!({
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
        RecordData::Uri {
            priority,
            weight,
            uri,
        } => serde_json::json!({
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
