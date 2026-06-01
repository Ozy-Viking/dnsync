//! Cloudflare rdata normalization and record->zone-record mapping.

use super::*;

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
