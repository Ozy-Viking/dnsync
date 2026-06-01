//! core RecordData -> Cloudflare API request body.

use super::*;

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
