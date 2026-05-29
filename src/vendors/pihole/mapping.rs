//! Pi-hole DNS record mapping and normalization.
//!
//! Pi-hole v6 local DNS records are simple hostname → IP mappings stored as A/AAAA
//! entries, plus a separate CNAME list.  This module converts Pi-hole API payloads
//! to vendor-neutral `ZoneRecord` values.

use serde_json::Value;

use crate::core::dns::names::relative_to_zone;
use crate::core::dns::records::RecordData;
use crate::core::dns::responses::ZoneRecord;

const LOCAL_ZONE: &str = "local";

/// Convert a Pi-hole local DNS entry (`{"ip": "...", "host": "..."}`) to a
/// vendor-neutral `ZoneRecord`.
pub fn local_dns_to_zone_record(entry: &Value, zone_name: &str) -> ZoneRecord {
    let host = entry.get("host").and_then(|h| h.as_str()).unwrap_or("");
    let ip = entry.get("ip").and_then(|i| i.as_str()).unwrap_or("");
    let name = relative_to_zone(host, zone_name);

    let (record_type, data) = if ip.contains(':') {
        ("AAAA", serde_json::json!({ "ipAddress": ip }))
    } else {
        ("A", serde_json::json!({ "ipAddress": ip }))
    };

    ZoneRecord {
        name,
        record_type: record_type.to_string(),
        ttl: 0,
        disabled: false,
        comments: String::new(),
        expiry_ttl: 0,
        data,
        parsed: None,
    }
}

/// Convert a Pi-hole local CNAME entry (`{"domain": "...", "target": "..."}`) to a
/// vendor-neutral `ZoneRecord`.
pub fn local_cname_to_zone_record(entry: &Value, zone_name: &str) -> ZoneRecord {
    let domain = entry.get("domain").and_then(|d| d.as_str()).unwrap_or("");
    let target = entry.get("target").and_then(|t| t.as_str()).unwrap_or("");
    let name = relative_to_zone(domain, zone_name);

    ZoneRecord {
        name,
        record_type: "CNAME".to_string(),
        ttl: 0,
        disabled: false,
        comments: String::new(),
        expiry_ttl: 0,
        data: serde_json::json!({ "cname": target }),
        parsed: None,
    }
}

/// Build the JSON body for a Pi-hole local DNS POST/DELETE request.
///
/// Pi-hole only supports A and AAAA records in local DNS (hostname → IP
/// mappings); CNAME records use a separate endpoint.
pub fn record_data_to_local_dns_body(domain: &str, record: &RecordData) -> Option<Value> {
    match record {
        RecordData::A { ip } => Some(serde_json::json!({ "ip": ip.to_string(), "host": domain })),
        RecordData::Aaaa { ip } => {
            Some(serde_json::json!({ "ip": ip.to_string(), "host": domain }))
        }
        RecordData::Cname { target } => {
            Some(serde_json::json!({ "domain": domain, "target": target }))
        }
        _ => None,
    }
}

/// Infer a synthetic zone name from a hostname by taking the last two labels.
/// Falls back to `"local"` for bare hostnames or errors.
pub fn infer_zone(host: &str) -> String {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        LOCAL_ZONE.to_string()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_record_mapping() {
        let entry = json!({"ip": "192.168.1.1", "host": "server.home.lan"});
        let rec = local_dns_to_zone_record(&entry, "home.lan");
        assert_eq!(rec.name, "server");
        assert_eq!(rec.record_type, "A");
        assert_eq!(rec.data["ipAddress"], "192.168.1.1");
        assert!(!rec.disabled);
    }

    #[test]
    fn aaaa_record_mapping() {
        let entry = json!({"ip": "::1", "host": "server.home.lan"});
        let rec = local_dns_to_zone_record(&entry, "home.lan");
        assert_eq!(rec.record_type, "AAAA");
        assert_eq!(rec.data["ipAddress"], "::1");
    }

    #[test]
    fn apex_host_becomes_at() {
        let entry = json!({"ip": "192.168.1.1", "host": "home.lan"});
        let rec = local_dns_to_zone_record(&entry, "home.lan");
        assert_eq!(rec.name, "@");
    }

    #[test]
    fn cname_record_mapping() {
        let entry = json!({"domain": "alias.home.lan", "target": "server.home.lan"});
        let rec = local_cname_to_zone_record(&entry, "home.lan");
        assert_eq!(rec.name, "alias");
        assert_eq!(rec.record_type, "CNAME");
        assert_eq!(rec.data["cname"], "server.home.lan");
    }

    #[test]
    fn a_record_body() {
        use std::net::Ipv4Addr;
        let record = RecordData::A {
            ip: Ipv4Addr::new(10, 0, 0, 1).into(),
        };
        let body = record_data_to_local_dns_body("myhost.local", &record).unwrap();
        assert_eq!(body["ip"], "10.0.0.1");
        assert_eq!(body["host"], "myhost.local");
    }

    #[test]
    fn cname_body() {
        let record = RecordData::Cname {
            target: "canonical.local".into(),
        };
        let body = record_data_to_local_dns_body("alias.local", &record).unwrap();
        assert_eq!(body["domain"], "alias.local");
        assert_eq!(body["target"], "canonical.local");
    }

    #[test]
    fn unsupported_record_type_returns_none() {
        let record = RecordData::Mx {
            preference: 10,
            exchange: "mail.example.com".into(),
        };
        assert!(record_data_to_local_dns_body("example.com", &record).is_none());
    }

    #[test]
    fn infer_zone_two_label_host() {
        assert_eq!(infer_zone("server.home.lan"), "home.lan");
    }

    #[test]
    fn infer_zone_bare_host_falls_back() {
        assert_eq!(infer_zone("server"), "local");
    }

    #[test]
    fn extract_relative_name_subdomain() {
        assert_eq!(
            relative_to_zone("sub.example.com", "example.com"),
            "sub"
        );
    }

    #[test]
    fn extract_relative_name_apex() {
        assert_eq!(relative_to_zone("example.com", "example.com"), "@");
    }

    #[test]
    fn extract_relative_name_non_matching() {
        assert_eq!(relative_to_zone("other.net", "example.com"), "other.net");
    }
}
