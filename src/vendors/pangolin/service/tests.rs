use super::*;
use serde_json::json;

use crate::core::dns::names::relative_to_zone;
use crate::vendors::pangolin::mapping::{
    dns_record_to_zone_record, parse_dns_records, parse_domains, parse_resources,
    resource_to_zone_record,
};
use crate::vendors::pangolin::responses::{PangolinDnsRecord, PangolinResource};

// ── relative_to_zone ──────────────────────────────────────────────────────

#[test]
fn apex_returns_at() {
    assert_eq!(relative_to_zone("app.hankin.io", "app.hankin.io"), "@");
}

#[test]
fn single_label_subdomain() {
    assert_eq!(
        relative_to_zone("grafana.app.hankin.io", "app.hankin.io"),
        "grafana"
    );
}

#[test]
fn multi_label_subdomain() {
    assert_eq!(
        relative_to_zone("a.b.app.hankin.io", "app.hankin.io"),
        "a.b"
    );
}

#[test]
fn case_insensitive_stripping() {
    assert_eq!(
        relative_to_zone("Grafana.App.Hankin.IO", "app.hankin.io"),
        "Grafana"
    );
}

#[test]
fn unrelated_domain_returned_as_is() {
    assert_eq!(
        relative_to_zone("other.example.com", "app.hankin.io"),
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
