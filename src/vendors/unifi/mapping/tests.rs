use super::*;
use serde_json::json;

fn a_policy() -> UnifiDnsPolicy {
    serde_json::from_value(json!({
        "id": "p1",
        "type": "A_RECORD",
        "enabled": true,
        "domain": "www.example.com",
        "ipv4Address": "192.168.1.10",
        "ttlSeconds": 300
    }))
    .unwrap()
}

fn disabled_aaaa_policy() -> UnifiDnsPolicy {
    serde_json::from_value(json!({
        "id": "p2",
        "type": "AAAA_RECORD",
        "enabled": false,
        "domain": "v6.example.com",
        "ipv6Address": "2001:db8::1",
        "ttlSeconds": 600
    }))
    .unwrap()
}

fn cname_policy() -> UnifiDnsPolicy {
    serde_json::from_value(json!({
        "id": "p3",
        "type": "CNAME_RECORD",
        "enabled": true,
        "domain": "alias.example.com",
        "targetDomain": "www.example.com",
        "ttlSeconds": 60
    }))
    .unwrap()
}

fn forward_policy() -> UnifiDnsPolicy {
    serde_json::from_value(json!({
        "id": "p4",
        "type": "FORWARD_DOMAIN",
        "enabled": true,
        "domain": "lan.example.com",
        "ipAddress": "192.168.1.1"
    }))
    .unwrap()
}

// ── policy_to_zone_record ───────────────────────────────────────────────

#[test]
fn a_record_normalises_to_ip_address() {
    let rec = policy_to_zone_record(&a_policy(), "example.com");
    assert_eq!(rec.name, "www");
    assert_eq!(rec.record_type, "A");
    assert_eq!(rec.ttl, 300);
    assert!(!rec.disabled);
    assert_eq!(rec.data["ipAddress"], "192.168.1.10");
    assert_eq!(rec.data["id"], "p1");
    assert_eq!(rec.data["enabled"], true);
    assert_eq!(rec.data["unifiType"], "A_RECORD");
}

#[test]
fn disabled_policy_maps_to_disabled_record() {
    let rec = policy_to_zone_record(&disabled_aaaa_policy(), "example.com");
    assert!(rec.disabled);
    assert_eq!(rec.data["enabled"], false);
    assert_eq!(rec.data["ipAddress"], "2001:db8::1");
    assert_eq!(rec.record_type, "AAAA");
}

#[test]
fn cname_record_maps_to_cname_field() {
    let rec = policy_to_zone_record(&cname_policy(), "example.com");
    assert_eq!(rec.name, "alias");
    assert_eq!(rec.record_type, "CNAME");
    assert_eq!(rec.data["cname"], "www.example.com");
}

#[test]
fn mx_record_normalises_priority_to_preference() {
    let mx: UnifiDnsPolicy = serde_json::from_value(json!({
        "id": "p5", "type": "MX_RECORD", "enabled": true,
        "domain": "example.com",
        "mailServerDomain": "mail.example.com",
        "priority": 10
    }))
    .unwrap();
    let rec = policy_to_zone_record(&mx, "example.com");
    assert_eq!(rec.record_type, "MX");
    assert_eq!(rec.data["preference"], 10);
    assert_eq!(rec.data["exchange"], "mail.example.com");
}

#[test]
fn txt_record_includes_split_text_default() {
    let txt: UnifiDnsPolicy = serde_json::from_value(json!({
        "id": "p6", "type": "TXT_RECORD", "enabled": true,
        "domain": "_acme.example.com",
        "text": "challenge"
    }))
    .unwrap();
    let rec = policy_to_zone_record(&txt, "example.com");
    assert_eq!(rec.data["text"], "challenge");
    assert_eq!(rec.data["splitText"], false);
}

#[test]
fn srv_record_includes_all_components() {
    let srv: UnifiDnsPolicy = serde_json::from_value(json!({
        "id": "p7", "type": "SRV_RECORD", "enabled": true,
        "domain": "_sip._tcp.example.com",
        "serverDomain": "sip.example.com",
        "service": "_sip", "protocol": "_tcp",
        "port": 5060, "priority": 10, "weight": 20
    }))
    .unwrap();
    let rec = policy_to_zone_record(&srv, "example.com");
    assert_eq!(rec.record_type, "SRV");
    assert_eq!(rec.data["priority"], 10);
    assert_eq!(rec.data["weight"], 20);
    assert_eq!(rec.data["port"], 5060);
    assert_eq!(rec.data["target"], "sip.example.com");
}

#[test]
fn forward_domain_keeps_provider_metadata() {
    let rec = policy_to_zone_record(&forward_policy(), "example.com");
    assert_eq!(rec.record_type, "FORWARD_DOMAIN");
    assert_eq!(rec.data["ipAddress"], "192.168.1.1");
    assert_eq!(rec.data["forwardDomain"], "lan.example.com");
    assert_eq!(rec.data["providerType"], "FORWARD_DOMAIN");
}

// ── record_data_to_unifi_body ───────────────────────────────────────────

#[test]
fn a_body_uses_ipv4_address_field() {
    let body = record_data_to_unifi_body(
        "www.example.com",
        300,
        true,
        &RecordData::A {
            ip: "1.2.3.4".parse().unwrap(),
        },
    )
    .unwrap();
    assert_eq!(body["type"], "A_RECORD");
    assert_eq!(body["enabled"], true);
    assert_eq!(body["domain"], "www.example.com");
    assert_eq!(body["ipv4Address"], "1.2.3.4");
    assert_eq!(body["ttlSeconds"], 300);
}

#[test]
fn aaaa_body_uses_ipv6_address_field() {
    let body = record_data_to_unifi_body(
        "v6.example.com",
        120,
        true,
        &RecordData::Aaaa {
            ip: "2001:db8::1".parse().unwrap(),
        },
    )
    .unwrap();
    assert_eq!(body["type"], "AAAA_RECORD");
    assert_eq!(body["ipv6Address"], "2001:db8::1");
}

#[test]
fn mx_body_uses_mail_server_domain_and_priority() {
    let body = record_data_to_unifi_body(
        "example.com",
        300,
        true,
        &RecordData::Mx {
            exchange: "mail.example.com".into(),
            preference: 10,
        },
    )
    .unwrap();
    assert_eq!(body["type"], "MX_RECORD");
    assert_eq!(body["mailServerDomain"], "mail.example.com");
    assert_eq!(body["priority"], 10);
    assert_eq!(body["ttlSeconds"], 300);
}

#[test]
fn srv_body_extracts_service_and_protocol_labels() {
    let body = record_data_to_unifi_body(
        "_sip._tcp.example.com",
        300,
        true,
        &RecordData::Srv {
            target: "sip.example.com".into(),
            port: 5060,
            priority: 10,
            weight: 20,
        },
    )
    .unwrap();
    assert_eq!(body["type"], "SRV_RECORD");
    assert_eq!(body["service"], "_sip");
    assert_eq!(body["protocol"], "_tcp");
    assert_eq!(body["port"], 5060);
    assert_eq!(body["serverDomain"], "sip.example.com");
    assert_eq!(body["ttlSeconds"], 300);
}

#[test]
fn txt_body_uses_text_field() {
    let body = record_data_to_unifi_body(
        "_acme.example.com",
        120,
        true,
        &RecordData::Txt {
            text: "challenge".into(),
            split_text: false,
        },
    )
    .unwrap();
    assert_eq!(body["type"], "TXT_RECORD");
    assert_eq!(body["text"], "challenge");
    assert_eq!(body["ttlSeconds"], 120);
}

#[test]
fn cname_body_uses_target_domain_field() {
    let body = record_data_to_unifi_body(
        "alias.example.com",
        60,
        false,
        &RecordData::Cname {
            target: "www.example.com".into(),
        },
    )
    .unwrap();
    assert_eq!(body["type"], "CNAME_RECORD");
    assert_eq!(body["targetDomain"], "www.example.com");
    assert_eq!(body["enabled"], false);
}

#[test]
fn unsupported_type_is_rejected() {
    let err = record_data_to_unifi_body(
        "example.com",
        300,
        true,
        &RecordData::Ns {
            nameserver: "ns1.example.com".into(),
            glue: None,
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        Error::Unsupported {
            vendor: "UniFi",
            ..
        }
    ));
}

// ── policy_matches_delete_params ────────────────────────────────────────

#[test]
fn delete_matches_by_type_and_value() {
    let pol = a_policy();
    assert!(policy_matches_delete_params(
        &pol,
        "www.example.com",
        &[("type", "A".into()), ("ipAddress", "192.168.1.10".into())],
    ));
    assert!(!policy_matches_delete_params(
        &pol,
        "www.example.com",
        &[("type", "A".into()), ("ipAddress", "10.0.0.1".into())],
    ));
}

#[test]
fn delete_requires_matching_domain() {
    let pol = a_policy();
    assert!(!policy_matches_delete_params(
        &pol,
        "other.example.com",
        &[("type", "A".into())],
    ));
}

#[test]
fn delete_requires_matching_type() {
    let pol = a_policy();
    assert!(!policy_matches_delete_params(
        &pol,
        "www.example.com",
        &[("type", "AAAA".into())],
    ));
}

#[test]
fn delete_never_matches_forward_domain() {
    let pol = forward_policy();
    assert!(!policy_matches_delete_params(
        &pol,
        "lan.example.com",
        &[("type", "FORWARD_DOMAIN".into())],
    ));
}

#[test]
fn delete_mx_distinguishes_by_preference() {
    let mx: UnifiDnsPolicy = serde_json::from_value(json!({
        "id": "mx1", "type": "MX_RECORD", "enabled": true,
        "domain": "example.com",
        "mailServerDomain": "mail.example.com",
        "priority": 10
    }))
    .unwrap();
    // Same exchange but wrong preference must NOT match.
    assert!(!policy_matches_delete_params(
        &mx,
        "example.com",
        &[
            ("type", "MX".into()),
            ("exchange", "mail.example.com".into()),
            ("preference", "20".into()),
        ],
    ));
    // Matching preference and exchange does match.
    assert!(policy_matches_delete_params(
        &mx,
        "example.com",
        &[
            ("type", "MX".into()),
            ("exchange", "mail.example.com".into()),
            ("preference", "10".into()),
        ],
    ));
}

#[test]
fn delete_srv_distinguishes_by_port_priority_weight() {
    let srv: UnifiDnsPolicy = serde_json::from_value(json!({
        "id": "srv1", "type": "SRV_RECORD", "enabled": true,
        "domain": "_sip._tcp.example.com",
        "serverDomain": "sip.example.com",
        "service": "_sip", "protocol": "_tcp",
        "port": 5060, "priority": 10, "weight": 20
    }))
    .unwrap();
    // Wrong port must NOT match even when target/priority/weight align.
    assert!(!policy_matches_delete_params(
        &srv,
        "_sip._tcp.example.com",
        &[
            ("type", "SRV".into()),
            ("target", "sip.example.com".into()),
            ("port", "5061".into()),
            ("priority", "10".into()),
            ("weight", "20".into()),
        ],
    ));
    // Wrong weight must NOT match either.
    assert!(!policy_matches_delete_params(
        &srv,
        "_sip._tcp.example.com",
        &[
            ("type", "SRV".into()),
            ("target", "sip.example.com".into()),
            ("port", "5060".into()),
            ("priority", "10".into()),
            ("weight", "30".into()),
        ],
    ));
    // All four match → policy is deletable.
    assert!(policy_matches_delete_params(
        &srv,
        "_sip._tcp.example.com",
        &[
            ("type", "SRV".into()),
            ("target", "sip.example.com".into()),
            ("port", "5060".into()),
            ("priority", "10".into()),
            ("weight", "20".into()),
        ],
    ));
}
