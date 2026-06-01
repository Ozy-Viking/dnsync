use super::*;

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
    let params = vec![
        ("type", "A".to_string()),
        ("ipAddress", "1.2.3.4".to_string()),
    ];
    assert_eq!(expected_cloudflare_content("A", &params), Some("1.2.3.4"));

    let params = vec![
        ("type", "CNAME".to_string()),
        ("cname", "x.example.com".to_string()),
    ];
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
