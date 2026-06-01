use super::*;

use rstest::{fixture, rstest};

// ── Fixtures ──────────────────────────────────────────────────────────────

#[fixture]
fn a_record() -> RecordData {
    RecordData::A {
        ip: "1.2.3.4".parse().unwrap(),
    }
}

#[fixture]
fn mx_record() -> RecordData {
    RecordData::Mx {
        preference: 10,
        exchange: "mail.example.com".into(),
    }
}

#[fixture]
fn srv_record() -> RecordData {
    RecordData::Srv {
        priority: 10,
        weight: 20,
        port: 5060,
        target: "sip.example.com".into(),
    }
}

#[fixture]
fn ns_with_glue() -> RecordData {
    RecordData::Ns {
        nameserver: "ns1.example.com".into(),
        glue: Some("1.2.3.4".into()),
    }
}

#[fixture]
fn ns_without_glue() -> RecordData {
    RecordData::Ns {
        nameserver: "ns1.example.com".into(),
        glue: None,
    }
}

// ── type_name — every variant ─────────────────────────────────────────────

#[rstest]
#[case::a(RecordData::A { ip: "1.2.3.4".parse().unwrap() }, "A")]
#[case::aaaa(RecordData::Aaaa { ip: "::1".parse().unwrap() }, "AAAA")]
#[case::aname(RecordData::Aname { aname: "t.example.com".into() }, "ANAME")]
#[case::app(RecordData::App { app_name: "App".into(), class_path: "C".into(), record_data: "{}".into() }, "APP")]
#[case::caa(RecordData::Caa { flags: 0, tag: "issue".into(), value: "le.org".into() }, "CAA")]
#[case::cname(RecordData::Cname { target: "www.example.com".into() }, "CNAME")]
#[case::dname(RecordData::Dname { dname: "other.example.com".into() }, "DNAME")]
#[case::ds(RecordData::Ds { key_tag: 1, algorithm: DsAlgorithm::Rsasha256, digest_type: DigestType::Sha256, digest: "ab".into() }, "DS")]
#[case::fwd(RecordData::Fwd { forwarder: "1.1.1.1".into(), protocol: FwdProtocol::Udp, priority: 10, dnssec_validation: false }, "FWD")]
#[case::https(RecordData::Https { svc_priority: 1, svc_target_name: "svc.example.com".into(), svc_params: None, auto_ipv4_hint: false, auto_ipv6_hint: false }, "HTTPS")]
#[case::mx(RecordData::Mx { preference: 10, exchange: "mail.example.com".into() }, "MX")]
#[case::naptr(RecordData::Naptr { order: 10, preference: 20, flags: "U".into(), services: "E2U+sip".into(), regexp: "".into(), replacement: ".".into() }, "NAPTR")]
#[case::ns(RecordData::Ns { nameserver: "ns1.example.com".into(), glue: None }, "NS")]
#[case::ptr(RecordData::Ptr { name: "host.example.com".into() }, "PTR")]
#[case::sshfp(RecordData::Sshfp { algorithm: SshfpAlgorithm::Rsa, fingerprint_type: SshfpFingerprintType::Sha256, fingerprint: "abcd".into() }, "SSHFP")]
#[case::srv(RecordData::Srv { priority: 0, weight: 0, port: 80, target: "t.example.com".into() }, "SRV")]
#[case::svcb(RecordData::Svcb { svc_priority: 1, svc_target_name: "svc.example.com".into(), svc_params: None, auto_ipv4_hint: false, auto_ipv6_hint: false }, "SVCB")]
#[case::tlsa(RecordData::Tlsa { cert_usage: TlsaCertUsage::DaneEe, selector: TlsaSelector::Spki, matching_type: TlsaMatchingType::Sha2_256, cert_association_data: "ab".into() }, "TLSA")]
#[case::txt(RecordData::Txt { text: "v=spf1 ~all".into(), split_text: false }, "TXT")]
#[case::uri(RecordData::Uri { priority: 1, weight: 1, uri: "https://example.com".into() }, "URI")]
#[case::unknown(RecordData::Unknown { rdata: "0a0b".into() }, "UNKNOWN")]
fn type_name_matches_variant(#[case] record: RecordData, #[case] expected: &str) {
    assert_eq!(record.type_name(), expected);
}

// ── to_api_params — correct field names ───────────────────────────────────

fn params_map(record: &RecordData) -> std::collections::HashMap<&'static str, String> {
    record.to_api_params().into_iter().collect()
}

#[rstest]
fn a_uses_ip_address_key(a_record: RecordData) {
    let p = params_map(&a_record);
    assert_eq!(p["type"], "A");
    assert_eq!(p["ipAddress"], "1.2.3.4");
    // Must NOT use "ip" — that's our internal field name
    assert!(!p.contains_key("ip"));
}

#[rstest]
fn aaaa_uses_ip_address_key() {
    let r = RecordData::Aaaa {
        ip: "2001:db8::1".parse().unwrap(),
    };
    let p = params_map(&r);
    assert_eq!(p["type"], "AAAA");
    assert_eq!(p["ipAddress"], "2001:db8::1");
}

#[rstest]
fn mx_uses_exchange_and_preference(mx_record: RecordData) {
    let p = params_map(&mx_record);
    assert_eq!(p["type"], "MX");
    assert_eq!(p["exchange"], "mail.example.com");
    assert_eq!(p["preference"], "10");
}

#[rstest]
fn ns_uses_name_server_key(ns_without_glue: RecordData) {
    let p = params_map(&ns_without_glue);
    assert_eq!(p["type"], "NS");
    assert_eq!(p["nameServer"], "ns1.example.com"); // camelCase, not "nameserver"
    assert!(!p.contains_key("glue"));
}

#[rstest]
fn ns_includes_glue_when_present(ns_with_glue: RecordData) {
    let p = params_map(&ns_with_glue);
    assert_eq!(p["glue"], "1.2.3.4");
}

#[rstest]
fn ptr_uses_ptr_name_key() {
    let r = RecordData::Ptr {
        name: "host.example.com".into(),
    };
    let p = params_map(&r);
    assert_eq!(p["ptrName"], "host.example.com");
    assert!(!p.contains_key("name"));
}

#[rstest]
fn cname_uses_cname_key() {
    let r = RecordData::Cname {
        target: "www.example.com".into(),
    };
    let p = params_map(&r);
    assert_eq!(p["cname"], "www.example.com");
    assert!(!p.contains_key("target"));
}

#[rstest]
fn srv_uses_correct_keys(srv_record: RecordData) {
    let p = params_map(&srv_record);
    assert_eq!(p["type"], "SRV");
    assert_eq!(p["priority"], "10");
    assert_eq!(p["weight"], "20");
    assert_eq!(p["port"], "5060");
    assert_eq!(p["target"], "sip.example.com");
}

#[rstest]
fn ds_uses_camel_case_keys() {
    let r = RecordData::Ds {
        key_tag: 12345,
        algorithm: DsAlgorithm::Ecdsap256sha256,
        digest_type: DigestType::Sha256,
        digest: "deadbeef".into(),
    };
    let p = params_map(&r);
    assert_eq!(p["keyTag"], "12345");
    assert_eq!(p["algorithm"], "ECDSAP256SHA256");
    assert_eq!(p["digestType"], "SHA256");
    assert_eq!(p["digest"], "deadbeef");
}

#[rstest]
fn tlsa_uses_full_key_names() {
    let r = RecordData::Tlsa {
        cert_usage: TlsaCertUsage::DaneTa,
        selector: TlsaSelector::Cert,
        matching_type: TlsaMatchingType::Sha2_512,
        cert_association_data: "cafebabe".into(),
    };
    let p = params_map(&r);
    assert_eq!(p["tlsaCertificateUsage"], "DANE-TA");
    assert_eq!(p["tlsaSelector"], "Cert");
    assert_eq!(p["tlsaMatchingType"], "SHA2-512");
    assert_eq!(p["tlsaCertificateAssociationData"], "cafebabe");
}

#[rstest]
fn fwd_uses_forwarder_priority_key() {
    let r = RecordData::Fwd {
        forwarder: "8.8.8.8".into(),
        protocol: FwdProtocol::Tls,
        priority: 5,
        dnssec_validation: true,
    };
    let p = params_map(&r);
    assert_eq!(p["forwarder"], "8.8.8.8");
    assert_eq!(p["protocol"], "Tls");
    assert_eq!(p["forwarderPriority"], "5"); // NOT "priority"
    assert_eq!(p["dnssecValidation"], "true");
}

#[rstest]
fn https_and_svcb_use_svc_prefix() {
    let https = RecordData::Https {
        svc_priority: 1,
        svc_target_name: "svc.example.com".into(),
        svc_params: Some("alpn|h2".into()),
        auto_ipv4_hint: true,
        auto_ipv6_hint: false,
    };
    let svcb = RecordData::Svcb {
        svc_priority: 1,
        svc_target_name: "svc.example.com".into(),
        svc_params: Some("alpn|h2".into()),
        auto_ipv4_hint: true,
        auto_ipv6_hint: false,
    };
    for r in [&https, &svcb] {
        let p = params_map(r);
        assert_eq!(p["svcPriority"], "1");
        assert_eq!(p["svcTargetName"], "svc.example.com");
        assert_eq!(p["svcParams"], "alpn|h2");
        assert_eq!(p["autoIpv4Hint"], "true");
        assert_eq!(p["autoIpv6Hint"], "false");
    }
}

#[rstest]
fn https_omits_svc_params_when_none() {
    let r = RecordData::Https {
        svc_priority: 1,
        svc_target_name: "svc.example.com".into(),
        svc_params: None,
        auto_ipv4_hint: false,
        auto_ipv6_hint: false,
    };
    let p = params_map(&r);
    assert!(!p.contains_key("svcParams"));
}

#[rstest]
fn uri_uses_uri_prefix_keys() {
    let r = RecordData::Uri {
        priority: 5,
        weight: 3,
        uri: "https://example.com/path".into(),
    };
    let p = params_map(&r);
    assert_eq!(p["uriPriority"], "5");
    assert_eq!(p["uriWeight"], "3");
    assert_eq!(p["uri"], "https://example.com/path");
}

#[rstest]
fn naptr_uses_naptr_prefix_keys() {
    let r = RecordData::Naptr {
        order: 10,
        preference: 20,
        flags: "U".into(),
        services: "E2U+sip".into(),
        regexp: "!^.*$!sip:info@example.com!".into(),
        replacement: ".".into(),
    };
    let p = params_map(&r);
    assert_eq!(p["naptrOrder"], "10");
    assert_eq!(p["naptrPreference"], "20");
    assert_eq!(p["naptrFlags"], "U");
    assert_eq!(p["naptrServices"], "E2U+sip");
    assert_eq!(p["naptrRegexp"], "!^.*$!sip:info@example.com!");
    assert_eq!(p["naptrReplacement"], ".");
}

#[rstest]
fn txt_includes_split_text_flag() {
    let r = RecordData::Txt {
        text: "v=spf1 ~all".into(),
        split_text: true,
    };
    let p = params_map(&r);
    assert_eq!(p["text"], "v=spf1 ~all");
    assert_eq!(p["splitText"], "true");
}

// ── type_name is always first param ──────────────────────────────────────

#[rstest]
fn type_param_is_always_first(
    #[values(
            RecordData::A { ip: "1.2.3.4".parse().unwrap() },
            RecordData::Cname { target: "www.example.com".into() },
            RecordData::Txt { text: "test".into(), split_text: false }
        )]
    record: RecordData,
) {
    let params = record.to_api_params();
    assert_eq!(params[0].0, "type");
    assert_eq!(params[0].1, record.type_name());
}

// ── APL ──────────────────────────────────────────────────────────────────

#[test]
fn apl_type_name_is_apl() {
    let r = RecordData::Apl {
        address_prefixes: vec!["1:10.5.161.84/32".into()],
    };
    assert_eq!(r.type_name(), "APL");
}

#[test]
fn apl_to_api_params_type_is_first() {
    let r = RecordData::Apl {
        address_prefixes: vec!["1:10.5.161.84/32".into()],
    };
    let params = r.to_api_params();
    assert_eq!(params[0], ("type", "APL".to_string()));
}

#[test]
fn apl_to_api_params_includes_address_prefixes() {
    let r = RecordData::Apl {
        address_prefixes: vec!["1:10.5.161.84/32".into(), "1:10.5.161.85/32".into()],
    };
    let map = params_map(&r);
    assert!(map.contains_key("addressPrefixes"));
    assert_eq!(map["addressPrefixes"], "1:10.5.161.84/32 1:10.5.161.85/32");
}

#[test]
fn apl_empty_prefixes_produces_empty_string() {
    let r = RecordData::Apl {
        address_prefixes: vec![],
    };
    let map = params_map(&r);
    assert_eq!(map["addressPrefixes"], "");
}
