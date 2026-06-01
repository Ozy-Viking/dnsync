use super::*;

#[test]
fn json_multi_server_uses_nested_servers_shape() {
    let blocks = vec![result_block("dns1"), result_block("dns2")];
    let kind = TargetKind::Named {
        servers: vec![
            NamedServer {
                server_id: "dns1".to_string(),
                cluster: Some("home-dns".to_string()),
            },
            NamedServer {
                server_id: "dns2".to_string(),
                cluster: Some("home-dns".to_string()),
            },
        ],
    };
    let v = build_json_value("huly.hankin.io", &["A".to_string()], &kind, &blocks);

    // Nested `servers`, no top-level `results`, ambiguous target null.
    assert!(v.get("results").is_none());
    assert!(v["target"]["server"].is_null());
    let servers = v["servers"].as_array().expect("servers array");
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0]["server"], "dns1");
    assert_eq!(servers[0]["cluster"], "home-dns");
    assert_eq!(servers[0]["results"][0]["answers"][0]["data"], "10.5.0.42");
    assert_eq!(servers[1]["server"], "dns2");
}

#[test]
fn json_single_server_keeps_flat_results_shape() {
    let blocks = vec![result_block("dns1")];
    let kind = TargetKind::Named {
        servers: vec![NamedServer {
            server_id: "dns1".to_string(),
            cluster: None,
        }],
    };
    let v = build_json_value("huly.hankin.io", &["A".to_string()], &kind, &blocks);

    assert!(v.get("servers").is_none());
    assert_eq!(v["target"]["server"], "dns1");
    assert_eq!(v["results"][0]["answers"][0]["data"], "10.5.0.42");
}

#[rstest]
#[case("A", "192.0.2.10", "192.0.2.10")]
#[case("AAAA", "2001:db8::10", "2001:db8::10")]
#[case("CNAME", "target.example.com.", "target.example.com.")]
#[case("MX", "10 mail.example.com.", "10 mail.example.com.")]
#[case("TXT", "\"v=spf1 -all\"", "v=spf1 -all")]
#[case("NS", "ns1.example.com.", "ns1.example.com.")]
#[case("SRV", "10 20 5060 sip.example.com.", "10 20 5060 sip.example.com.")]
#[case("CAA", "0 issue \"letsencrypt.org\"", "0 issue \"letsencrypt.org\"")]
#[case("PTR", "host.example.com.", "host.example.com.")]
#[case(
    "SOA",
    "ns1.example.com. hostmaster.example.com. 2026052901 3600 900 604800 300",
    "ns1.example.com. hostmaster.example.com. 2026052901 3600 900 604800 300"
)]
fn observed_records_preserve_actual_type_name_ttl_and_value(
    #[case] rr_type: &str,
    #[case] rdata_text: &str,
    #[case] expected_value: &str,
) {
    let rr_type = rr_type.parse::<RecordType>().unwrap();
    let record = test_record("owner.example.com.", 600, rr_type, rdata_text);

    let observed = observed_records_from_answers(&[record]);

    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].name, "owner.example.com.");
    assert_eq!(observed[0].record_type, rr_type.to_string());
    assert_eq!(observed[0].ttl, Some(600));
    assert_eq!(observed[0].values, vec![expected_value.to_string()]);
}

#[test]
fn observed_records_keep_cname_type_returned_during_aaaa_lookup() {
    let records = vec![
        test_record(
            "alias.example.com.",
            300,
            RecordType::CNAME,
            "target.example.com.",
        ),
        test_record("target.example.com.", 300, RecordType::AAAA, "2001:db8::10"),
    ];

    let observed = observed_records_from_answers(&records);

    assert_eq!(observed[0].name, "alias.example.com.");
    assert_eq!(observed[0].record_type, "CNAME");
    assert_eq!(observed[0].values, vec!["target.example.com.".to_string()]);
    assert_eq!(observed[1].name, "target.example.com.");
    assert_eq!(observed[1].record_type, "AAAA");
    assert_eq!(observed[1].values, vec!["2001:db8::10".to_string()]);
}

#[test]
fn observed_records_keep_cname_type_returned_during_a_lookup() {
    let records = vec![
        test_record(
            "alias.example.com.",
            300,
            RecordType::CNAME,
            "target.example.com.",
        ),
        test_record("target.example.com.", 300, RecordType::A, "192.0.2.10"),
    ];

    let observed = observed_records_from_answers(&records);

    assert_eq!(observed[0].name, "alias.example.com.");
    assert_eq!(observed[0].record_type, "CNAME");
    assert_eq!(observed[0].values, vec!["target.example.com.".to_string()]);
    assert_eq!(observed[1].name, "target.example.com.");
    assert_eq!(observed[1].record_type, "A");
    assert_eq!(observed[1].values, vec!["192.0.2.10".to_string()]);
}
#[test]
fn push_observed_record_once_deduplicates_cname_seen_from_multiple_type_lookups() {
    let mut records = Vec::new();
    let cname = ObservedRecord {
        name: "alias.example.com.".to_string(),
        record_type: "CNAME".to_string(),
        ttl: Some(300),
        values: vec!["target.example.com.".to_string()],
    };

    push_observed_record_once(&mut records, cname.clone());
    push_observed_record_once(&mut records, cname);

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record_type, "CNAME");
}

#[test]
fn push_observed_record_once_collapses_differing_ttls_keeping_smallest() {
    // The same CNAME comes back from the A-type lookup (cache TTL
    // 3600) and the explicit CNAME-type lookup (counted down to 599).
    // It should collapse to a single row carrying the smaller TTL.
    let mut records = Vec::new();
    let high = ObservedRecord {
        name: "huly.hankin.io.".to_string(),
        record_type: "CNAME".to_string(),
        ttl: Some(3600),
        values: vec!["nasapps.hankin.io.".to_string()],
    };
    let low = ObservedRecord {
        ttl: Some(599),
        ..high.clone()
    };

    push_observed_record_once(&mut records, high);
    push_observed_record_once(&mut records, low);

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].ttl, Some(599));
}
