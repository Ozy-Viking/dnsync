use super::*;

// ── apply_ip_map ──────────────────────────────────────────────────────────

#[test]
fn ip_map_rewrites_mapped_a_record() {
    let map = ip_map(&[("203.0.113.10", "192.168.1.10")]);
    let mapped = apply_ip_map(
        RecordData::A {
            ip: "203.0.113.10".parse().unwrap(),
        },
        &map,
    );
    match mapped {
        RecordData::A { ip } => assert_eq!(ip.to_string(), "192.168.1.10"),
        other => panic!("expected A, got {other:?}"),
    }
}

#[test]
fn ip_map_leaves_unmapped_a_record_untouched() {
    let map = ip_map(&[("203.0.113.10", "192.168.1.10")]);
    let mapped = apply_ip_map(
        RecordData::A {
            ip: "8.8.8.8".parse().unwrap(),
        },
        &map,
    );
    match mapped {
        RecordData::A { ip } => assert_eq!(ip.to_string(), "8.8.8.8"),
        other => panic!("expected A, got {other:?}"),
    }
}

#[test]
fn ip_map_rewrites_mapped_aaaa_record() {
    let map = ip_map(&[("2001:db8::1", "fd00::1")]);
    let mapped = apply_ip_map(
        RecordData::Aaaa {
            ip: "2001:db8::1".parse().unwrap(),
        },
        &map,
    );
    match mapped {
        RecordData::Aaaa { ip } => assert_eq!(ip.to_string(), "fd00::1"),
        other => panic!("expected AAAA, got {other:?}"),
    }
}

#[test]
fn ip_map_leaves_non_address_records_untouched() {
    let map = ip_map(&[("203.0.113.10", "192.168.1.10")]);
    let mapped = apply_ip_map(
        RecordData::Cname {
            target: "example.com".to_string(),
        },
        &map,
    );
    assert!(matches!(mapped, RecordData::Cname { .. }));
}

// ── plan/apply ────────────────────────────────────────────────────────────

#[tokio::test]
async fn plan_zone_lists_entire_zone_and_includes_child_records() {
    let zone = "dnsync-sync-test.example";
    let source = FakeZoneRead::new(sync_test_response(
        zone,
        vec![
            zone_record(zone, "SOA", 3600, json!({})),
            zone_record(zone, "NS", 3600, json!({ "nameServer": "dns1.hankin.io" })),
            zone_record(
                &format!("www.{zone}"),
                "A",
                3600,
                json!({ "ipAddress": "203.0.113.10" }),
            ),
            zone_record(
                &format!("api.{zone}"),
                "CNAME",
                3600,
                json!({ "cname": format!("www.{zone}") }),
            ),
        ],
    ));
    let dest = FakeZoneRead::new(sync_test_response(
        zone,
        vec![
            zone_record(zone, "SOA", 3600, json!({})),
            zone_record(zone, "NS", 3600, json!({ "nameServer": "dns2.hankin.io" })),
        ],
    ));

    let plan = plan_zone_with_clients(
        &source,
        &dest,
        zone,
        &HashMap::new(),
        &SyncDiffOptions::default(),
    )
    .await
    .unwrap();

    assert!(source.calls.lock().unwrap()[0].2.all_subdomains);
    assert!(dest.calls.lock().unwrap()[0].2.all_subdomains);
    assert_eq!(plan.adds.len(), 2);
    assert!(plan.adds.iter().any(|r| {
        r.fqdn == format!("www.{zone}")
            && r.rtype == "A"
            && value_display(&r.record) == "203.0.113.10"
    }));
    assert!(plan.adds.iter().any(|r| {
        r.fqdn == format!("api.{zone}")
            && r.rtype == "CNAME"
            && value_display(&r.record) == format!("www.{zone}")
    }));
    assert_eq!(plan.skipped, 2);
}

#[tokio::test]
async fn apply_writes_missing_child_records_to_destination() {
    let zone = "dnsync-sync-test.example";
    let writer = FakeRecordWrite::default();
    let plan = ZonePlan {
        zone: zone.to_string(),
        adds: vec![
            PlannedRecord {
                fqdn: format!("www.{zone}"),
                rtype: "A".to_string(),
                ttl: 3600,
                record: RecordData::A {
                    ip: "203.0.113.10".parse().unwrap(),
                },
            },
            PlannedRecord {
                fqdn: format!("api.{zone}"),
                rtype: "CNAME".to_string(),
                ttl: 3600,
                record: RecordData::Cname {
                    target: format!("www.{zone}"),
                },
            },
        ],
        deletes: vec![],
        unchanged: 0,
        untouched: 0,
        skipped: 0,
    };

    apply_plans_with_client(&writer, &[plan]).await.unwrap();

    let adds = writer.adds.lock().unwrap();
    assert_eq!(adds.len(), 2);
    assert_eq!(adds[0].0, zone);
    assert_eq!(adds[0].1, format!("www.{zone}"));
    assert!(matches!(adds[0].3, RecordData::A { .. }));
    assert_eq!(adds[1].1, format!("api.{zone}"));
    assert!(matches!(adds[1].3, RecordData::Cname { .. }));
}

#[tokio::test]
async fn plan_zone_applies_ip_mapping_to_child_address_records() {
    let zone = "dnsync-sync-test.example";
    let source = FakeZoneRead::new(sync_test_response(
        zone,
        vec![zone_record(
            &format!("www.{zone}"),
            "A",
            3600,
            json!({ "ipAddress": "203.0.113.10" }),
        )],
    ));
    let dest = FakeZoneRead::new(sync_test_response(zone, vec![]));
    let map = ip_map(&[("203.0.113.10", "192.0.2.10")]);

    let plan = plan_zone_with_clients(&source, &dest, zone, &map, &SyncDiffOptions::default())
        .await
        .unwrap();

    assert_eq!(plan.adds.len(), 1);
    assert_eq!(value_display(&plan.adds[0].record), "192.0.2.10");
}

// ── parse_ip_pair ─────────────────────────────────────────────────────────

#[test]
fn parse_ip_pair_accepts_valid_pair() {
    let (s, d) = parse_ip_pair("203.0.113.10 = 192.168.1.10").unwrap();
    assert_eq!(s.to_string(), "203.0.113.10");
    assert_eq!(d.to_string(), "192.168.1.10");
}

#[rstest]
#[case::missing_separator("203.0.113.10")]
#[case::bad_address("203.0.113.10=not-an-ip")]
#[case::family_mismatch("203.0.113.10=fd00::1")]
fn parse_ip_pair_rejects_bad_input(#[case] spec: &str) {
    assert!(parse_ip_pair(spec).is_err());
}

// ── canonical ─────────────────────────────────────────────────────────────

#[test]
fn canonical_equal_for_same_value_differs_for_others() {
    let one = RecordData::A {
        ip: "1.2.3.4".parse().unwrap(),
    };
    let same = RecordData::A {
        ip: "1.2.3.4".parse().unwrap(),
    };
    let other = RecordData::A {
        ip: "1.2.3.5".parse().unwrap(),
    };
    assert_eq!(canonical(&one), canonical(&same));
    assert_ne!(canonical(&one), canonical(&other));
}

// ── diff_records ──────────────────────────────────────────────────────────

#[test]
fn diff_adds_record_set_missing_on_destination() {
    let diff = diff_records(vec![a("www.example.com", "1.1.1.1")], vec![]);
    assert_eq!(diff.missing_adds.len(), 1);
    assert_eq!(diff.update_deletes.len(), 0);
    assert_eq!(diff.unchanged, 0);
}

#[test]
fn diff_updates_changed_value_with_add_and_remove() {
    let diff = diff_records(
        vec![a("www.example.com", "2.2.2.2")],
        vec![a("www.example.com", "1.1.1.1")],
    );
    assert_eq!(diff.update_adds.len(), 1);
    assert_eq!(diff.update_deletes.len(), 1);
    assert_eq!(diff.unchanged, 0);
    match &diff.update_adds[0].record {
        RecordData::A { ip } => assert_eq!(ip.to_string(), "2.2.2.2"),
        other => panic!("expected A, got {other:?}"),
    }
}

#[test]
fn diff_reports_identical_records_as_unchanged() {
    let diff = diff_records(
        vec![a("www.example.com", "1.1.1.1")],
        vec![a("www.example.com", "1.1.1.1")],
    );
    assert_eq!(diff.missing_adds.len(), 0);
    assert_eq!(diff.update_adds.len(), 0);
    assert_eq!(diff.update_deletes.len(), 0);
    assert_eq!(diff.unchanged, 1);
}

#[test]
fn diff_treats_ttl_difference_as_update() {
    let mut src = a("www.example.com", "1.1.1.1");
    src.ttl = 300;
    let mut dst = a("www.example.com", "1.1.1.1");
    dst.ttl = 3600;
    let diff = diff_records(vec![src], vec![dst]);
    assert_eq!(diff.update_adds.len(), 1);
    assert_eq!(diff.update_deletes.len(), 1);
    assert_eq!(diff.unchanged, 0);
    assert_eq!(diff.update_adds[0].ttl, 300);
}

#[test]
fn diff_never_prunes_destination_only_names() {
    let diff = diff_records(
        vec![a("a.example.com", "1.1.1.1")],
        vec![a("a.example.com", "1.1.1.1"), a("b.example.com", "2.2.2.2")],
    );
    assert_eq!(diff.missing_adds.len(), 0);
    assert_eq!(diff.update_adds.len(), 0);
    assert_eq!(diff.update_deletes.len(), 0);
    assert_eq!(diff.unchanged, 1);
    assert_eq!(diff.destination_only.len(), 1);
}
