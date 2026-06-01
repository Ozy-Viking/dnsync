use super::*;

#[tokio::test]
async fn create_missing_false_does_not_add_new_name_types() {
    let zone = "example.com";
    let (source, dest) = make_source_dest_clients(
        zone,
        vec![zone_record(
            "new-host.example.com",
            "A",
            3600,
            json!({ "ipAddress": "1.1.1.1" }),
        )],
        vec![],
    );
    let opts = SyncDiffOptions {
        create_missing: false,
        overwrite_existing: true,
        delete_destination_only: false,
        ignore: vec![],
    };
    let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
        .await
        .unwrap();
    assert_eq!(plan.adds.len(), 0);
    assert_eq!(plan.deletes.len(), 0);
}

#[tokio::test]
async fn create_missing_true_adds_new_name_types() {
    let zone = "example.com";
    let (source, dest) = make_source_dest_clients(
        zone,
        vec![zone_record(
            "new-host.example.com",
            "A",
            3600,
            json!({ "ipAddress": "1.1.1.1" }),
        )],
        vec![],
    );
    let opts = SyncDiffOptions {
        create_missing: true,
        overwrite_existing: false,
        delete_destination_only: false,
        ignore: vec![],
    };
    let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
        .await
        .unwrap();
    assert_eq!(plan.adds.len(), 1);
    assert_eq!(plan.deletes.len(), 0);
}

#[tokio::test]
async fn overwrite_existing_false_leaves_changed_records_untouched() {
    let zone = "example.com";
    let (source, dest) = make_source_dest_clients(
        zone,
        vec![zone_record(
            "www.example.com",
            "A",
            3600,
            json!({ "ipAddress": "2.2.2.2" }),
        )],
        vec![zone_record(
            "www.example.com",
            "A",
            3600,
            json!({ "ipAddress": "1.1.1.1" }),
        )],
    );
    let opts = SyncDiffOptions {
        create_missing: true,
        overwrite_existing: false,
        delete_destination_only: false,
        ignore: vec![],
    };
    let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
        .await
        .unwrap();
    assert_eq!(plan.adds.len(), 0);
    assert_eq!(plan.deletes.len(), 0);
}

#[tokio::test]
async fn overwrite_existing_true_replaces_changed_records() {
    let zone = "example.com";
    let (source, dest) = make_source_dest_clients(
        zone,
        vec![zone_record(
            "www.example.com",
            "A",
            3600,
            json!({ "ipAddress": "2.2.2.2" }),
        )],
        vec![zone_record(
            "www.example.com",
            "A",
            3600,
            json!({ "ipAddress": "1.1.1.1" }),
        )],
    );
    let opts = SyncDiffOptions {
        create_missing: false,
        overwrite_existing: true,
        delete_destination_only: false,
        ignore: vec![],
    };
    let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
        .await
        .unwrap();
    assert_eq!(plan.adds.len(), 1);
    assert_eq!(plan.deletes.len(), 1);
    match &plan.adds[0].record {
        RecordData::A { ip } => assert_eq!(ip.to_string(), "2.2.2.2"),
        other => panic!("expected A, got {other:?}"),
    }
}

#[tokio::test]
async fn delete_destination_only_false_leaves_destination_only_records() {
    let zone = "example.com";
    let (source, dest) = make_source_dest_clients(
        zone,
        vec![],
        vec![zone_record(
            "www.example.com",
            "A",
            3600,
            json!({ "ipAddress": "1.1.1.1" }),
        )],
    );
    let opts = SyncDiffOptions {
        create_missing: true,
        overwrite_existing: true,
        delete_destination_only: false,
        ignore: vec![],
    };
    let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
        .await
        .unwrap();
    assert_eq!(plan.deletes.len(), 0);
    assert_eq!(plan.untouched, 1);
}

#[tokio::test]
async fn delete_destination_only_true_removes_destination_only_records() {
    let zone = "example.com";
    let (source, dest) = make_source_dest_clients(
        zone,
        vec![],
        vec![zone_record(
            "www.example.com",
            "A",
            3600,
            json!({ "ipAddress": "1.1.1.1" }),
        )],
    );
    let opts = SyncDiffOptions {
        create_missing: true,
        overwrite_existing: true,
        delete_destination_only: true,
        ignore: vec![],
    };
    let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
        .await
        .unwrap();
    assert_eq!(plan.deletes.len(), 1);
    assert_eq!(plan.untouched, 0);
}

#[tokio::test]
async fn ignore_pattern_filters_source_records_by_fqdn() {
    let zone = "example.com";
    let (source, dest) = make_source_dest_clients(
        zone,
        vec![
            zone_record(
                "web.example.com",
                "A",
                3600,
                json!({ "ipAddress": "1.1.1.1" }),
            ),
            zone_record(
                "internal.example.com",
                "A",
                3600,
                json!({ "ipAddress": "10.0.0.1" }),
            ),
        ],
        vec![],
    );
    let opts = SyncDiffOptions {
        create_missing: true,
        overwrite_existing: true,
        delete_destination_only: false,
        ignore: vec![Regex::new(r"^internal\.").unwrap()],
    };
    let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
        .await
        .unwrap();
    assert_eq!(plan.adds.len(), 1);
    assert!(plan.adds.iter().any(|r| r.fqdn == "web.example.com"));
    assert!(!plan.adds.iter().any(|r| r.fqdn == "internal.example.com"));
}

/// Verifies that ignore regexes in `SyncDiffOptions` match FQDNs case-sensitively by default.
///
/// The test builds a source zone containing `web.example.com` and `api.example.com`,
/// sets an ignore pattern that matches `web.example` (lowercase), and asserts that
/// only `api.example.com` remains in the planned additions while `web.example.com` is filtered.
#[tokio::test]
async fn ignore_pattern_is_case_sensitive_by_default() {
    let zone = "example.com";
    let (source, dest) = make_source_dest_clients(
        zone,
        vec![
            zone_record(
                "web.example.com",
                "A",
                3600,
                json!({ "ipAddress": "1.1.1.1" }),
            ),
            zone_record(
                "api.example.com",
                "A",
                3600,
                json!({ "ipAddress": "2.2.2.2" }),
            ),
        ],
        vec![],
    );
    let opts = SyncDiffOptions {
        create_missing: true,
        overwrite_existing: true,
        delete_destination_only: false,
        ignore: vec![Regex::new(r"^web\.example").unwrap()],
    };
    let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
        .await
        .unwrap();
    // web.example.com should be filtered, api.example.com should remain
    assert_eq!(plan.adds.len(), 1);
    assert!(plan.adds.iter().any(|r| r.fqdn == "api.example.com"));
    assert!(!plan.adds.iter().any(|r| r.fqdn == "web.example.com"));
}

/// Verifies that when all diff options are disabled, no add or delete operations are planned.
///
/// Creates source and destination records such that there are source-only and differing records,
/// then constructs `SyncDiffOptions` with `create_missing`, `overwrite_existing`, and
/// `delete_destination_only` all set to `false`. Asserts that the resulting `ZonePlan` contains
/// zero `adds` and zero `deletes`.
#[tokio::test]
async fn all_flags_false_produces_no_ops() {
    let zone = "example.com";
    let (source, dest) = make_source_dest_clients(
        zone,
        vec![
            zone_record(
                "new-host.example.com",
                "A",
                3600,
                json!({ "ipAddress": "1.1.1.1" }),
            ),
            zone_record(
                "www.example.com",
                "A",
                3600,
                json!({ "ipAddress": "2.2.2.2" }),
            ),
        ],
        vec![zone_record(
            "www.example.com",
            "A",
            3600,
            json!({ "ipAddress": "1.1.1.1" }),
        )],
    );
    let opts = SyncDiffOptions {
        create_missing: false,
        overwrite_existing: false,
        delete_destination_only: false,
        ignore: vec![],
    };
    let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
        .await
        .unwrap();
    assert_eq!(plan.adds.len(), 0);
    assert_eq!(plan.deletes.len(), 0);
}

#[tokio::test]
async fn delete_destination_only_with_create_missing_is_full_mirror() {
    let zone = "example.com";
    let (source, dest) = make_source_dest_clients(
        zone,
        vec![zone_record(
            "a.example.com",
            "A",
            3600,
            json!({ "ipAddress": "1.1.1.1" }),
        )],
        vec![zone_record(
            "b.example.com",
            "A",
            3600,
            json!({ "ipAddress": "2.2.2.2" }),
        )],
    );
    let opts = SyncDiffOptions {
        create_missing: true,
        overwrite_existing: true,
        delete_destination_only: true,
        ignore: vec![],
    };
    let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
        .await
        .unwrap();
    assert_eq!(plan.adds.len(), 1);
    assert!(plan.adds.iter().any(|r| r.fqdn == "a.example.com"));
    assert_eq!(plan.deletes.len(), 1);
    assert!(plan.deletes.iter().any(|r| r.fqdn == "b.example.com"));
}
