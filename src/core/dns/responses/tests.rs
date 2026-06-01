use super::*;

// ── ListRecordsResponse::single ───────────────────────────────────────────

fn make_zone(name: &str) -> ZoneInfo {
    ZoneInfo {
        id: None,
        name: name.to_string(),
        zone_type: "Primary".to_string(),
        disabled: false,
        dnssec_status: None,
    }
}

#[test]
fn single_wraps_zone_and_records_in_one_entry() {
    let result = ListRecordsResponse::single(make_zone("example.com"), vec![]);
    assert_eq!(result.zones.len(), 1);
    assert_eq!(result.zones[0].zone.name, "example.com");
    assert!(result.zones[0].records.is_empty());
}

// ── Serialization shape ───────────────────────────────────────────────────

#[test]
fn single_zone_serializes_flat() {
    let resp = ListRecordsResponse::single(make_zone("example.com"), vec![]);
    let v = serde_json::to_value(&resp).unwrap();
    assert!(v.get("zone").is_some(), "should have top-level 'zone'");
    assert!(
        v.get("records").is_some(),
        "should have top-level 'records'"
    );
    assert!(v.get("zones").is_none(), "should NOT have 'zones' wrapper");
    assert_eq!(v["zone"]["name"], "example.com");
}

#[test]
fn multi_zone_serializes_with_zones_array() {
    let resp = ListRecordsResponse {
        zones: vec![
            ZoneRecords {
                zone: make_zone("a.example.com"),
                records: vec![],
            },
            ZoneRecords {
                zone: make_zone("b.example.com"),
                records: vec![],
            },
        ],
    };
    let v = serde_json::to_value(&resp).unwrap();
    assert!(v.get("zones").is_some(), "should have 'zones' array");
    assert!(v.get("zone").is_none(), "should NOT have top-level 'zone'");
    assert_eq!(v["zones"].as_array().unwrap().len(), 2);
}

#[test]
fn single_zone_round_trips_through_serde() {
    let original = ListRecordsResponse::single(make_zone("example.com"), vec![]);
    let json = serde_json::to_value(&original).unwrap();
    let restored: ListRecordsResponse = serde_json::from_value(json).unwrap();
    assert_eq!(restored.zones.len(), 1);
    assert_eq!(restored.zones[0].zone.name, "example.com");
}

#[test]
fn multi_zone_round_trips_through_serde() {
    let original = ListRecordsResponse {
        zones: vec![
            ZoneRecords {
                zone: make_zone("a.example.com"),
                records: vec![],
            },
            ZoneRecords {
                zone: make_zone("b.example.com"),
                records: vec![],
            },
        ],
    };
    let json = serde_json::to_value(&original).unwrap();
    let restored: ListRecordsResponse = serde_json::from_value(json).unwrap();
    assert_eq!(restored.zones.len(), 2);
    assert_eq!(restored.zones[0].zone.name, "a.example.com");
    assert_eq!(restored.zones[1].zone.name, "b.example.com");
}
