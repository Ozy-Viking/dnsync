
use super::*;
use rstest::{fixture, rstest};
use serde_json::json;

// ── Fixtures ──────────────────────────────────────────────────────────────

#[fixture]
fn zone_json() -> serde_json::Value {
    json!({ "name": "example.com", "type": "Primary", "disabled": false })
}

#[fixture]
fn a_record_json() -> serde_json::Value {
    json!({
        "name": "www",
        "type": "A",
        "ttl": 3600,
        "disabled": false,
        "comments": "",
        "rData": { "ipAddress": "1.2.3.4" }
    })
}

#[fixture]
fn rrsig_record_json() -> serde_json::Value {
    json!({
        "name": "@",
        "type": "RRSIG",
        "ttl": 86400,
        "disabled": false,
        "comments": "",
        "rData": {
            "typeCovered": "A",
            "algorithm": "ECDSAP256SHA256",
            "labels": 2,
            "originalTtl": 3600,
            "signatureExpiration": "20261231000000",
            "signatureInception": "20260101000000",
            "keyTag": 12345,
            "signerName": "example.com",
            "signature": "abc123=="
        }
    })
}

#[fixture]
fn dnskey_record_json() -> serde_json::Value {
    json!({
        "name": "@",
        "type": "DNSKEY",
        "ttl": 86400,
        "disabled": false,
        "comments": "",
        "rData": {
            "flags": 257,
            "protocol": 3,
            "algorithm": "ECDSAP256SHA256",
            "publicKey": "base64key==",
            "computedKeyTag": 12345,
            "dnsKeyState": "Active",
            "isKsk": true
        }
    })
}

fn wrap_response(zone: serde_json::Value, records: Vec<serde_json::Value>) -> serde_json::Value {
    json!({ "status": "ok", "response": { "zone": zone, "records": records } })
}

// ── from_value — happy paths ──────────────────────────────────────────────

#[rstest]
fn parses_zone_info(zone_json: serde_json::Value) {
    let resp = wrap_response(zone_json, vec![]);
    let result = ListRecordsResponse::from_value(&resp).expect("should parse");
    assert_eq!(result.zones.len(), 1);
    assert_eq!(result.zones[0].zone.name, "example.com");
    assert_eq!(result.zones[0].zone.zone_type, "Primary");
    assert!(!result.zones[0].zone.disabled);
}

#[rstest]
fn empty_records_list(zone_json: serde_json::Value) {
    let resp = wrap_response(zone_json, vec![]);
    let result = ListRecordsResponse::from_value(&resp).expect("should parse");
    assert!(result.zones[0].records.is_empty());
}

#[rstest]
fn a_record_parsed_as_writable(zone_json: serde_json::Value, a_record_json: serde_json::Value) {
    let resp = wrap_response(zone_json, vec![a_record_json]);
    let result = ListRecordsResponse::from_value(&resp).expect("should parse");

    let records = &result.zones[0].records;
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.record_type, "A");
    assert_eq!(record.ttl, 3600);
    assert_eq!(record.name, "www");

    match &record.parsed {
        Some(AnyRecordData::Writable(RecordData::A { ip })) => {
            assert_eq!(ip.to_string(), "1.2.3.4");
        }
        other => panic!("expected Writable(A), got {other:?}"),
    }
}

#[rstest]
fn rrsig_parsed_as_read_only(zone_json: serde_json::Value, rrsig_record_json: serde_json::Value) {
    let resp = wrap_response(zone_json, vec![rrsig_record_json]);
    let result = ListRecordsResponse::from_value(&resp).expect("should parse");

    match &result.zones[0].records[0].parsed {
        Some(AnyRecordData::ReadOnly(ReadOnlyRecordData::Rrsig(data))) => {
            assert_eq!(data.type_covered, "A");
            assert_eq!(data.key_tag, 12345);
            assert_eq!(data.signer_name, "example.com");
        }
        other => panic!("expected ReadOnly(Rrsig), got {other:?}"),
    }
}

#[rstest]
fn dnskey_parsed_as_read_only(zone_json: serde_json::Value, dnskey_record_json: serde_json::Value) {
    let resp = wrap_response(zone_json, vec![dnskey_record_json]);
    let result = ListRecordsResponse::from_value(&resp).expect("should parse");

    match &result.zones[0].records[0].parsed {
        Some(AnyRecordData::ReadOnly(ReadOnlyRecordData::Dnskey(data))) => {
            assert_eq!(data.flags, 257);
            assert_eq!(data.computed_key_tag, 12345);
            assert_eq!(data.dns_key_state.as_deref(), Some("Active"));
            assert_eq!(data.is_ksk, Some(true));
        }
        other => panic!("expected ReadOnly(Dnskey), got {other:?}"),
    }
}

#[rstest]
fn unknown_type_produces_none_parsed(zone_json: serde_json::Value) {
    let record = json!({
        "name": "weird",
        "type": "NEWTYPE99",
        "ttl": 300,
        "rData": { "someField": "someValue" }
    });
    let resp = wrap_response(zone_json, vec![record]);
    let result = ListRecordsResponse::from_value(&resp).expect("should parse");
    assert!(
        result.zones[0].records[0].parsed.is_none(),
        "unknown type should produce None"
    );
}

#[rstest]
fn mixed_records_parse_correctly(
    zone_json: serde_json::Value,
    a_record_json: serde_json::Value,
    rrsig_record_json: serde_json::Value,
) {
    let unknown = json!({ "name": "x", "type": "MYSTERY", "ttl": 60, "rData": {} });
    let resp = wrap_response(zone_json, vec![a_record_json, rrsig_record_json, unknown]);
    let result = ListRecordsResponse::from_value(&resp).expect("should parse");

    let records = &result.zones[0].records;
    assert_eq!(records.len(), 3);
    assert!(matches!(
        records[0].parsed,
        Some(AnyRecordData::Writable(_))
    ));
    assert!(matches!(
        records[1].parsed,
        Some(AnyRecordData::ReadOnly(_))
    ));
    assert!(records[2].parsed.is_none());
}

// ── from_value — error paths ──────────────────────────────────────────────

#[rstest]
fn missing_response_key_returns_parse_error() {
    let bad = json!({ "status": "ok" });
    let err = ListRecordsResponse::from_value(&bad).unwrap_err();
    assert!(
        matches!(err, crate::core::error::Error::Parse { ref context } if context.contains("'response'"))
    );
}

#[rstest]
fn missing_zone_key_returns_parse_error() {
    let bad = json!({ "status": "ok", "response": { "records": [] } });
    let err = ListRecordsResponse::from_value(&bad).unwrap_err();
    assert!(
        matches!(err, crate::core::error::Error::Parse { ref context } if context.contains("zone"))
    );
}

#[rstest]
fn missing_records_key_returns_parse_error(zone_json: serde_json::Value) {
    let bad = json!({ "status": "ok", "response": { "zone": zone_json } });
    let err = ListRecordsResponse::from_value(&bad).unwrap_err();
    assert!(
        matches!(err, crate::core::error::Error::Parse { ref context } if context.contains("records"))
    );
}

#[rstest]
#[case(json!({}))]
#[case(json!(null))]
#[case(json!([]))]
fn empty_or_null_json_returns_parse_error(#[case] input: serde_json::Value) {
    assert!(ListRecordsResponse::from_value(&input).is_err());
}

#[rstest]
fn skips_malformed_records_rather_than_failing(
    zone_json: serde_json::Value,
    a_record_json: serde_json::Value,
) {
    let bad_record = json!({ "name": "bad", "ttl": 300, "rData": {} });
    let resp = wrap_response(zone_json, vec![bad_record, a_record_json]);
    let result = ListRecordsResponse::from_value(&resp).expect("should parse overall response");
    let records = &result.zones[0].records;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record_type, "A");
}

// ── ZoneRecord fields ─────────────────────────────────────────────────────

#[rstest]
fn record_disabled_defaults_to_false(zone_json: serde_json::Value) {
    let record = json!({
        "name": "test", "type": "A", "ttl": 300,
        "rData": { "ipAddress": "10.0.0.1" }
    });
    let resp = wrap_response(zone_json, vec![record]);
    let result = ListRecordsResponse::from_value(&resp).unwrap();
    assert!(!result.zones[0].records[0].disabled);
}

#[rstest]
fn record_comments_defaults_to_empty(zone_json: serde_json::Value) {
    let record = json!({
        "name": "test", "type": "A", "ttl": 300,
        "rData": { "ipAddress": "10.0.0.1" }
    });
    let resp = wrap_response(zone_json, vec![record]);
    let result = ListRecordsResponse::from_value(&resp).unwrap();
    assert_eq!(result.zones[0].records[0].comments, "");
}

// ── ListRecordsResponse::single ───────────────────────────────────────────

#[rstest]
fn single_wraps_zone_and_records_in_one_entry(zone_json: serde_json::Value) {
    let zone: ZoneInfo = serde_json::from_value(zone_json).unwrap();
    let result = ListRecordsResponse::single(zone, vec![]);
    assert_eq!(result.zones.len(), 1);
    assert_eq!(result.zones[0].zone.name, "example.com");
    assert!(result.zones[0].records.is_empty());
}

// ── Serialization shape ───────────────────────────────────────────────────

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
