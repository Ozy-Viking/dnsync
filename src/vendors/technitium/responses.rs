//! Technitium API response parsing.
//!
//! Technitium's DNS API returns JSON responses whose shapes vary by endpoint.
//! Most endpoints return flat `Value` responses that are handled directly by the
//! service trait implementations. Record list responses use the Technitium
//! envelope (`{"response": {"zone": .., "records": [..]}}`) and are normalised
//! into the vendor-neutral [`ListRecordsResponse`] by [`parse_list_records`].

use serde_json::Value;

use crate::core::dns::responses::{ListRecordsResponse, ZoneInfo, ZoneRecord, parse_record_data};
use crate::core::error::{Error, Result};

/// Parse a Technitium `list_records` response into the vendor-neutral
/// [`ListRecordsResponse`], populating `parsed` on each record where the type is
/// recognised.
pub fn parse_list_records(value: &Value) -> Result<ListRecordsResponse> {
    let response = value
        .get("response")
        .ok_or_else(|| Error::parse("list_records response missing 'response' key"))?;

    let mut zone: ZoneInfo = serde_json::from_value(
        response
            .get("zone")
            .ok_or_else(|| Error::parse("list_records response missing 'response.zone'"))?
            .clone(),
    )
    .map_err(|e| Error::parse(format!("could not deserialize zone info: {e}")))?;
    if zone.id.is_none() {
        zone.id = Some(zone.name.clone());
    }

    let raw_records = response
        .get("records")
        .and_then(|r| r.as_array())
        .ok_or_else(|| Error::parse("list_records response missing 'response.records' array"))?;

    let records = raw_records
        .iter()
        .filter_map(|r| {
            let mut record: ZoneRecord = serde_json::from_value(r.clone()).ok()?;
            record.parsed = parse_record_data(&record.record_type, &record.data);
            Some(record)
        })
        .collect();

    Ok(ListRecordsResponse::single(zone, records))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::dns::records::RecordData;
    use crate::core::dns::responses::{AnyRecordData, ReadOnlyRecordData};
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

    fn wrap_response(
        zone: serde_json::Value,
        records: Vec<serde_json::Value>,
    ) -> serde_json::Value {
        json!({ "status": "ok", "response": { "zone": zone, "records": records } })
    }

    // ── parse_list_records — happy paths ──────────────────────────────────────

    #[rstest]
    fn parses_zone_info(zone_json: serde_json::Value) {
        let resp = wrap_response(zone_json, vec![]);
        let result = parse_list_records(&resp).expect("should parse");
        assert_eq!(result.zones.len(), 1);
        assert_eq!(result.zones[0].zone.name, "example.com");
        assert_eq!(result.zones[0].zone.zone_type, "Primary");
        assert!(!result.zones[0].zone.disabled);
    }

    #[rstest]
    fn empty_records_list(zone_json: serde_json::Value) {
        let resp = wrap_response(zone_json, vec![]);
        let result = parse_list_records(&resp).expect("should parse");
        assert!(result.zones[0].records.is_empty());
    }

    #[rstest]
    fn a_record_parsed_as_writable(zone_json: serde_json::Value, a_record_json: serde_json::Value) {
        let resp = wrap_response(zone_json, vec![a_record_json]);
        let result = parse_list_records(&resp).expect("should parse");

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
    fn rrsig_parsed_as_read_only(
        zone_json: serde_json::Value,
        rrsig_record_json: serde_json::Value,
    ) {
        let resp = wrap_response(zone_json, vec![rrsig_record_json]);
        let result = parse_list_records(&resp).expect("should parse");

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
    fn dnskey_parsed_as_read_only(
        zone_json: serde_json::Value,
        dnskey_record_json: serde_json::Value,
    ) {
        let resp = wrap_response(zone_json, vec![dnskey_record_json]);
        let result = parse_list_records(&resp).expect("should parse");

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
        let result = parse_list_records(&resp).expect("should parse");
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
        let result = parse_list_records(&resp).expect("should parse");

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

    // ── parse_list_records — error paths ──────────────────────────────────────

    #[rstest]
    fn missing_response_key_returns_parse_error() {
        let bad = json!({ "status": "ok" });
        let err = parse_list_records(&bad).unwrap_err();
        assert!(
            matches!(err, crate::core::error::Error::Parse { ref context } if context.contains("'response'"))
        );
    }

    #[rstest]
    fn missing_zone_key_returns_parse_error() {
        let bad = json!({ "status": "ok", "response": { "records": [] } });
        let err = parse_list_records(&bad).unwrap_err();
        assert!(
            matches!(err, crate::core::error::Error::Parse { ref context } if context.contains("zone"))
        );
    }

    #[rstest]
    fn missing_records_key_returns_parse_error(zone_json: serde_json::Value) {
        let bad = json!({ "status": "ok", "response": { "zone": zone_json } });
        let err = parse_list_records(&bad).unwrap_err();
        assert!(
            matches!(err, crate::core::error::Error::Parse { ref context } if context.contains("records"))
        );
    }

    #[rstest]
    #[case(json!({}))]
    #[case(json!(null))]
    #[case(json!([]))]
    fn empty_or_null_json_returns_parse_error(#[case] input: serde_json::Value) {
        assert!(parse_list_records(&input).is_err());
    }

    #[rstest]
    fn skips_malformed_records_rather_than_failing(
        zone_json: serde_json::Value,
        a_record_json: serde_json::Value,
    ) {
        let bad_record = json!({ "name": "bad", "ttl": 300, "rData": {} });
        let resp = wrap_response(zone_json, vec![bad_record, a_record_json]);
        let result = parse_list_records(&resp).expect("should parse overall response");
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
        let result = parse_list_records(&resp).unwrap();
        assert!(!result.zones[0].records[0].disabled);
    }

    #[rstest]
    fn record_comments_defaults_to_empty(zone_json: serde_json::Value) {
        let record = json!({
            "name": "test", "type": "A", "ttl": 300,
            "rData": { "ipAddress": "10.0.0.1" }
        });
        let resp = wrap_response(zone_json, vec![record]);
        let result = parse_list_records(&resp).unwrap();
        assert_eq!(result.zones[0].records[0].comments, "");
    }
}
