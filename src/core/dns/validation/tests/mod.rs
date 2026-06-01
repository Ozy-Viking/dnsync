//! Tests for `core::dns::validation`.

pub(crate) use super::*;
pub(crate) use crate::control_plane::config::ValidationTransport;
pub(crate) use crate::core::dns::responses::{ZoneInfo, ZoneRecords};
pub(crate) use rstest::{fixture, rstest};
pub(crate) use serde_json::{Value, json};
pub(crate) use std::net::{Ipv4Addr, Ipv6Addr};

mod compare;
mod report;

#[fixture]
fn expected_record() -> ExpectedRecord {
    ExpectedRecord {
        name: "www.example.com".to_string(),
        record_type: "A".to_string(),
        values: vec!["192.0.2.10".to_string()],
    }
}

#[fixture]
fn mismatch() -> RecordMismatch {
    RecordMismatch {
        name: "www.example.com".to_string(),
        record_type: "A".to_string(),
        expected: vec!["192.0.2.10".to_string()],
        observed: vec!["192.0.2.11".to_string()],
        mismatch_kind: "wrong_value".to_string(),
    }
}

#[fixture]
fn mismatched_result(mismatch: RecordMismatch) -> RecordValidationResult {
    RecordValidationResult {
        name: mismatch.name.clone(),
        record_type: mismatch.record_type.clone(),
        status: ValidationStatus::Mismatched,
        mismatch: Some(mismatch),
        failure_kind: None,
        skip_reason: None,
    }
}

#[fixture]
fn endpoint_report(
    mismatch: RecordMismatch,
    mismatched_result: RecordValidationResult,
) -> EndpointValidationReport {
    EndpointValidationReport {
        endpoint_name: "public-doh".to_string(),
        transport: "doh".to_string(),
        address: "https://dns.example/dns-query".to_string(),
        status: ValidationStatus::Mismatched,
        results: vec![mismatched_result],
        mismatches: vec![mismatch],
        skipped: vec![SkippedRecord {
            name: "dnskey.example.com".to_string(),
            record_type: "DNSKEY".to_string(),
            reason: "unsupported record type".to_string(),
        }],
        failures: vec![ValidationFailureKind::DohHttpFailure],
    }
}

fn validation_endpoint(transport: ValidationTransport) -> ValidationEndpointConfig {
    ValidationEndpointConfig {
        name: "test-endpoint".to_string(),
        transport,
        address: if matches!(transport, ValidationTransport::Doh) {
            String::new()
        } else {
            "127.0.0.1".to_string()
        },
        port: None,
        url: matches!(transport, ValidationTransport::Doh)
            .then(|| "https://127.0.0.1/dns-query".to_string()),
        tls_server_name: matches!(transport, ValidationTransport::Dot)
            .then(|| "dns.example.test".to_string()),
        enabled: true,
        timeout_ms: Some(10),
    }
}

#[fixture]
fn validation_report(
    endpoint_report: EndpointValidationReport,
    mismatch: RecordMismatch,
    mismatched_result: RecordValidationResult,
) -> ValidationReport {
    ValidationReport {
        enabled: true,
        status: ValidationStatus::Mismatched,
        zone: Some("example.com".to_string()),
        domain: Some("www.example.com".to_string()),
        phase: Some("transfer_pre".to_string()),
        endpoints: vec![endpoint_report],
        results: vec![mismatched_result],
        mismatches: vec![mismatch],
        skipped: vec![SkippedRecord {
            name: "dnskey.example.com".to_string(),
            record_type: "DNSKEY".to_string(),
            reason: "unsupported record type".to_string(),
        }],
        failures: vec![ValidationFailureKind::DohHttpFailure],
    }
}

fn zone_info() -> ZoneInfo {
    ZoneInfo {
        id: None,
        name: "example.test".to_string(),
        zone_type: "Primary".to_string(),
        disabled: false,
        dnssec_status: None,
    }
}

fn zone_record(name: &str, ttl: u32, data: RecordData) -> ZoneRecord {
    ZoneRecord {
        name: name.to_string(),
        record_type: data.type_name().to_string(),
        ttl,
        disabled: false,
        comments: String::new(),
        expiry_ttl: 0,
        data: serde_json::to_value(&data).expect("record data serializes"),
        parsed: Some(AnyRecordData::Writable(data)),
    }
}

fn list_response(records: Vec<ZoneRecord>) -> ListRecordsResponse {
    ListRecordsResponse {
        zones: vec![ZoneRecords {
            zone: zone_info(),
            records,
        }],
    }
}
