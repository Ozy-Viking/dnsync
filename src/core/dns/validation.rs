//! Stable domain types for DNS endpoint validation reports.
//!
//! This module contains stable serializable data shapes and resolver endpoint
//! abstractions. Record comparison logic lives in later validation layers.

use std::{future::Future, time::Duration};

use hickory_resolver::{Resolver, net::runtime::TokioRuntimeProvider, proto::rr::RecordType};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    control_plane::config::ValidationEndpointConfig,
    core::dns::{
        records::RecordData,
        resolver::{ResolverTarget, build_resolver, classify_hickory_error},
        responses::{AnyRecordData, ListRecordsResponse, ZoneRecord},
    },
};

fn default_enabled() -> bool {
    true
}

/// Result type returned by endpoint resolvers.
pub type DnsEndpointResolverResult<T> = std::result::Result<T, ValidationFailureKind>;

/// Async DNS endpoint resolver abstraction used by validation code.
///
/// Implementations query one configured endpoint for one FQDN and record type.
/// Tests can implement this trait without opening network sockets.
pub trait DnsEndpointResolver {
    /// Query a validation endpoint for records visible at that endpoint.
    fn query_endpoint<'a>(
        &'a self,
        endpoint: &'a ValidationEndpointConfig,
        fqdn: &'a str,
        record_type: &'a str,
        timeout: Duration,
    ) -> impl Future<Output = DnsEndpointResolverResult<Vec<ObservedRecord>>> + Send + 'a;
}
/// Production resolver backed by Hickory's async Tokio resolver.
#[derive(Debug, Clone, Copy, Default)]
pub struct HickoryDnsEndpointResolver;

impl HickoryDnsEndpointResolver {
    /// Build a production Hickory resolver for one validation endpoint.
    ///
    /// Delegates to [`build_resolver`] via a [`ResolverTarget`] derived
    /// from the legacy endpoint shape; behaviour is unchanged.
    pub fn resolver_for_endpoint(
        endpoint: &ValidationEndpointConfig,
        timeout: Duration,
    ) -> DnsEndpointResolverResult<Resolver<TokioRuntimeProvider>> {
        let mut target = ResolverTarget::from_endpoint(endpoint);
        target.timeout = timeout;
        build_resolver(&target)
    }
}

impl DnsEndpointResolver for HickoryDnsEndpointResolver {
    fn query_endpoint<'a>(
        &'a self,
        endpoint: &'a ValidationEndpointConfig,
        fqdn: &'a str,
        record_type: &'a str,
        timeout: Duration,
    ) -> impl Future<Output = DnsEndpointResolverResult<Vec<ObservedRecord>>> + Send + 'a {
        async move {
            let rr_type = record_type
                .parse::<RecordType>()
                .map_err(|_| ValidationFailureKind::MalformedResponse)?;
            let resolver = Self::resolver_for_endpoint(endpoint, timeout)?;

            let lookup = tokio::time::timeout(timeout, resolver.lookup(fqdn, rr_type))
                .await
                .map_err(|_| ValidationFailureKind::Timeout)?
                .map_err(|err| classify_hickory_error(endpoint.transport, &err.to_string()))?;

            Ok(lookup
                .answers()
                .iter()
                .map(|record| ObservedRecord {
                    name: record.name.to_string(),
                    record_type: record.record_type().to_string(),
                    ttl: Some(record.ttl),
                    values: vec![record.data.to_string()],
                })
                .collect())
        }
    }
}

/// Return the configured endpoint timeout, defaulting to five seconds.
#[must_use]
pub fn endpoint_timeout(endpoint: &ValidationEndpointConfig) -> Duration {
    Duration::from_millis(endpoint.timeout_ms.unwrap_or(5_000))
}

/// Convert provider/API records into validation expected RRsets.
#[must_use]
pub fn expected_records_from_response(
    response: &ListRecordsResponse,
) -> (Vec<ExpectedRecord>, Vec<SkippedRecord>) {
    let mut expected = Vec::new();
    let mut skipped = Vec::new();

    for zone_records in &response.zones {
        for record in &zone_records.records {
            match expected_record_from_zone_record(&zone_records.zone.name, record) {
                Ok(record) => expected.push(record),
                Err(skip) => skipped.push(skip),
            }
        }
    }

    (expected, skipped)
}

/// Compare normalized expected and observed RRsets, ignoring TTL.
#[must_use]
pub fn compare_rrsets(
    expected: &[ExpectedRecord],
    observed: &[ObservedRecord],
) -> Vec<RecordValidationResult> {
    use std::collections::{BTreeMap, BTreeSet};

    let expected_sets = expected.iter().fold(BTreeMap::new(), |mut acc, record| {
        let key = normalized_rrset_key(&record.name, &record.record_type);
        let values = normalize_values(&record.record_type, &record.values);
        acc.entry(key).or_insert_with(BTreeSet::new).extend(values);
        acc
    });
    let observed_sets = observed.iter().fold(BTreeMap::new(), |mut acc, record| {
        let key = normalized_rrset_key(&record.name, &record.record_type);
        let values = normalize_values(&record.record_type, &record.values);
        acc.entry(key).or_insert_with(BTreeSet::new).extend(values);
        acc
    });

    let mut results = Vec::new();
    for ((name, record_type), expected_values) in &expected_sets {
        let observed_values = observed_sets
            .get(&(name.clone(), record_type.clone()))
            .cloned()
            .unwrap_or_default();

        if observed_values.is_empty() {
            results.push(mismatched_result(
                name,
                record_type,
                expected_values,
                &observed_values,
                "missing",
            ));
        } else if expected_values == &observed_values {
            results.push(RecordValidationResult {
                name: name.clone(),
                record_type: record_type.clone(),
                status: ValidationStatus::Passed,
                mismatch: None,
                failure_kind: None,
                skip_reason: None,
            });
        } else {
            let mismatch_kind = if !expected_values.is_subset(&observed_values) {
                "wrong_value"
            } else {
                "extra"
            };
            results.push(mismatched_result(
                name,
                record_type,
                expected_values,
                &observed_values,
                mismatch_kind,
            ));
        }
    }

    for ((name, record_type), observed_values) in observed_sets {
        if !expected_sets.contains_key(&(name.clone(), record_type.clone())) {
            results.push(mismatched_result(
                &name,
                &record_type,
                &BTreeSet::new(),
                &observed_values,
                "extra",
            ));
        }
    }

    results
}

fn expected_record_from_zone_record(
    zone: &str,
    record: &ZoneRecord,
) -> std::result::Result<ExpectedRecord, SkippedRecord> {
    let record_type = record.record_type.to_ascii_uppercase();
    let name = normalize_domain_name(&fqdn_for_record(&record.name, zone));
    let values = match record.parsed.as_ref() {
        Some(AnyRecordData::Writable(data)) => values_from_record_data(data),
        Some(AnyRecordData::ReadOnly(_)) | None => None,
    };

    match values {
        Some(values) => Ok(ExpectedRecord {
            name,
            record_type,
            values,
        }),
        None => Err(SkippedRecord {
            name,
            record_type,
            reason: "unsupported_record_type".to_string(),
        }),
    }
}

fn values_from_record_data(record: &RecordData) -> Option<Vec<String>> {
    match record {
        RecordData::A { ip } => Some(vec![ip.to_string()]),
        RecordData::Aaaa { ip } => Some(vec![ip.to_string()]),
        RecordData::Cname { target } => Some(vec![target.clone()]),
        RecordData::Txt { text, .. } => Some(vec![text.clone()]),
        RecordData::Mx {
            preference,
            exchange,
        } => Some(vec![format!("{preference} {exchange}")]),
        RecordData::Ns { nameserver, .. } => Some(vec![nameserver.clone()]),
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => Some(vec![format!("{priority} {weight} {port} {target}")]),
        RecordData::Caa { flags, tag, value } => Some(vec![format!("{flags} {tag} {value}")]),
        _ => None,
    }
}

fn mismatched_result(
    name: &str,
    record_type: &str,
    expected: &std::collections::BTreeSet<String>,
    observed: &std::collections::BTreeSet<String>,
    mismatch_kind: &str,
) -> RecordValidationResult {
    RecordValidationResult {
        name: name.to_string(),
        record_type: record_type.to_string(),
        status: ValidationStatus::Mismatched,
        mismatch: Some(RecordMismatch {
            name: name.to_string(),
            record_type: record_type.to_string(),
            expected: expected.iter().cloned().collect(),
            observed: observed.iter().cloned().collect(),
            mismatch_kind: mismatch_kind.to_string(),
        }),
        failure_kind: None,
        skip_reason: None,
    }
}

fn normalized_rrset_key(name: &str, record_type: &str) -> (String, String) {
    (
        normalize_domain_name(name),
        record_type.trim().to_ascii_uppercase(),
    )
}

fn normalize_values(record_type: &str, values: &[String]) -> std::collections::BTreeSet<String> {
    values
        .iter()
        .map(|value| normalize_record_value(record_type, value))
        .collect()
}

fn normalize_record_value(record_type: &str, value: &str) -> String {
    let value = value.trim();
    match record_type.to_ascii_uppercase().as_str() {
        "CNAME" | "NS" => normalize_domain_name(value),
        "MX" => normalize_priority_target(value),
        "SRV" => normalize_srv(value),
        "TXT" => normalize_txt(value),
        "CAA" => normalize_caa(value),
        _ => value.trim_end_matches('.').to_ascii_lowercase(),
    }
}

fn normalize_domain_name(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_priority_target(value: &str) -> String {
    let mut parts = value.split_whitespace();
    let preference = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    format!("{} {}", preference, normalize_domain_name(target))
}

fn normalize_srv(value: &str) -> String {
    let mut parts = value.split_whitespace();
    let priority = parts.next().unwrap_or_default();
    let weight = parts.next().unwrap_or_default();
    let port = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    format!(
        "{} {} {} {}",
        priority,
        weight,
        port,
        normalize_domain_name(target)
    )
}

fn normalize_txt(value: &str) -> String {
    value
        .trim()
        .replace("\" \"", "")
        .trim_matches('"')
        .to_string()
}

fn normalize_caa(value: &str) -> String {
    let mut parts = value.split_whitespace();
    let flags = parts.next().unwrap_or_default();
    let tag = parts.next().unwrap_or_default().to_ascii_lowercase();
    let value = parts.collect::<Vec<_>>().join(" ");
    format!("{flags} {tag} {value}")
}

fn fqdn_for_record(name: &str, zone: &str) -> String {
    let name = name.trim_end_matches('.');
    let zone = zone.trim_end_matches('.');
    if name == "@" || name.eq_ignore_ascii_case(zone) {
        zone.to_string()
    } else if name
        .to_ascii_lowercase()
        .ends_with(&format!(".{}", zone.to_ascii_lowercase()))
    {
        name.to_string()
    } else {
        format!("{name}.{zone}")
    }
}

/// Deterministic resolver helper for unit tests.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct FakeDnsEndpointResolver {
    result: DnsEndpointResolverResult<Vec<ObservedRecord>>,
}

#[cfg(test)]
impl FakeDnsEndpointResolver {
    pub fn with_records(records: Vec<ObservedRecord>) -> Self {
        Self {
            result: Ok(records),
        }
    }

    pub fn with_failure(failure: ValidationFailureKind) -> Self {
        Self {
            result: Err(failure),
        }
    }
}

#[cfg(test)]
impl DnsEndpointResolver for FakeDnsEndpointResolver {
    fn query_endpoint(
        &self,
        _endpoint: &ValidationEndpointConfig,
        _fqdn: &str,
        _record_type: &str,
        _timeout: Duration,
    ) -> impl Future<Output = DnsEndpointResolverResult<Vec<ObservedRecord>>> + Send + '_ {
        std::future::ready(self.result.clone())
    }
}

/// Options that control whether and where validation runs.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValidationOptions {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_filter: Option<Vec<String>>,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint_filter: None,
        }
    }
}

/// Validation input for a record list, import, export, or transfer phase.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValidationRequest {
    pub zone: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default)]
    pub expected_records: Vec<ExpectedRecord>,
    #[serde(default)]
    pub options: ValidationOptions,
}

/// A DNS record expected to be visible at a validation endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedRecord {
    pub name: String,
    pub record_type: String,
    pub values: Vec<String>,
}

/// A DNS record observed from a validation endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ObservedRecord {
    pub name: String,
    pub record_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    pub values: Vec<String>,
}

/// Stable validation status values used at report, endpoint, and record level.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ValidationStatus {
    Passed,
    Mismatched,
    Skipped,
    Failed,
}

/// Stable categories for endpoint-level validation failures.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ValidationFailureKind {
    Timeout,
    Nxdomain,
    Servfail,
    Refused,
    TlsFailure,
    DohHttpFailure,
    MalformedResponse,
    UnsupportedTransport,
}

/// A difference between expected and observed DNS record values.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecordMismatch {
    pub name: String,
    pub record_type: String,
    pub expected: Vec<String>,
    pub observed: Vec<String>,
    pub mismatch_kind: String,
}

/// A record that validation intentionally skipped.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SkippedRecord {
    pub name: String,
    pub record_type: String,
    pub reason: String,
}

/// Validation result for one expected record.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecordValidationResult {
    pub name: String,
    pub record_type: String,
    pub status: ValidationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mismatch: Option<RecordMismatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_kind: Option<ValidationFailureKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

/// Validation results collected from one configured endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EndpointValidationReport {
    pub endpoint_name: String,
    pub transport: String,
    pub address: String,
    pub status: ValidationStatus,
    #[serde(default)]
    pub results: Vec<RecordValidationResult>,
    #[serde(default)]
    pub mismatches: Vec<RecordMismatch>,
    #[serde(default)]
    pub skipped: Vec<SkippedRecord>,
    #[serde(default)]
    pub failures: Vec<ValidationFailureKind>,
}

/// Stable validation report shape for record lists and transfer pre/post checks.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValidationReport {
    pub enabled: bool,
    pub status: ValidationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Optional report phase, such as `record_list`, `transfer_pre`, or `transfer_post`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(default)]
    pub endpoints: Vec<EndpointValidationReport>,
    #[serde(default)]
    pub results: Vec<RecordValidationResult>,
    #[serde(default)]
    pub mismatches: Vec<RecordMismatch>,
    #[serde(default)]
    pub skipped: Vec<SkippedRecord>,
    #[serde(default)]
    pub failures: Vec<ValidationFailureKind>,
}

impl ValidationReport {
    /// Build a report for validation explicitly disabled by caller options.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            status: ValidationStatus::Skipped,
            zone: None,
            domain: None,
            phase: None,
            endpoints: Vec::new(),
            results: Vec::new(),
            mismatches: Vec::new(),
            skipped: vec![SkippedRecord {
                name: "*".to_string(),
                record_type: "*".to_string(),
                reason: "validation_disabled".to_string(),
            }],
            failures: Vec::new(),
        }
    }

    /// Build a report for enabled validation with no configured endpoints.
    #[must_use]
    pub fn skipped_no_endpoints() -> Self {
        Self::skipped("no_validation_endpoints_configured")
    }

    /// Build a report for enabled validation skipped for a specific reason.
    #[must_use]
    pub fn skipped(reason: &str) -> Self {
        Self {
            enabled: true,
            status: ValidationStatus::Skipped,
            zone: None,
            domain: None,
            phase: None,
            endpoints: Vec::new(),
            results: Vec::new(),
            mismatches: Vec::new(),
            skipped: vec![SkippedRecord {
                name: "*".to_string(),
                record_type: "*".to_string(),
                reason: reason.to_string(),
            }],
            failures: Vec::new(),
        }
    }

    /// Return the aggregate report status.
    #[must_use]
    pub const fn overall_status(&self) -> &ValidationStatus {
        &self.status
    }

    /// Whether validation completed without mismatches, failures, or skips.
    #[must_use]
    pub fn is_passed(&self) -> bool {
        self.status == ValidationStatus::Passed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::config::ValidationTransport;
    use crate::core::dns::responses::{ZoneInfo, ZoneRecords};
    use rstest::{fixture, rstest};
    use serde_json::{Value, json};
    use std::net::{Ipv4Addr, Ipv6Addr};

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

    #[rstest]
    fn validation_report_json_shape(validation_report: ValidationReport) {
        let value = serde_json::to_value(validation_report).expect("report serializes to JSON");

        assert_eq!(value["enabled"], json!(true));
        assert_eq!(value["status"], json!("mismatched"));
        assert_eq!(value["phase"], json!("transfer_pre"));
        assert!(value["endpoints"].is_array());
        assert!(value["results"].is_array());
        assert!(value["mismatches"].is_array());
        assert!(value["skipped"].is_array());
        assert!(value["failures"].is_array());
        assert_eq!(value["failures"][0], json!("doh_http_failure"));
        assert_eq!(value["results"][0]["status"], json!("mismatched"));
        assert_eq!(value["mismatches"][0]["mismatchKind"], json!("wrong_value"));
        assert_eq!(value["endpoints"][0]["endpointName"], json!("public-doh"));
    }

    #[rstest]
    fn validation_disabled_report_shape() {
        let report = ValidationReport::disabled();
        let value = serde_json::to_value(&report).expect("disabled report serializes to JSON");

        assert!(!report.enabled);
        assert_eq!(report.overall_status(), &ValidationStatus::Skipped);
        assert_eq!(value["enabled"], json!(false));
        assert_eq!(value["status"], json!("skipped"));
        assert_eq!(value["endpoints"], json!([]));
        assert_eq!(value["results"], json!([]));
        assert_eq!(value["mismatches"], json!([]));
        assert_eq!(value["skipped"][0]["reason"], json!("validation_disabled"));
        assert_eq!(value["failures"], json!([]));
    }

    #[rstest]
    fn skipped_no_endpoints_report_shape() {
        let value = serde_json::to_value(ValidationReport::skipped_no_endpoints())
            .expect("skipped report serializes to JSON");

        assert_eq!(value["enabled"], json!(true));
        assert_eq!(value["status"], json!("skipped"));
        assert_eq!(
            value["skipped"][0]["reason"],
            json!("no_validation_endpoints_configured")
        );
    }

    #[rstest]
    fn validation_options_default_is_enabled() {
        assert_eq!(ValidationOptions::default().enabled, true);

        let parsed: ValidationOptions =
            serde_json::from_value(json!({})).expect("empty validation options use defaults");

        assert!(parsed.enabled);
        assert_eq!(parsed.endpoint_filter, None);
    }

    #[rstest]
    fn validation_request_defaults_options(expected_record: ExpectedRecord) {
        let request: ValidationRequest = serde_json::from_value(json!({
            "zone": "example.com",
            "expectedRecords": [expected_record]
        }))
        .expect("request deserializes with default options");

        assert!(request.options.enabled);
        assert_eq!(request.domain, None);
        assert_eq!(request.expected_records.len(), 1);
    }

    #[tokio::test]
    async fn validation_resolver_plain_dns_fake() {
        let endpoint = validation_endpoint(ValidationTransport::Dns);
        let expected = vec![ObservedRecord {
            name: "www.example.com".to_string(),
            record_type: "A".to_string(),
            ttl: None,
            values: vec!["192.0.2.10".to_string()],
        }];
        let resolver = FakeDnsEndpointResolver::with_records(expected.clone());

        let observed = resolver
            .query_endpoint(
                &endpoint,
                "www.example.com",
                "A",
                endpoint_timeout(&endpoint),
            )
            .await
            .expect("fake resolver returns deterministic records");

        assert_eq!(observed, expected);
    }

    #[tokio::test]
    async fn validation_resolver_doh_http_500_failure() {
        let endpoint = validation_endpoint(ValidationTransport::Doh);
        let resolver = FakeDnsEndpointResolver::with_failure(ValidationFailureKind::DohHttpFailure);

        let failure = resolver
            .query_endpoint(
                &endpoint,
                "www.example.com",
                "A",
                endpoint_timeout(&endpoint),
            )
            .await
            .expect_err("fake resolver returns deterministic DoH failure");

        assert_eq!(failure, ValidationFailureKind::DohHttpFailure);
    }

    #[tokio::test]
    async fn validation_resolver_dot_tls_failure() {
        let endpoint = validation_endpoint(ValidationTransport::Dot);
        let resolver = FakeDnsEndpointResolver::with_failure(ValidationFailureKind::TlsFailure);

        let failure = resolver
            .query_endpoint(
                &endpoint,
                "www.example.com",
                "A",
                endpoint_timeout(&endpoint),
            )
            .await
            .expect_err("fake resolver returns deterministic DoT failure");

        assert_eq!(failure, ValidationFailureKind::TlsFailure);
    }

    #[tokio::test]
    async fn validation_resolver_timeout_failure() {
        let endpoint = validation_endpoint(ValidationTransport::Dns);
        let resolver = FakeDnsEndpointResolver::with_failure(ValidationFailureKind::Timeout);

        let failure = resolver
            .query_endpoint(
                &endpoint,
                "www.example.com",
                "A",
                endpoint_timeout(&endpoint),
            )
            .await
            .expect_err("fake resolver returns deterministic timeout");

        assert_eq!(failure, ValidationFailureKind::Timeout);
    }

    #[rstest]
    fn validation_compare_exact_match() {
        let response = list_response(vec![
            zone_record(
                "@",
                300,
                RecordData::A {
                    ip: Ipv4Addr::new(192, 0, 2, 10),
                },
            ),
            zone_record(
                "@",
                300,
                RecordData::Aaaa {
                    ip: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0010),
                },
            ),
            zone_record(
                "www",
                300,
                RecordData::Cname {
                    target: "example.test.".to_string(),
                },
            ),
            zone_record(
                "@",
                300,
                RecordData::Mx {
                    preference: 10,
                    exchange: "mail.example.test.".to_string(),
                },
            ),
            zone_record(
                "@",
                300,
                RecordData::Txt {
                    text: "dnsync-validation-test".to_string(),
                    split_text: false,
                },
            ),
        ]);
        let (expected, skipped) = expected_records_from_response(&response);
        let observed = expected
            .iter()
            .map(|record| ObservedRecord {
                name: record.name.clone(),
                record_type: record.record_type.clone(),
                ttl: None,
                values: record.values.clone(),
            })
            .collect::<Vec<_>>();

        let results = compare_rrsets(&expected, &observed);

        assert!(skipped.is_empty());
        assert_eq!(results.len(), 5);
        assert!(
            results
                .iter()
                .all(|result| result.status == ValidationStatus::Passed)
        );
    }

    #[rstest]
    fn validation_compare_missing_extra_wrong_value() {
        let expected = vec![
            ExpectedRecord {
                name: "example.test".to_string(),
                record_type: "A".to_string(),
                values: vec!["192.0.2.10".to_string()],
            },
            ExpectedRecord {
                name: "www.example.test".to_string(),
                record_type: "CNAME".to_string(),
                values: vec!["example.test".to_string()],
            },
        ];
        let observed = vec![
            ObservedRecord {
                name: "example.test".to_string(),
                record_type: "A".to_string(),
                ttl: None,
                values: vec!["192.0.2.99".to_string()],
            },
            ObservedRecord {
                name: "extra.example.test".to_string(),
                record_type: "AAAA".to_string(),
                ttl: None,
                values: vec!["2001:db8::99".to_string()],
            },
        ];

        let results = compare_rrsets(&expected, &observed);
        let kinds = results
            .iter()
            .filter_map(|result| result.mismatch.as_ref())
            .map(|mismatch| mismatch.mismatch_kind.as_str())
            .collect::<Vec<_>>();

        assert_eq!(results.len(), 3);
        assert!(kinds.contains(&"wrong_value"));
        assert!(kinds.contains(&"missing"));
        assert!(kinds.contains(&"extra"));
    }

    #[rstest]
    fn validation_skips_unsupported_types() {
        let response = list_response(vec![zone_record(
            "@",
            300,
            RecordData::Unknown {
                rdata: "00ff".to_string(),
            },
        )]);

        let (expected, skipped) = expected_records_from_response(&response);

        assert!(expected.is_empty());
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].record_type, "UNKNOWN");
        assert_eq!(skipped[0].reason, "unsupported_record_type");
    }

    #[rstest]
    fn validation_ignores_ttl_differences() {
        let response = list_response(vec![zone_record(
            "@",
            30,
            RecordData::A {
                ip: Ipv4Addr::new(192, 0, 2, 10),
            },
        )]);
        let (expected, skipped) = expected_records_from_response(&response);
        let observed = vec![ObservedRecord {
            name: "example.test.".to_string(),
            record_type: "a".to_string(),
            ttl: Some(999),
            values: vec!["192.0.2.10".to_string()],
        }];

        let results = compare_rrsets(&expected, &observed);

        assert!(skipped.is_empty());
        assert_eq!(results[0].status, ValidationStatus::Passed);
    }

    #[rstest]
    fn validation_normalizes_txt_mx_srv_cname_ns() {
        let response = list_response(vec![
            zone_record(
                "www",
                300,
                RecordData::Cname {
                    target: "Example.TEST.".to_string(),
                },
            ),
            zone_record(
                "@",
                300,
                RecordData::Txt {
                    text: "dnsync-validation-test".to_string(),
                    split_text: true,
                },
            ),
            zone_record(
                "@",
                300,
                RecordData::Mx {
                    preference: 10,
                    exchange: "Mail.Example.Test.".to_string(),
                },
            ),
            zone_record(
                "@",
                300,
                RecordData::Ns {
                    nameserver: "NS1.Example.Test.".to_string(),
                    glue: None,
                },
            ),
            zone_record(
                "_sip._tcp",
                300,
                RecordData::Srv {
                    priority: 10,
                    weight: 20,
                    port: 5060,
                    target: "Sip.Example.Test.".to_string(),
                },
            ),
        ]);
        let (expected, skipped) = expected_records_from_response(&response);
        let observed = vec![
            ObservedRecord {
                name: "WWW.EXAMPLE.TEST.".to_string(),
                record_type: "cname".to_string(),
                ttl: None,
                values: vec!["example.test".to_string()],
            },
            ObservedRecord {
                name: "example.test".to_string(),
                record_type: "TXT".to_string(),
                ttl: None,
                values: vec!["\"dnsync-\" \"validation-test\"".to_string()],
            },
            ObservedRecord {
                name: "example.test".to_string(),
                record_type: "MX".to_string(),
                ttl: None,
                values: vec!["10 mail.example.test".to_string()],
            },
            ObservedRecord {
                name: "example.test".to_string(),
                record_type: "NS".to_string(),
                ttl: None,
                values: vec!["ns1.example.test".to_string()],
            },
            ObservedRecord {
                name: "_sip._tcp.example.test".to_string(),
                record_type: "SRV".to_string(),
                ttl: None,
                values: vec!["10 20 5060 sip.example.test".to_string()],
            },
        ];

        let results = compare_rrsets(&expected, &observed);

        assert!(skipped.is_empty());
        assert_eq!(results.len(), 5);
        assert!(
            results
                .iter()
                .all(|result| result.status == ValidationStatus::Passed)
        );
    }

    #[rstest]
    #[case::passed(ValidationStatus::Passed, "passed")]
    #[case::mismatched(ValidationStatus::Mismatched, "mismatched")]
    #[case::skipped(ValidationStatus::Skipped, "skipped")]
    #[case::failed(ValidationStatus::Failed, "failed")]
    fn validation_status_serializes_lowercase(
        #[case] status: ValidationStatus,
        #[case] expected: &str,
    ) {
        assert_eq!(
            serde_json::to_value(status).expect("status serializes"),
            Value::String(expected.to_string())
        );
    }

    #[rstest]
    #[case::timeout(ValidationFailureKind::Timeout, "timeout")]
    #[case::nxdomain(ValidationFailureKind::Nxdomain, "nxdomain")]
    #[case::servfail(ValidationFailureKind::Servfail, "servfail")]
    #[case::refused(ValidationFailureKind::Refused, "refused")]
    #[case::tls_failure(ValidationFailureKind::TlsFailure, "tls_failure")]
    #[case::doh_http_failure(ValidationFailureKind::DohHttpFailure, "doh_http_failure")]
    #[case::malformed_response(ValidationFailureKind::MalformedResponse, "malformed_response")]
    #[case::unsupported_transport(
        ValidationFailureKind::UnsupportedTransport,
        "unsupported_transport"
    )]
    fn validation_failure_kind_serializes_snake_case(
        #[case] failure_kind: ValidationFailureKind,
        #[case] expected: &str,
    ) {
        assert_eq!(
            serde_json::to_value(failure_kind).expect("failure kind serializes"),
            Value::String(expected.to_string())
        );
    }
}
