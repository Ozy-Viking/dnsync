use super::*;

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
