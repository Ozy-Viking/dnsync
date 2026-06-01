use super::*;

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
#[case::unsupported_transport(ValidationFailureKind::UnsupportedTransport, "unsupported_transport")]
fn validation_failure_kind_serializes_snake_case(
    #[case] failure_kind: ValidationFailureKind,
    #[case] expected: &str,
) {
    assert_eq!(
        serde_json::to_value(failure_kind).expect("failure kind serializes"),
        Value::String(expected.to_string())
    );
}
