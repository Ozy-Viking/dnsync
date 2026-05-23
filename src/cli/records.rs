//! CLI display for DNS records.

use clap::ValueEnum;
use clap::builder::PossibleValue;

use crate::core::dns::records::{
    DigestType, DsAlgorithm, FwdProtocol, SshfpAlgorithm, SshfpFingerprintType,
    TlsaCertUsage, TlsaMatchingType, TlsaSelector,
};
use crate::core::dns::responses::ListRecordsResponse;

macro_rules! impl_value_enum {
    ($ty:ty, [$($variant:expr),+ $(,)?]) => {
        impl ValueEnum for $ty {
            fn value_variants<'a>() -> &'a [Self]
            where
                Self: 'a,
            {
                &[$($variant),+]
            }

            fn to_possible_value(&self) -> Option<PossibleValue> {
                Some(PossibleValue::new(self.as_str()))
            }
        }
    };
}

impl_value_enum!(
    DsAlgorithm,
    [
        DsAlgorithm::Rsamd5,
        DsAlgorithm::Dsa,
        DsAlgorithm::Rsasha1,
        DsAlgorithm::DsaNsec3Sha1,
        DsAlgorithm::Rsasha1Nsec3Sha1,
        DsAlgorithm::Rsasha256,
        DsAlgorithm::Rsasha512,
        DsAlgorithm::EccGost,
        DsAlgorithm::Ecdsap256sha256,
        DsAlgorithm::Ecdsap384sha384,
        DsAlgorithm::Ed25519,
        DsAlgorithm::Ed448,
    ]
);

impl_value_enum!(
    DigestType,
    [
        DigestType::Sha1,
        DigestType::Sha256,
        DigestType::GostR341194,
        DigestType::Sha384,
    ]
);

impl_value_enum!(
    SshfpAlgorithm,
    [
        SshfpAlgorithm::Rsa,
        SshfpAlgorithm::Dsa,
        SshfpAlgorithm::Ecdsa,
        SshfpAlgorithm::Ed25519,
        SshfpAlgorithm::Ed448,
    ]
);

impl_value_enum!(
    SshfpFingerprintType,
    [SshfpFingerprintType::Sha1, SshfpFingerprintType::Sha256,]
);

impl_value_enum!(
    TlsaCertUsage,
    [
        TlsaCertUsage::PkixTa,
        TlsaCertUsage::PkixEe,
        TlsaCertUsage::DaneTa,
        TlsaCertUsage::DaneEe,
    ]
);

impl_value_enum!(TlsaSelector, [TlsaSelector::Cert, TlsaSelector::Spki]);

impl_value_enum!(
    TlsaMatchingType,
    [
        TlsaMatchingType::Full,
        TlsaMatchingType::Sha2_256,
        TlsaMatchingType::Sha2_512,
    ]
);

impl_value_enum!(
    FwdProtocol,
    [
        FwdProtocol::Udp,
        FwdProtocol::Tcp,
        FwdProtocol::Tls,
        FwdProtocol::Https,
        FwdProtocol::Quic,
    ]
);

// ─── Content extraction ───────────────────────────────────────────────────────

/// Returns a compact, human-readable string for the data portion of a record.
pub fn record_content(record_type: &str, data: &serde_json::Value) -> String {
    match record_type.to_uppercase().as_str() {
        "A" | "AAAA" => str_field(data, "ipAddress"),
        "CNAME" => str_field(data, "cname"),
        "ANAME" => str_field(data, "aname"),
        "DNAME" => str_field(data, "dname"),
        "NS" => str_field(data, "nameServer"),
        "PTR" => str_field(data, "ptrName"),
        "TXT" => str_field(data, "text"),
        "MX" => format!(
            "{} {}",
            data.get("preference")
                .and_then(|v| v.as_u64())
                .unwrap_or(10),
            str_field(data, "exchange"),
        ),
        "SRV" => format!(
            "{} {} {} {}",
            data.get("priority").and_then(|v| v.as_u64()).unwrap_or(0),
            data.get("weight").and_then(|v| v.as_u64()).unwrap_or(0),
            data.get("port").and_then(|v| v.as_u64()).unwrap_or(0),
            str_field(data, "target"),
        ),
        "CAA" => format!(
            "{} {} \"{}\"",
            data.get("flags").and_then(|v| v.as_u64()).unwrap_or(0),
            str_field(data, "tag"),
            str_field(data, "value"),
        ),
        "SSHFP" => format!(
            "{} {} {}",
            str_field(data, "sshfpAlgorithm"),
            str_field(data, "sshfpFingerprintType"),
            str_field(data, "sshfpFingerprint"),
        ),
        "TLSA" => format!(
            "{} {} {} {}",
            str_field(data, "tlsaCertificateUsage"),
            str_field(data, "tlsaSelector"),
            str_field(data, "tlsaMatchingType"),
            str_field(data, "tlsaCertificateAssociationData"),
        ),
        "DS" => format!(
            "{} {} {} {}",
            data.get("keyTag").and_then(|v| v.as_u64()).unwrap_or(0),
            str_field(data, "algorithm"),
            str_field(data, "digestType"),
            str_field(data, "digest"),
        ),
        "HTTPS" | "SVCB" => format!(
            "{} {}",
            data.get("svcPriority")
                .and_then(|v| v.as_u64())
                .unwrap_or(1),
            str_field(data, "svcTargetName"),
        ),
        "FWD" => str_field(data, "forwarder"),
        "NAPTR" => format!(
            "{} {} \"{}\" \"{}\" \"{}\" {}",
            data.get("naptrOrder").and_then(|v| v.as_u64()).unwrap_or(0),
            data.get("naptrPreference")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            str_field(data, "naptrFlags"),
            str_field(data, "naptrServices"),
            str_field(data, "naptrRegexp"),
            str_field(data, "naptrReplacement"),
        ),
        _ => {
            // Try a "value" key (Pangolin generic), then fall back to compact JSON.
            if let Some(v) = data.get("value").and_then(|v| v.as_str()) {
                return v.to_string();
            }
            serde_json::to_string(data).unwrap_or_default()
        }
    }
}

fn str_field(data: &serde_json::Value, key: &str) -> String {
    data.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

// ─── Table display ────────────────────────────────────────────────────────────

const COL_NAME: &str = "HOST";
const COL_TYPE: &str = "TYPE";
const COL_TTL: &str = "TTL";
const COL_DATA: &str = "DATA";

/// Print `response` as an aligned table.
///
/// Each zone gets its own header block. Disabled zones and records are
/// flagged inline.
pub fn print_records_table(response: &ListRecordsResponse) {
    let total = response.zones.len();

    for (i, zone_records) in response.zones.iter().enumerate() {
        let zone = &zone_records.zone;

        // Zone header.
        if zone.disabled {
            println!("Zone: {}  [{}]  [disabled]", zone.name, zone.zone_type);
        } else {
            println!("Zone: {}  [{}]", zone.name, zone.zone_type);
        }

        if zone_records.records.is_empty() {
            println!("  (no records)");
        } else {
            // Compute column widths.
            let name_w = zone_records
                .records
                .iter()
                .map(|r| r.name.len())
                .max()
                .unwrap_or(0)
                .max(COL_NAME.len());

            let type_w = zone_records
                .records
                .iter()
                .map(|r| r.record_type.len())
                .max()
                .unwrap_or(0)
                .max(COL_TYPE.len());

            let ttl_w = zone_records
                .records
                .iter()
                .map(|r| r.ttl.to_string().len())
                .max()
                .unwrap_or(0)
                .max(COL_TTL.len());

            // Header row.
            println!();
            println!(
                "{:<name_w$}  {:<type_w$}  {:>ttl_w$}  {}",
                COL_NAME, COL_TYPE, COL_TTL, COL_DATA,
            );
            println!("{}", "-".repeat(name_w + type_w + ttl_w + 8));

            // Data rows.
            for record in &zone_records.records {
                let content = record_content(&record.record_type, &record.data);
                let disabled = if record.disabled { "  [disabled]" } else { "" };

                println!(
                    "{:<name_w$}  {:<type_w$}  {:>ttl_w$}  {}{}",
                    record.name, record.record_type, record.ttl, content, disabled,
                );
            }
        }

        // Blank line between zones but not after the last one.
        if i + 1 < total {
            println!();
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::dns::records::RecordSelector;
    use rstest::rstest;
    use serde_json::json;

    #[rstest]
    #[case::a_none(RecordSelector::A { ip: None }, vec![("type", "A")])]
    #[case::a_some(
        RecordSelector::A { ip: Some("1.2.3.4".parse().unwrap()) },
        vec![("type", "A"), ("ipAddress", "1.2.3.4")]
    )]
    #[case::aaaa_some(
        RecordSelector::Aaaa { ip: Some("2001:db8::1".parse().unwrap()) },
        vec![("type", "AAAA"), ("ipAddress", "2001:db8::1")]
    )]
    #[case::mx_some(
        RecordSelector::Mx { exchange: Some("mail.example.com".into()) },
        vec![("type", "MX"), ("exchange", "mail.example.com")]
    )]
    #[case::txt_some(
        RecordSelector::Txt { text: Some("v=spf1 ~all".into()) },
        vec![("type", "TXT"), ("text", "v=spf1 ~all")]
    )]
    fn record_selector_to_api_params_matches_expected(
        #[case] selector: RecordSelector,
        #[case] expected: Vec<(&'static str, &'static str)>,
    ) {
        let actual = selector.to_api_params();
        let expected: Vec<(&str, String)> = expected
            .into_iter()
            .map(|(key, value)| (key, value.to_string()))
            .collect();

        assert_eq!(actual, expected);
    }

    #[test]
    fn a_record_content() {
        assert_eq!(
            record_content("A", &json!({"ipAddress": "1.2.3.4"})),
            "1.2.3.4"
        );
    }

    #[test]
    fn aaaa_record_content() {
        assert_eq!(
            record_content("AAAA", &json!({"ipAddress": "2001:db8::1"})),
            "2001:db8::1"
        );
    }

    #[test]
    fn cname_record_content() {
        assert_eq!(
            record_content("CNAME", &json!({"cname": "target.example.com"})),
            "target.example.com"
        );
    }

    #[test]
    fn mx_record_content_includes_preference() {
        assert_eq!(
            record_content(
                "MX",
                &json!({"preference": 10, "exchange": "mail.example.com"})
            ),
            "10 mail.example.com"
        );
    }

    #[test]
    fn mx_record_content_defaults_preference_to_10() {
        assert_eq!(
            record_content("MX", &json!({"exchange": "mail.example.com"})),
            "10 mail.example.com"
        );
    }

    #[test]
    fn txt_record_content() {
        assert_eq!(
            record_content("TXT", &json!({"text": "v=spf1 ~all"})),
            "v=spf1 ~all"
        );
    }

    #[test]
    fn ns_record_content() {
        assert_eq!(
            record_content(
                "NS",
                &json!({"nameServer": "ns1.example.com", "glue": null})
            ),
            "ns1.example.com"
        );
    }

    #[test]
    fn srv_record_content() {
        assert_eq!(
            record_content(
                "SRV",
                &json!({"priority": 10, "weight": 20, "port": 5060, "target": "sip.example.com"})
            ),
            "10 20 5060 sip.example.com"
        );
    }

    #[test]
    fn caa_record_content() {
        assert_eq!(
            record_content(
                "CAA",
                &json!({"flags": 0, "tag": "issue", "value": "letsencrypt.org"})
            ),
            "0 issue \"letsencrypt.org\""
        );
    }

    #[test]
    fn ds_record_content() {
        assert_eq!(
            record_content(
                "DS",
                &json!({"keyTag": 12345, "algorithm": "RSASHA256", "digestType": "SHA256", "digest": "abcdef"})
            ),
            "12345 RSASHA256 SHA256 abcdef"
        );
    }

    #[test]
    fn fwd_record_content() {
        assert_eq!(
            record_content("FWD", &json!({"forwarder": "1.1.1.1"})),
            "1.1.1.1"
        );
    }

    #[test]
    fn unknown_type_falls_back_to_value_key() {
        assert_eq!(
            record_content("CUSTOM", &json!({"value": "some-data"})),
            "some-data"
        );
    }

    #[test]
    fn unknown_type_falls_back_to_json() {
        let data = json!({"field": "x"});
        let result = record_content("MYSTERY", &data);
        assert!(result.contains("field"));
    }

    #[test]
    fn naptr_record_content() {
        assert_eq!(
            record_content(
                "NAPTR",
                &json!({
                    "naptrOrder": 10,
                    "naptrPreference": 20,
                    "naptrFlags": "U",
                    "naptrServices": "E2U+sip",
                    "naptrRegexp": "!^.*$!sip:info@example.com!",
                    "naptrReplacement": "."
                })
            ),
            "10 20 \"U\" \"E2U+sip\" \"!^.*$!sip:info@example.com!\" ."
        );
    }

    #[test]
    fn record_content_is_case_insensitive() {
        assert_eq!(
            record_content("a", &json!({"ipAddress": "1.2.3.4"})),
            record_content("A", &json!({"ipAddress": "1.2.3.4"}))
        );
    }
}
