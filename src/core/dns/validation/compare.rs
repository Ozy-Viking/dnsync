//! record comparison and value normalization.

use super::*;

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
