//! stable serializable validation report types.

use super::*;

fn default_enabled() -> bool {
    true
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
