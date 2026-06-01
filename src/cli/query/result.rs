//! query result block and status types.

use super::*;

/// Per-transport outcome for one block within a single `dns query`
/// invocation. The renderer turns these into header+rows / short
/// lines / JSON entries.
#[derive(Debug, Clone)]
pub struct QueryResultBlock {
    pub target_label: String,
    /// The configured server id this block was produced for, when the
    /// target was a named `[[servers]]` entry. `None` for the system
    /// resolver and ad-hoc targets. Used to disambiguate headers and
    /// JSON results when fanning out across multiple servers.
    pub server_id: Option<String>,
    /// The vendor of the named server, shown in multi-server `=== Server
    /// ===` group headers. `None` for system/ad-hoc targets.
    pub server_vendor: Option<VendorKind>,
    pub transport: ValidationTransport,
    pub extras: Vec<(String, String)>,
    pub url: Option<String>,
    pub host_for_json: Option<String>,
    pub port_for_json: Option<u16>,
    pub elapsed: Duration,
    pub status: QueryStatus,
    pub records: Vec<ObservedRecord>,
    pub asked_types: Vec<String>,
    /// The domain that was queried, kept so status rows (NXDOMAIN,
    /// TIMEOUT, …) can show the name on the left even when no answer
    /// records came back.
    pub queried_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryStatus {
    NoError,
    NxDomain,
    Servfail,
    Refused,
    Timeout,
    TlsFailure,
    DohHttpFailure,
    MalformedResponse,
    UnsupportedTransport,
    Skipped { reason: String },
}

impl QueryStatus {
    pub(crate) fn header_word(&self) -> Option<&str> {
        Some(match self {
            QueryStatus::NoError => return None,
            QueryStatus::NxDomain => "NXDOMAIN",
            QueryStatus::Servfail => "SERVFAIL",
            QueryStatus::Refused => "REFUSED",
            QueryStatus::Timeout => "TIMEOUT",
            QueryStatus::TlsFailure => "TLS_FAILURE",
            QueryStatus::DohHttpFailure => "HTTP_FAILURE",
            QueryStatus::MalformedResponse => "MALFORMED",
            QueryStatus::UnsupportedTransport => "UNSUPPORTED",
            QueryStatus::Skipped { .. } => "SKIPPED",
        })
    }

    pub(crate) fn json_tag(&self) -> &'static str {
        match self {
            QueryStatus::NoError => "noerror",
            QueryStatus::NxDomain => "nxdomain",
            QueryStatus::Servfail => "servfail",
            QueryStatus::Refused => "refused",
            QueryStatus::Timeout => "timeout",
            QueryStatus::TlsFailure => "tls_failure",
            QueryStatus::DohHttpFailure => "doh_http_failure",
            QueryStatus::MalformedResponse => "malformed_response",
            QueryStatus::UnsupportedTransport => "unsupported_transport",
            QueryStatus::Skipped { .. } => "skipped",
        }
    }

    /// Severity rank — `noerror` is best (0), failure modes worst.
    /// Used for the "worst across blocks" exit-code rule.
    pub(crate) fn severity(&self) -> u8 {
        match self {
            QueryStatus::NoError => 0,
            QueryStatus::Skipped { .. } => 1,
            QueryStatus::NxDomain => 2,
            QueryStatus::Servfail
            | QueryStatus::Refused
            | QueryStatus::Timeout
            | QueryStatus::TlsFailure
            | QueryStatus::DohHttpFailure
            | QueryStatus::MalformedResponse
            | QueryStatus::UnsupportedTransport => 3,
        }
    }
}

impl From<ValidationFailureKind> for QueryStatus {
    fn from(kind: ValidationFailureKind) -> Self {
        match kind {
            ValidationFailureKind::Timeout => QueryStatus::Timeout,
            ValidationFailureKind::Nxdomain => QueryStatus::NxDomain,
            ValidationFailureKind::Servfail => QueryStatus::Servfail,
            ValidationFailureKind::Refused => QueryStatus::Refused,
            ValidationFailureKind::TlsFailure => QueryStatus::TlsFailure,
            ValidationFailureKind::DohHttpFailure => QueryStatus::DohHttpFailure,
            ValidationFailureKind::MalformedResponse => QueryStatus::MalformedResponse,
            ValidationFailureKind::UnsupportedTransport => QueryStatus::UnsupportedTransport,
        }
    }
}

pub(crate) fn worst(a: QueryStatus, b: QueryStatus) -> QueryStatus {
    if a.severity() >= b.severity() { a } else { b }
}

pub(crate) fn exit_code_for(blocks: &[QueryResultBlock]) -> i32 {
    let mut worst = 0u8;
    for b in blocks {
        worst = worst.max(b.status.severity());
    }
    match worst {
        0 => 0,
        1 => 0, // implicit skip doesn't affect exit
        2 => 1, // NXDOMAIN
        _ => 2,
    }
}
