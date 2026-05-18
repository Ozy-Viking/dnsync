use miette::Diagnostic;
use thiserror::Error;

/// All errors that can be produced by this crate.
#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    /// An operation was blocked by the active server policy (read-only or zone restriction).
    #[error("policy violation: {reason}")]
    #[diagnostic(code(dns::policy), help("{hint}"))]
    PolicyViolation { reason: String, hint: String },

    /// The Technitium API returned `{"status":"error","errorMessage":"..."}`.
    #[error("API error: {message}")]
    #[diagnostic(
        code(dns::api),
        help(
            "Check the Technitium server logs for more details.\n\
              Common causes: invalid zone name, record conflict, insufficient permissions."
        )
    )]
    Api { message: String },

    /// The server returned a non-2xx HTTP status with no API-level error body.
    #[error("HTTP {status}: {body}")]
    #[diagnostic(
        code(dns::http),
        help(
            "Verify the server is running and TECHNITIUM_BASE_URL is correct.\n\
              Use RUST_LOG=debug for full request details."
        )
    )]
    Http { status: u16, body: String },

    /// A network-level failure — connection refused, timeout, DNS resolution, etc.
    #[error("network error: {0}")]
    #[diagnostic(
        code(dns::network),
        help(
            "Check that the server is reachable at the configured base URL.\n\
              If using TLS, verify the certificate is trusted."
        )
    )]
    Network(#[source] reqwest::Error),

    /// The HTTP response body could not be decoded as JSON.
    #[error("invalid JSON response from server")]
    #[diagnostic(
        code(dns::invalid_json),
        help(
            "The server returned a response that isn't valid JSON.\n\
              Verify the base URL points to the API, not a proxy or redirect."
        )
    )]
    InvalidJson(#[source] reqwest::Error),

    /// A well-formed API response could not be parsed into the expected shape.
    #[error("parse error: {context}")]
    #[diagnostic(
        code(dns::parse),
        help(
            "The API response had an unexpected structure. This may indicate a \
              version mismatch between this client and the Technitium server."
        )
    )]
    Parse { context: String },

    /// The config file could not be read or is structurally invalid.
    #[error("config error: {context}")]
    #[diagnostic(
        code(dns::config),
        help(
            "Check the config file syntax and field names.\n\
              Run `dns config print` to inspect the parsed result, or\n\
              `dns config init` to regenerate a starter template."
        )
    )]
    Config { context: String },

    /// A MIME type string was rejected by reqwest (should never happen in practice).
    #[error("invalid MIME type")]
    #[diagnostic(code(dns::mime))]
    Mime(#[source] reqwest::Error),

    /// An operation not supported by this vendor backend.
    #[error("operation not supported by {vendor}: {feature}")]
    #[diagnostic(
        code(dns::unsupported),
        help("This vendor does not support this operation.")
    )]
    Unsupported {
        vendor: &'static str,
        feature: &'static str,
    },

    /// The API token lacks the required permissions (HTTP 403).
    #[error("forbidden: {message}")]
    #[diagnostic(
        code(dns::forbidden),
        help(
            "The API key does not have sufficient permissions.\n\
              Check that the token has the access level required for this operation."
        )
    )]
    Forbidden { message: String },

    /// An I/O error — typically reading a zone file from disk.
    #[error("{context}")]
    #[diagnostic(code(dns::io), help("Check that the file exists and is readable."))]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
}

impl Error {
    /// True for transient failures the user might retry (network, timeout).
    pub fn is_transient(&self) -> bool {
        if let Self::Network(e) = self {
            return e.is_timeout() || e.is_connect();
        }
        false
    }

    /// True when the server explicitly rejected the request.
    pub fn is_api_error(&self) -> bool {
        matches!(self, Self::Api { .. })
    }

    /// Suggested process exit code for CLI use.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::PolicyViolation { .. } => 6,
            Self::Api { .. } => 2,
            Self::Http { .. } => 3,
            Self::Network(_) => 4,
            Self::Io { .. } => 5,
            Self::Unsupported { .. } => 7,
            Self::Forbidden { .. } => 8,
            _ => 1,
        }
    }

    // ── Constructors ──────────────────────────────────────────────────────────

    pub fn policy_violation(reason: impl Into<String>, hint: impl Into<String>) -> Self {
        Self::PolicyViolation {
            reason: reason.into(),
            hint: hint.into(),
        }
    }

    pub fn api(message: impl Into<String>) -> Self {
        Self::Api {
            message: message.into(),
        }
    }

    pub fn parse(context: impl Into<String>) -> Self {
        Self::Parse {
            context: context.into(),
        }
    }

    pub fn config(context: impl Into<String>) -> Self {
        Self::Config {
            context: context.into(),
        }
    }

    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    pub fn unsupported(vendor: &'static str, feature: &'static str) -> Self {
        Self::Unsupported { vendor, feature }
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden {
            message: message.into(),
        }
    }
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::{fixture, rstest};

    #[fixture]
    fn api_error() -> Error {
        Error::api("zone not found")
    }

    #[fixture]
    fn io_error() -> Error {
        Error::io(
            "reading zone file 'example.zone'",
            std::io::Error::from(std::io::ErrorKind::NotFound),
        )
    }

    // ── Display format ────────────────────────────────────────────────────────

    #[rstest]
    fn api_error_display_includes_message(api_error: Error) {
        assert_eq!(api_error.to_string(), "API error: zone not found");
    }

    #[rstest]
    fn http_error_display_includes_status() {
        let e = Error::Http {
            status: 403,
            body: r#"{"detail":"forbidden"}"#.into(),
        };
        assert!(e.to_string().contains("403"));
    }

    #[rstest]
    fn parse_error_display_includes_context() {
        let e = Error::parse("could not parse list_records for 'example.com'");
        assert!(e.to_string().contains("example.com"));
    }

    #[rstest]
    fn io_error_display_includes_context(io_error: Error) {
        assert!(io_error.to_string().contains("example.zone"));
    }

    // ── Diagnostic codes ─────────────────────────────────────────────────────

    #[rstest]
    fn api_error_has_diagnostic_code(api_error: Error) {
        let code = api_error.code().expect("should have a code");
        assert_eq!(code.to_string(), "dns::api");
    }

    #[rstest]
    #[case::http(Error::Http { status: 500, body: "".into() }, "dns::http")]
    #[case::parse(Error::Parse { context: "x".into() }, "dns::parse")]
    #[case::io(Error::Io { context: "x".into(), source: std::io::Error::from(std::io::ErrorKind::NotFound) }, "dns::io")]
    fn diagnostic_codes_are_correct(#[case] e: Error, #[case] expected: &str) {
        let code = e.code().expect("should have a code");
        assert_eq!(code.to_string(), expected);
    }

    // ── Help text ─────────────────────────────────────────────────────────────

    #[rstest]
    fn api_error_has_help_text(api_error: Error) {
        assert!(api_error.help().is_some());
    }

    #[rstest]
    fn io_error_has_help_text(io_error: Error) {
        let help = io_error.help().expect("should have help");
        assert!(help.to_string().contains("readable"));
    }

    // ── is_api_error ──────────────────────────────────────────────────────────

    #[rstest]
    fn api_error_is_api_error(api_error: Error) {
        assert!(api_error.is_api_error());
    }

    #[rstest]
    #[case(Error::Http { status: 500, body: "".into() })]
    #[case(Error::Parse { context: "bad".into() })]
    #[case(Error::Io { context: "x".into(), source: std::io::Error::from(std::io::ErrorKind::NotFound) })]
    fn non_api_errors_are_not_api_errors(#[case] e: Error) {
        assert!(!e.is_api_error());
    }

    // ── exit_code ─────────────────────────────────────────────────────────────

    #[rstest]
    #[case::api(Error::Api { message: "x".into() }, 2)]
    #[case::http(Error::Http { status: 500, body: "".into() }, 3)]
    #[case::parse(Error::Parse { context: "x".into() }, 1)]
    #[case::io(Error::Io { context: "x".into(), source: std::io::Error::from(std::io::ErrorKind::NotFound) }, 5)]
    fn exit_code_by_variant(#[case] e: Error, #[case] expected: i32) {
        assert_eq!(e.exit_code(), expected);
    }

    // ── constructors ──────────────────────────────────────────────────────────

    #[rstest]
    fn api_constructor_sets_message() {
        let e = Error::api("access denied");
        assert!(matches!(e, Error::Api { ref message } if message == "access denied"));
    }

    #[rstest]
    fn parse_constructor_sets_context() {
        let e = Error::parse("bad response shape");
        assert!(matches!(e, Error::Parse { ref context } if context == "bad response shape"));
    }

    #[rstest]
    fn io_constructor_sets_context(io_error: Error) {
        assert!(
            matches!(io_error, Error::Io { ref context, .. } if context.contains("example.zone"))
        );
    }
}
