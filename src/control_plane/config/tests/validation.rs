//! Negative-path tests for semantic config validation.
//!
//! Happy-path parsing is covered in `loading`/`transport`; job validation in
//! `jobs`. This module focuses on the cluster, server-transport, validation
//! endpoint, and server-id error branches in `validate.rs` / `app_config.rs`.

use super::*;

/// Parse a TOML snippet into an AppConfig.
///
/// Parses the provided TOML string and returns the deserialized `AppConfig`.
/// Panics if the TOML cannot be parsed or does not match the expected structure.
///
/// # Examples
///
/// ```
/// let cfg = parse(r#"
/// [servers.dns]
/// id = "dns1"
/// token = "secret"
/// "#);
/// // `cfg` is an AppConfig parsed from the snippet
/// ```
fn parse(toml_str: &str) -> AppConfig {
    toml::from_str(toml_str).expect("config snippet should parse")
}

// ── server identity ─────────────────────────────────────────────────────────

#[test]
fn rejects_empty_server_id() {
    let cfg = parse(
        r#"
            [[servers]]
            id = ""
            token = "tok"
        "#,
    );
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("empty id"), "unexpected error: {err}");
}

/// Verifies that server IDs are treated case-insensitively and duplicate IDs are rejected by validation.
///
/// This test parses a configuration that defines two servers whose IDs differ only by case and
/// asserts that validation fails with an error mentioning a duplicate DNS server id.
///
/// # Examples
///
/// ```
/// let cfg = parse(r#"
///     [[servers]]
///     id = "Home"
///     token = "tok"
///
///     [[servers]]
///     id = "home"
///     token = "tok"
/// "#);
/// let err = cfg.validate().unwrap_err().to_string();
/// assert!(err.contains("duplicate DNS server id"));
/// ```
#[test]
fn rejects_duplicate_server_ids_case_insensitively() {
    let cfg = parse(
        r#"
            [[servers]]
            id = "Home"
            token = "tok"

            [[servers]]
            id = "home"
            token = "tok"
        "#,
    );
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("duplicate DNS server id"), "unexpected: {err}");
}

#[test]
fn rejects_server_referencing_unknown_cluster() {
    let cfg = parse(
        r#"
            [[servers]]
            id = "home"
            token = "tok"
            cluster = "ghost"
        "#,
    );
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("unknown cluster"), "unexpected: {err}");
}

// ── clusters ────────────────────────────────────────────────────────────────

/// Ensures validation rejects clusters that reference servers which are not defined.
///
/// Creates a configuration where `clusters.home.members` includes a server id that
/// is not present in `servers` and asserts that validation fails with an error
/// mentioning the unknown member.
///
/// # Examples
///
/// ```
/// let cfg = parse(
///     r#"
///         [[servers]]
///         id = "dns1"
///         token = "tok"
///
///         [clusters.home]
///         members = ["dns1", "missing"]
///     "#,
/// );
/// let err = cfg.validate().unwrap_err().to_string();
/// assert!(err.contains("references unknown DNS server 'missing'"));
/// ```
#[test]
fn rejects_cluster_with_unknown_member() {
    let cfg = parse(
        r#"
            [[servers]]
            id = "dns1"
            token = "tok"

            [clusters.home]
            members = ["dns1", "missing"]
        "#,
    );
    let err = cfg.validate().unwrap_err().to_string();
    assert!(
        err.contains("references unknown DNS server 'missing'"),
        "unexpected: {err}"
    );
}

#[test]
fn rejects_cluster_primary_referencing_unknown_server() {
    let cfg = parse(
        r#"
            [[servers]]
            id = "dns1"
            token = "tok"

            [clusters.home]
            members = ["dns1"]
            primary = "nope"
        "#,
    );
    let err = cfg.validate().unwrap_err().to_string();
    assert!(
        err.contains("references unknown DNS server 'nope'"),
        "unexpected: {err}"
    );
}

#[test]
fn cluster_primary_auto_is_accepted() {
    let cfg = parse(
        r#"
            [[servers]]
            id = "dns1"
            token = "tok"

            [clusters.home]
            members = ["dns1"]
            primary = "auto"
            preferred_writer = "AUTO"
        "#,
    );
    cfg.validate().expect("`auto` writer markers must validate");
}

#[test]
fn cluster_member_match_is_case_insensitive() {
    let cfg = parse(
        r#"
            [[servers]]
            id = "DNS1"
            token = "tok"

            [clusters.home]
            members = ["dns1"]
        "#,
    );
    cfg.validate()
        .expect("member lookup should be case-insensitive");
}

// ── server transports ───────────────────────────────────────────────────────

#[test]
fn rejects_enabled_dns_transport_without_addr() {
    let cfg = parse(
        r#"
            [[servers]]
            id = "home"
            token = "tok"

            [servers.dns]
            enabled = true
        "#,
    );
    let err = cfg.validate().unwrap_err().to_string();
    assert!(
        err.contains("enabled dns transport without addr"),
        "unexpected: {err}"
    );
}

#[test]
fn rejects_enabled_dot_transport_without_addr() {
    let cfg = parse(
        r#"
            [[servers]]
            id = "home"
            token = "tok"

            [servers.dot]
            enabled = true
        "#,
    );
    let err = cfg.validate().unwrap_err().to_string();
    assert!(
        err.contains("enabled dot transport without addr"),
        "unexpected: {err}"
    );
}

#[test]
fn rejects_enabled_doh_transport_without_url() {
    let cfg = parse(
        r#"
            [[servers]]
            id = "home"
            token = "tok"

            [servers.doh]
            enabled = true
        "#,
    );
    let err = cfg.validate().unwrap_err().to_string();
    assert!(
        err.contains("enabled doh transport without url"),
        "unexpected: {err}"
    );
}

#[test]
fn disabled_transport_without_addr_is_allowed() {
    let cfg = parse(
        r#"
            [[servers]]
            id = "home"
            token = "tok"

            [servers.dns]
            enabled = false
        "#,
    );
    cfg.validate()
        .expect("a disabled transport need not specify an addr");
}

/// Fails validation when an enabled DNS transport's `addr` is only whitespace.
///
/// # Examples
///
/// ```
/// let cfg = parse(r#"
///     [[servers]]
///     id = "home"
///     token = "tok"
///
///     [servers.dns]
///     enabled = true
///     addr = "   "
/// "#);
/// let err = cfg.validate().unwrap_err().to_string();
/// assert!(err.contains("enabled dns transport without addr"));
/// ```
#[test]
fn whitespace_only_addr_counts_as_missing() {
    let cfg = parse(
        r#"
            [[servers]]
            id = "home"
            token = "tok"

            [servers.dns]
            enabled = true
            addr = "   "
        "#,
    );
    let err = cfg.validate().unwrap_err().to_string();
    assert!(
        err.contains("enabled dns transport without addr"),
        "unexpected: {err}"
    );
}

// ── validation endpoints ────────────────────────────────────────────────────

#[test]
fn rejects_dns_validation_endpoint_without_address() {
    let cfg = parse(
        r#"
            [[servers]]
            id = "home"
            token = "tok"

            [[servers.validation_endpoints]]
            name = "router"
            transport = "dns"
        "#,
    );
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("requires address"), "unexpected: {err}");
}

/// Ensures a DOQ validation endpoint without an address is rejected during config validation.
///
/// The test builds a config that declares a validation endpoint with `transport = "doq"` but
/// omits any `address`/URL and asserts validation fails with a message containing `"requires address"`.
///
/// # Examples
///
/// ```
/// // Construct a config snippet with a DOQ validation endpoint missing an address,
/// // then assert validation reports the missing address.
/// let cfg = parse(
///     r#"
///         [[servers]]
///         id = "home"
///         token = "tok"
///
///         [[servers.validation_endpoints]]
///         name = "quic"
///         transport = "doq"
///     "#,
/// );
/// let err = cfg.validate().unwrap_err().to_string();
/// assert!(err.contains("requires address"));
/// ```
#[test]
fn rejects_doq_validation_endpoint_without_address() {
    let cfg = parse(
        r#"
            [[servers]]
            id = "home"
            token = "tok"

            [[servers.validation_endpoints]]
            name = "quic"
            transport = "doq"
        "#,
    );
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("requires address"), "unexpected: {err}");
}

/// Ensures that a validation endpoint whose name is only whitespace is rejected by configuration validation.
///
/// # Examples
///
/// ```
/// let cfg = parse(r#"
/// [[servers]]
/// id = "home"
/// token = "tok"
///
/// [[servers.validation_endpoints]]
/// name = "   "
/// transport = "dns"
/// address = "1.1.1.1"
/// "#);
/// let err = cfg.validate().unwrap_err().to_string();
/// assert!(err.contains("empty name"));
/// ```
#[test]
fn rejects_validation_endpoint_with_empty_name() {
    let cfg = parse(
        r#"
            [[servers]]
            id = "home"
            token = "tok"

            [[servers.validation_endpoints]]
            name = "   "
            transport = "dns"
            address = "1.1.1.1"
        "#,
    );
    let err = cfg.validate().unwrap_err().to_string();
    assert!(err.contains("empty name"), "unexpected: {err}");
}

#[test]
fn accepts_well_formed_validation_endpoints() {
    let cfg = parse(
        r#"
            [[servers]]
            id = "home"
            token = "tok"

            [[servers.validation_endpoints]]
            name = "router"
            transport = "dns"
            address = "1.1.1.1"

            [[servers.validation_endpoints]]
            name = "doh"
            transport = "doh"
            url = "https://dns.example/dns-query"
        "#,
    );
    cfg.validate().expect("valid endpoints should pass");
}
