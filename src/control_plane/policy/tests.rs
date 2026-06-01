use super::*;
use rstest::{fixture, rstest};

#[fixture]
fn unrestricted() -> Policy {
    Policy::new(
        [PolicyRule::Read, PolicyRule::Write, PolicyRule::Delete],
        None,
    )
}

#[fixture]
fn readonly() -> Policy {
    Policy::new([PolicyRule::Read], None)
}

#[fixture]
fn write_access() -> Policy {
    Policy::new([PolicyRule::Read, PolicyRule::Write], None)
}

#[fixture]
fn write_only() -> Policy {
    Policy::new([PolicyRule::Write], None)
}

#[fixture]
fn write_delete() -> Policy {
    Policy::new([PolicyRule::Write, PolicyRule::Delete], None)
}

#[fixture]
fn zone_restricted() -> Policy {
    Policy::new(
        [PolicyRule::Read, PolicyRule::Write, PolicyRule::Delete],
        Some(vec!["example.com".into(), "internal.lan".into()]),
    )
}

#[fixture]
fn both() -> Policy {
    Policy::new([PolicyRule::Read], Some(vec!["example.com".into()]))
}

// ── check / check_read / check_write / check_delete ──────────────────────

#[rstest]
fn unrestricted_allows_reads(unrestricted: Policy) {
    assert!(unrestricted.check_read().is_ok());
}

#[rstest]
fn unrestricted_allows_writes(unrestricted: Policy) {
    assert!(unrestricted.check_write().is_ok());
}

#[rstest]
fn unrestricted_allows_deletes(unrestricted: Policy) {
    assert!(unrestricted.check_delete().is_ok());
}

#[rstest]
fn readonly_allows_reads(readonly: Policy) {
    assert!(readonly.check_read().is_ok());
}

#[rstest]
fn readonly_blocks_writes(readonly: Policy) {
    let err = readonly.check_write().unwrap_err();
    assert!(matches!(err, Error::PolicyViolation { .. }));
}

#[rstest]
fn readonly_blocks_deletes(readonly: Policy) {
    assert!(readonly.check_delete().is_err());
}

#[rstest]
fn write_access_allows_writes(write_access: Policy) {
    assert!(write_access.check_write().is_ok());
}

#[rstest]
fn write_access_blocks_deletes(write_access: Policy) {
    let err = write_access.check_delete().unwrap_err();
    assert!(matches!(err, Error::PolicyViolation { .. }));
}

#[rstest]
fn write_only_blocks_reads(write_only: Policy) {
    let err = write_only.check_read().unwrap_err();
    assert!(matches!(err, Error::PolicyViolation { .. }));
    assert!(err.to_string().contains("read"));
}

#[rstest]
fn write_only_allows_writes(write_only: Policy) {
    assert!(write_only.check_write().is_ok());
}

#[rstest]
fn write_only_blocks_deletes(write_only: Policy) {
    let err = write_only.check_delete().unwrap_err();
    assert!(matches!(err, Error::PolicyViolation { .. }));
}

#[rstest]
fn write_delete_allows_writes(write_delete: Policy) {
    assert!(write_delete.check_write().is_ok());
}

#[rstest]
fn write_delete_allows_deletes(write_delete: Policy) {
    assert!(write_delete.check_delete().is_ok());
}

#[rstest]
fn write_delete_blocks_reads(write_delete: Policy) {
    let err = write_delete.check_read().unwrap_err();
    assert!(matches!(err, Error::PolicyViolation { .. }));
    assert!(err.to_string().contains("read"));
}

#[rstest]
fn zone_restricted_allows_writes(zone_restricted: Policy) {
    assert!(zone_restricted.check_write().is_ok());
}

#[rstest]
fn zone_restricted_allows_deletes(zone_restricted: Policy) {
    assert!(zone_restricted.check_delete().is_ok());
}

#[rstest]
fn both_blocks_writes(both: Policy) {
    assert!(both.check_write().is_err());
}

// ── check_zone ────────────────────────────────────────────────────────────

#[rstest]
fn unrestricted_allows_any_zone(unrestricted: Policy) {
    assert!(unrestricted.check_zone("anything.example.com").is_ok());
    assert!(unrestricted.check_zone("other.net").is_ok());
}

#[rstest]
fn exact_zone_match_is_allowed(zone_restricted: Policy) {
    assert!(zone_restricted.check_zone("example.com").is_ok());
    assert!(zone_restricted.check_zone("internal.lan").is_ok());
}

#[rstest]
fn subdomain_of_allowed_zone_is_allowed(zone_restricted: Policy) {
    assert!(zone_restricted.check_zone("sub.example.com").is_ok());
    assert!(zone_restricted.check_zone("deep.sub.internal.lan").is_ok());
}

#[rstest]
fn zone_check_is_case_insensitive(zone_restricted: Policy) {
    assert!(zone_restricted.check_zone("EXAMPLE.COM").is_ok());
    assert!(zone_restricted.check_zone("Sub.Example.Com").is_ok());
}

#[rstest]
fn disallowed_zone_is_rejected(zone_restricted: Policy) {
    let err = zone_restricted.check_zone("other.net").unwrap_err();
    assert!(matches!(err, Error::PolicyViolation { .. }));
    assert!(err.to_string().contains("other.net"));
}

#[rstest]
fn partial_suffix_without_dot_is_not_allowed(zone_restricted: Policy) {
    // "notexample.com" must NOT match allowed "example.com"
    assert!(zone_restricted.check_zone("notexample.com").is_err());
}

// ── instructions_suffix ───────────────────────────────────────────────────

#[rstest]
fn unrestricted_has_no_suffix(unrestricted: Policy) {
    assert!(unrestricted.instructions_suffix().is_empty());
}

#[rstest]
fn readonly_suffix_mentions_read_only(readonly: Policy) {
    assert!(readonly.instructions_suffix().contains("Read-only"));
}

#[rstest]
fn write_access_suffix_mentions_write_mode(write_access: Policy) {
    assert!(
        write_access
            .instructions_suffix()
            .contains("Write mode: delete operations are disabled.")
    );
}

#[rstest]
fn write_only_suffix_mentions_write_only(write_only: Policy) {
    assert!(write_only.instructions_suffix().contains("Write-only"));
}

#[rstest]
fn write_delete_suffix_mentions_read_disabled(write_delete: Policy) {
    assert!(
        write_delete
            .instructions_suffix()
            .contains("read operations are disabled")
    );
}

#[rstest]
fn zone_restricted_suffix_mentions_zones(zone_restricted: Policy) {
    let s = zone_restricted.instructions_suffix();
    assert!(s.contains("example.com"));
    assert!(s.contains("internal.lan"));
}

#[rstest]
fn both_suffix_mentions_both(both: Policy) {
    let s = both.instructions_suffix();
    assert!(s.contains("Read-only"));
    assert!(s.contains("example.com"));
}

// ── Policy::for_server ────────────────────────────────────────────────────

use crate::control_plane::config::{DnsServerConfig, McpPermissions, VendorKind};

/// Constructs a test `DnsServerConfig` with the provided MCP permissions.
///
/// The returned config is populated with a fixed id, vendor, token and the given
/// `access` and `allowed_zones` embedded in `mcp`. Other fields are left as
/// None or empty suitable for unit tests.
///
/// # Examples
///
/// ```ignore
/// let cfg = server_with_mcp(vec![PolicyRule::Read, PolicyRule::Write], vec!["example.com".into()]);
/// assert_eq!(cfg.id, "test");
/// assert_eq!(cfg.mcp.allowed_zones.len(), 1);
/// assert!(cfg.mcp.access.contains(&PolicyRule::Read));
/// ```ignore
fn server_with_mcp(access: Vec<PolicyRule>, allowed_zones: Vec<String>) -> DnsServerConfig {
    DnsServerConfig {
        id: "test".into(),
        vendor: VendorKind::Technitium,
        location: None,
        base_url: None,
        base_url_env: None,
        token: Some("tok".into()),
        token_env: None,
        org_id: None,
        cluster: None,
        dns: None,
        dot: None,
        doh: None,
        doq: None,
        mcp: McpPermissions {
            access,
            allowed_zones,
            show_settings_secrets: false,
        },
        validation_endpoints: vec![],
    }
}

#[test]
fn for_server_uses_mcp_access_when_cli_access_empty() {
    let server = server_with_mcp(vec![PolicyRule::Read], vec![]);
    let policy = Policy::for_server(&server, &[], &[]).unwrap();
    assert!(policy.check_read().is_ok());
    assert!(policy.check_write().is_err());
    assert!(policy.check_delete().is_err());
}

#[test]
fn for_server_intersects_cli_access_with_mcp_access() {
    let server = server_with_mcp(vec![PolicyRule::Read, PolicyRule::Write], vec![]);
    // CLI requests read+delete but server only allows read+write → intersection is read only
    let policy = Policy::for_server(&server, &[PolicyRule::Read, PolicyRule::Delete], &[]).unwrap();
    assert!(policy.check_read().is_ok());
    assert!(policy.check_write().is_err());
    assert!(policy.check_delete().is_err());
}

#[test]
fn for_server_cli_access_cannot_broaden_mcp_access() {
    let server = server_with_mcp(vec![PolicyRule::Read], vec![]);
    // CLI asks for write but server config only permits read → result is still read-only
    let policy = Policy::for_server(&server, &[PolicyRule::Write], &[]).unwrap();
    assert!(policy.check_read().is_err());
    assert!(policy.check_write().is_err());
}

#[test]
fn for_server_cli_allow_zone_narrows_mcp_zones() {
    let server = server_with_mcp(
        vec![PolicyRule::Read],
        vec!["example.com".into(), "internal.lan".into()],
    );
    let policy = Policy::for_server(&server, &[], &["example.com".to_string()]).unwrap();
    assert!(policy.check_zone("example.com").is_ok());
    assert!(policy.check_zone("sub.example.com").is_ok());
    assert!(policy.check_zone("internal.lan").is_err());
}

#[test]
fn for_server_cli_allow_zone_outside_mcp_zones_is_rejected() {
    let server = server_with_mcp(vec![PolicyRule::Read], vec!["example.com".into()]);
    let err = Policy::for_server(&server, &[], &["other.net".to_string()]).unwrap_err();
    assert!(matches!(err, Error::PolicyViolation { .. }));
    assert!(err.to_string().contains("other.net"));
}

#[test]
fn for_server_unrestricted_zones_when_neither_side_configures_them() {
    let server = server_with_mcp(
        vec![PolicyRule::Read, PolicyRule::Write, PolicyRule::Delete],
        vec![],
    );
    let policy = Policy::for_server(&server, &[], &[]).unwrap();
    assert!(policy.allowed_zones.is_none());
    assert!(policy.check_zone("anything.example.com").is_ok());
}
