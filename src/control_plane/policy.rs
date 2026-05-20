//! Guardrail policy for the MCP server.
//!
//! Policy is evaluated before any tool call dispatches to `dns::*`.
//! Config, CLI, and env vars are the source of truth — callers of `DnsServer::new`
//! must construct a `Policy` for the selected DNS server and pass it in.
//!
//! # Modes
//!
//! - **Read-only** (`PolicyRule::Read`): all write and delete tools are rejected.
//! - **Write** (`PolicyRule::Write`): create/update tools are permitted; delete tools are rejected.
//! - **Full** (`PolicyRule::Delete`): all tools are permitted (default).
//! - **Zone allow-list**: any tool that targets a specific zone is rejected unless
//!   that zone (or its parent) is in the allow-list. Zone-agnostic tools (stats,
//!   settings, cache browse) are always permitted.

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::core::error::{Error, Result};

/// Classifies the maximum operation level the MCP server is permitted to perform.
///
/// Variants are ordered from least to most permissive: `Read < Write < Delete`.
/// A `Policy` with a given `access` level permits all operations at or below that level.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum PolicyRule {
    /// Read-only: no mutations permitted.
    Read,
    /// Writes permitted; deletes are not.
    Write,
    /// All operations permitted (default).
    Delete,
}

impl Default for PolicyRule {
    fn default() -> Self {
        Self::Delete
    }
}

/// Governs what the MCP server is permitted to do.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Maximum permitted operation level.
    pub access: PolicyRule,

    /// If `Some`, only zones in this list (case-insensitive) are accessible.
    /// `None` means unrestricted.
    pub allowed_zones: Option<Vec<String>>,
}

impl Policy {
    /// Construct a new policy from its constituent parts.
    pub fn new(access: PolicyRule, allowed_zones: Option<Vec<String>>) -> Self {
        Self {
            access,
            allowed_zones: allowed_zones
                .map(|zones| zones.into_iter().map(|z| z.to_lowercase()).collect()),
        }
    }

    /// Assert that the active policy permits `rule`.
    /// Call at the start of every tool handler with the appropriate `PolicyRule` variant.
    pub fn check(&self, rule: PolicyRule) -> Result<()> {
        if rule <= self.access {
            return Ok(());
        }
        match rule {
            PolicyRule::Read => Ok(()),
            PolicyRule::Write => {
                tracing::warn!("write rejected: access level is {:?}", self.access);
                Err(Error::policy_violation(
                    "this MCP server is configured in read-only mode",
                    "Update this server's MCP permissions or set --access=write to enable writes.",
                ))
            }
            PolicyRule::Delete => {
                tracing::warn!("delete rejected: access level is {:?}", self.access);
                Err(Error::policy_violation(
                    format!(
                        "this MCP server does not permit delete operations (access: {:?})",
                        self.access
                    ),
                    "Update this server's MCP permissions or set --access=delete to enable deletes.",
                ))
            }
        }
    }

    /// Assert that the active policy permits write operations.
    /// Shorthand for `check(PolicyRule::Write)`.
    pub fn check_write(&self) -> Result<()> {
        self.check(PolicyRule::Write)
    }

    /// Assert that the active policy permits delete operations.
    /// Shorthand for `check(PolicyRule::Delete)`.
    pub fn check_delete(&self) -> Result<()> {
        self.check(PolicyRule::Delete)
    }

    /// Assert that the active policy permits access to `zone`.
    /// Call at the start of every tool handler that targets a specific zone.
    pub fn check_zone(&self, zone: &str) -> Result<()> {
        let Some(ref allowed) = self.allowed_zones else {
            return Ok(()); // unrestricted
        };

        let zone_lower = zone.to_lowercase();

        // Allow exact match or suffix match (e.g. allow-list "example.com"
        // also permits "sub.example.com").
        let permitted = allowed
            .iter()
            .any(|a| zone_lower == *a || zone_lower.ends_with(&format!(".{a}")));

        if permitted {
            Ok(())
        } else {
            tracing::warn!(zone, "write rejected: zone not in allow-list");
            let list = allowed.join(", ");
            Err(Error::policy_violation(
                format!("zone '{zone}' is not in the allowed-zones list"),
                format!(
                    "Allowed zones: {list}. Update this server's MCP permissions or pass --allow-zone to expand the list."
                ),
            ))
        }
    }

    /// Returns a human-readable summary of active restrictions, used in the
    /// MCP `ServerInfo.instructions` field so Claude knows upfront what it can do.
    pub fn instructions_suffix(&self) -> String {
        let mut parts = Vec::new();

        match self.access {
            PolicyRule::Read => {
                parts.push(
                    "⚠️  Read-only mode: all write and delete operations are disabled."
                        .to_string(),
                );
            }
            PolicyRule::Write => {
                parts.push(
                    "⚠️  Write mode: delete operations are disabled.".to_string(),
                );
            }
            PolicyRule::Delete => {}
        }

        if let Some(ref zones) = self.allowed_zones {
            parts.push(format!(
                "⚠️  Zone restriction: only the following zones are accessible: {}.",
                zones.join(", ")
            ));
        }

        if parts.is_empty() {
            String::new()
        } else {
            format!("\n\n{}", parts.join("\n"))
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::{fixture, rstest};

    #[fixture]
    fn unrestricted() -> Policy {
        Policy::default()
    }

    #[fixture]
    fn readonly() -> Policy {
        Policy::new(PolicyRule::Read, None)
    }

    #[fixture]
    fn write_access() -> Policy {
        Policy::new(PolicyRule::Write, None)
    }

    #[fixture]
    fn zone_restricted() -> Policy {
        Policy::new(
            PolicyRule::Delete,
            Some(vec!["example.com".into(), "internal.lan".into()]),
        )
    }

    #[fixture]
    fn both() -> Policy {
        Policy::new(PolicyRule::Read, Some(vec!["example.com".into()]))
    }

    // ── check / check_write / check_delete ───────────────────────────────────

    #[rstest]
    fn unrestricted_allows_writes(unrestricted: Policy) {
        assert!(unrestricted.check_write().is_ok());
    }

    #[rstest]
    fn unrestricted_allows_deletes(unrestricted: Policy) {
        assert!(unrestricted.check_delete().is_ok());
    }

    #[rstest]
    fn readonly_blocks_writes(readonly: Policy) {
        let err = readonly.check_write().unwrap_err();
        assert!(matches!(err, Error::PolicyViolation { .. }));
        assert!(err.to_string().contains("read-only"));
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
        assert!(write_access.instructions_suffix().contains("Write mode"));
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

    // ── PolicyRule ordering ───────────────────────────────────────────────────

    #[test]
    fn policy_rule_ordering() {
        assert!(PolicyRule::Read < PolicyRule::Write);
        assert!(PolicyRule::Write < PolicyRule::Delete);
        assert!(PolicyRule::Read < PolicyRule::Delete);
    }
}
