//! Guardrail policy for the MCP server.
//!
//! Policy is evaluated before any tool call dispatches to `dns::*`.
//! Config, CLI, and env vars are the source of truth — callers of `DnsServer::new`
//! must construct a `Policy` for the selected DNS server and pass it in.
//!
//! # Operation sets
//!
//! A `Policy` holds an explicit set of allowed `PolicyRule` variants.
//! Rules are independent: you can permit any combination of Read, Write, and Delete.
//!
//! - **Read**: list/export/stats/settings/cache-browse tools are permitted.
//! - **Write**: create/update/import/flush/block/allow tools are permitted.
//! - **Delete**: delete tools are permitted.
//! - **Zone allow-list**: any tool that targets a specific zone is rejected unless
//!   that zone (or its parent) is in the allow-list. Zone-agnostic tools (stats,
//!   settings, cache browse) are always permitted.

use std::collections::HashSet;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::cli::Cli;
use crate::control_plane::config::{AppConfig, McpPermissions};
use crate::core::error::{Error, Result};

/// Identifies a single class of DNS operation.
///
/// A `Policy` holds a `HashSet<PolicyRule>` — only operations whose rule is
/// present in that set are permitted.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum PolicyRule {
    /// Read-only operations: list zones/records, export, stats, settings, cache browse.
    Read,
    /// Write operations: create/update/import/flush/block/allow.
    Write,
    /// Delete operations: delete zone/record/cache/block/allow entries.
    Delete,
}

/// Governs what the MCP server is permitted to do.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Set of permitted operation classes.
    pub allowed: HashSet<PolicyRule>,

    /// If `Some`, only zones in this list (case-insensitive) are accessible.
    /// `None` means unrestricted.
    pub allowed_zones: Option<Vec<String>>,
}

impl Default for Policy {
    fn default() -> Self {
        Self::new([PolicyRule::Read, PolicyRule::Write, PolicyRule::Delete], None)
    }
}

impl Policy {
    /// Construct a new policy from its constituent parts.
    pub fn new(
        allowed: impl IntoIterator<Item = PolicyRule>,
        allowed_zones: Option<Vec<String>>,
    ) -> Self {
        Self {
            allowed: allowed.into_iter().collect(),
            allowed_zones: allowed_zones
                .map(|zones| zones.into_iter().map(|z| z.to_lowercase()).collect()),
        }
    }

    pub fn check(&self, rule: PolicyRule) -> Result<()> {
        if self.allowed.contains(&rule) {
            return Ok(());
        }
        match rule {
            PolicyRule::Read => {
                tracing::warn!("read rejected: read is not in the allowed set");
                Err(Error::policy_violation(
                    "this MCP server does not permit read operations",
                    "Update this server's MCP permissions or add 'read' to the allowed operations.",
                ))
            }
            PolicyRule::Write => {
                tracing::warn!("write rejected: write is not in the allowed set");
                Err(Error::policy_violation(
                    "this MCP server does not permit write operations",
                    "Update this server's MCP permissions or add 'write' to the allowed operations.",
                ))
            }
            PolicyRule::Delete => {
                tracing::warn!("delete rejected: delete is not in the allowed set");
                Err(Error::policy_violation(
                    "this MCP server does not permit delete operations",
                    "Update this server's MCP permissions or add 'delete' to the allowed operations.",
                ))
            }
        }
    }

    /// Assert that the active policy permits read operations.
    /// Shorthand for `check(PolicyRule::Read)`.
    pub fn check_read(&self) -> Result<()> {
        self.check(PolicyRule::Read)
    }

    /// Assert that the active policy permits write operations.
    /// Shorthand for `check(PolicyRule::Write)`.
    pub fn check_write(&self) -> Result<()> {
        self.check(PolicyRule::Write)
    }

    pub fn check_delete(&self) -> Result<()> {
        self.check(PolicyRule::Delete)
    }

    pub fn check_zone(&self, zone: &str) -> Result<()> {
        let Some(allowed_zones) = &self.allowed_zones else {
            return Ok(());
        };

        let zone = zone.trim_end_matches('.').to_lowercase();
        let allowed = allowed_zones.iter().any(|allowed| {
            let allowed = allowed.trim_end_matches('.').to_lowercase();
            zone == allowed || zone.ends_with(&format!(".{allowed}"))
        });

        if allowed {
            Ok(())
        } else {
            Err(Error::policy_violation(
                format!("zone '{zone}' is outside the configured allowed zones"),
                "Choose a zone permitted by this server's policy.",
            ))
        }
    }

    /// Returns a human-readable summary of active restrictions, used in the
    /// MCP `ServerInfo.instructions` field so Claude knows upfront what it can do.
    pub fn instructions_suffix(&self) -> String {
        let mut parts = Vec::new();

        // Collect disabled operations (those NOT in self.allowed)
        let mut disabled: Vec<&str> = Vec::new();
        if !self.allowed.contains(&PolicyRule::Read) {
            disabled.push("read");
        }
        if !self.allowed.contains(&PolicyRule::Write) {
            disabled.push("write");
        }
        if !self.allowed.contains(&PolicyRule::Delete) {
            disabled.push("delete");
        }

        if !disabled.is_empty() {
            // Check for common named combinations for human-friendly messages
            let read_disabled = disabled.contains(&"read");
            let write_disabled = disabled.contains(&"write");
            let delete_disabled = disabled.contains(&"delete");

            if read_disabled && write_disabled && !delete_disabled {
                // only delete allowed — unusual but possible
                parts.push("⚠️  Restricted mode: read and write operations are disabled.".to_string());
            } else if read_disabled && delete_disabled && !write_disabled {
                // write-only
                parts.push(
                    "⚠️  Write-only mode: read and delete operations are disabled.".to_string(),
                );
            } else if write_disabled && delete_disabled && !read_disabled {
                // read-only
                parts.push(
                    "⚠️  Read-only mode: all write and delete operations are disabled.".to_string(),
                );
            } else if read_disabled && !write_disabled && !delete_disabled {
                // write+delete mode (read disabled) — write mode with read blocked
                parts.push(
                    "⚠️  Write mode: read operations are disabled.".to_string(),
                );
            } else if delete_disabled && !read_disabled && !write_disabled {
                // read+write mode (delete disabled) — write mode without deletes
                parts.push(
                    "⚠️  Write mode: delete operations are disabled.".to_string(),
                );
            } else {
                // Generic fallback: list the disabled operations
                parts.push(format!(
                    "⚠️  Restricted mode: {} operations are disabled.",
                    disabled.join(", ")
                ));
            }
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

impl Policy {
    /// Constructs an effective `Policy` for a single DNS server by combining the server's MCP
    /// access configuration with CLI-provided access and zone overrides.
    ///
    /// - Operation permissions: if `cli_access` is empty the server's MCP `access` is used;
    ///   otherwise the resulting allowed operations are the intersection of `cli_access` and the
    ///   server's MCP `access` (the CLI cannot broaden permissions beyond the server's config).
    /// - Zone restrictions: if `cli_allow_zone` is empty the server's configured `allowed_zones`
    ///   (if any) is used; if `cli_allow_zone` is non-empty it becomes the resulting zone list.
    ///   When the server has configured allowed zones, each CLI-provided zone is validated against
    ///   the server's allowed zones (subdomains and case-insensitive matches are permitted);
    ///   a CLI zone outside the server's configured zones causes a `PolicyViolation` error.
    ///
    /// # Errors
    ///
    /// Returns `Error::PolicyViolation` when any entry in `cli_allow_zone` is not permitted by the
    /// server's MCP configured allowed zones (when that restriction exists).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use crate::control_plane::policy::Policy;
    /// use crate::control_plane::config::DnsServerConfig;
    ///
    /// // Construct `server`, `cli_access`, and `cli_allow_zone` according to your application.
    /// let server: DnsServerConfig = /* server from config */ unimplemented!();
    /// let cli_access = vec![]; // empty means "use server MCP access"
    /// let cli_allow_zone: Vec<String> = vec![]; // empty means "use server MCP zones"
    ///
    /// let policy = Policy::for_server(&server, &cli_access, &cli_allow_zone)?;
    /// ```
    pub fn for_server(
        server: &crate::control_plane::config::DnsServerConfig,
        cli_access: &[PolicyRule],
        cli_allow_zone: &[String],
    ) -> Result<Self> {
        let mcp = &server.mcp;

        let config_set: HashSet<PolicyRule> = mcp.access.iter().cloned().collect();
        let cli_set: HashSet<PolicyRule> = cli_access.iter().cloned().collect();

        let allowed: HashSet<PolicyRule> = if cli_set.is_empty() {
            config_set
        } else {
            cli_set.intersection(&config_set).cloned().collect()
        };

        let configured_zones =
            (!mcp.allowed_zones.is_empty()).then_some(&mcp.allowed_zones);

        let allowed_zones = if cli_allow_zone.is_empty() {
            configured_zones.cloned()
        } else if let Some(configured) = configured_zones {
            let configured_policy = Self::new(
                [PolicyRule::Read, PolicyRule::Write, PolicyRule::Delete],
                Some(configured.clone()),
            );
            for zone in cli_allow_zone {
                configured_policy.check_zone(zone).map_err(|_| {
                    Error::policy_violation(
                        format!(
                            "--allow-zone '{zone}' is outside this server's configured MCP allowed zones"
                        ),
                        "Remove the override or choose a zone already permitted by this server's config.",
                    )
                })?;
            }
            Some(cli_allow_zone.to_vec())
        } else {
            Some(cli_allow_zone.to_vec())
        };

        Ok(Self::new(allowed, allowed_zones))
    }

    /// Build a `Policy` from CLI options and config.
    pub fn from_cli_and_config(cli: &Cli, config: Option<&AppConfig>) -> Result<Self> {
        let mcp = config
            .and_then(|c| {
                c.selected_server(cli.servers.first().map(|s| s.as_str()))
                    .ok()
            })
            .map(|s| &s.mcp);

        let config_set: HashSet<PolicyRule> = mcp
            .map(|p| p.access.iter().cloned().collect())
            .unwrap_or_else(|| {
                [PolicyRule::Read, PolicyRule::Write, PolicyRule::Delete]
                    .into_iter()
                    .collect()
            });

        let cli_set: HashSet<PolicyRule> = cli.access.iter().cloned().collect();

        let allowed: HashSet<PolicyRule> = if cli_set.is_empty() {
            config_set
        } else {
            cli_set.intersection(&config_set).cloned().collect()
        };

        let allowed_zones = Self::allowed_zones_from_cli_and_mcp(cli, mcp)?;
        Ok(Self::new(allowed, allowed_zones))
    }

    /// Build allowed zones from CLI and MCP config.
    pub fn allowed_zones_from_cli_and_mcp(
        cli: &Cli,
        mcp: Option<&McpPermissions>,
    ) -> Result<Option<Vec<String>>> {
        let configured = mcp.and_then(|permissions| {
            (!permissions.allowed_zones.is_empty()).then_some(&permissions.allowed_zones)
        });

        if cli.allow_zone.is_empty() {
            return Ok(configured.cloned());
        }

        let Some(configured) = configured else {
            return Ok(Some(cli.allow_zone.clone()));
        };

        let configured_policy = Self::new(
            [PolicyRule::Read, PolicyRule::Write, PolicyRule::Delete],
            Some(configured.clone()),
        );
        for zone in &cli.allow_zone {
            configured_policy.check_zone(zone).map_err(|_| {
                Error::policy_violation(
                    format!(
                        "--allow-zone '{zone}' is outside this server's configured MCP allowed zones"
                    ),
                    "Remove the override or choose a zone already permitted by this server's config.",
                )
            })?;
        }

        Ok(Some(cli.allow_zone.clone()))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::{fixture, rstest};

    #[fixture]
    fn unrestricted() -> Policy {
        Policy::new([PolicyRule::Read, PolicyRule::Write, PolicyRule::Delete], None)
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
        assert!(write_access.instructions_suffix().contains("Write mode: delete operations are disabled."));
    }

    #[rstest]
    fn write_only_suffix_mentions_write_only(write_only: Policy) {
        assert!(write_only.instructions_suffix().contains("Write-only"));
    }

    #[rstest]
    fn write_delete_suffix_mentions_read_disabled(write_delete: Policy) {
        assert!(write_delete.instructions_suffix().contains("read operations are disabled"));
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
    /// ```
    /// let cfg = server_with_mcp(vec![PolicyRule::Read, PolicyRule::Write], vec!["example.com".into()]);
    /// assert_eq!(cfg.id, "test");
    /// assert_eq!(cfg.mcp.allowed_zones.len(), 1);
    /// assert!(cfg.mcp.access.contains(&PolicyRule::Read));
    /// ```
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
            mcp: McpPermissions { access, allowed_zones },
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
        let server = server_with_mcp(
            vec![PolicyRule::Read, PolicyRule::Write],
            vec![],
        );
        // CLI requests read+delete but server only allows read+write → intersection is read only
        let policy =
            Policy::for_server(&server, &[PolicyRule::Read, PolicyRule::Delete], &[]).unwrap();
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
        let policy =
            Policy::for_server(&server, &[], &["example.com".to_string()]).unwrap();
        assert!(policy.check_zone("example.com").is_ok());
        assert!(policy.check_zone("sub.example.com").is_ok());
        assert!(policy.check_zone("internal.lan").is_err());
    }

    #[test]
    fn for_server_cli_allow_zone_outside_mcp_zones_is_rejected() {
        let server = server_with_mcp(
            vec![PolicyRule::Read],
            vec!["example.com".into()],
        );
        let err =
            Policy::for_server(&server, &[], &["other.net".to_string()]).unwrap_err();
        assert!(matches!(err, Error::PolicyViolation { .. }));
        assert!(err.to_string().contains("other.net"));
    }

    #[test]
    fn for_server_unrestricted_zones_when_neither_side_configures_them() {
        let server = server_with_mcp(vec![PolicyRule::Read, PolicyRule::Write, PolicyRule::Delete], vec![]);
        let policy = Policy::for_server(&server, &[], &[]).unwrap();
        assert!(policy.allowed_zones.is_none());
        assert!(policy.check_zone("anything.example.com").is_ok());
    }
}
