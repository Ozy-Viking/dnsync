use rmcp::{ErrorData as McpError, model::*};

use crate::{
    control_plane::{config::AppConfig, policy::Policy},
    mcp::{helpers::run_json, params::SyncParams},
};

/// Perform an MCP `dns_sync` tool call after validating read/write permissions and zone constraints.
///
/// If either `from_policy` or `to_policy` defines an allow-list of zones and the provided `p.zones` is empty,
/// this function returns a policy violation error requiring explicit `zones` (and `from`/`to`) in the tool call.
/// On success it executes the sync with the provided parameters and default `SyncDiffOptions`.
///
/// # Returns
///
/// `CallToolResult` with the tool execution outcome, or an `McpError` if policy checks fail.
///
/// # Examples
///
/// ```text
/// # async fn example() {
/// // Construct AppConfig, Policy, and SyncParams appropriately for your application.
/// // let config = AppConfig::default();
/// // let from_policy = Policy::allow_read(...);
/// // let to_policy = Policy::allow_write(...);
/// // let params = SyncParams { zones: vec!["example.com".into()], ..Default::default() };
/// // let res = handle_sync(&config, &from_policy, &to_policy, params).await;
/// # }
/// ```
pub async fn handle_sync(
    config: &AppConfig,
    from_policy: &Policy,
    to_policy: &Policy,
    p: SyncParams,
) -> Result<CallToolResult, McpError> {
    // Named sync profiles have been superseded by [[jobs]]; zone resolution
    // now relies solely on the explicit `zones` parameter or server allow-lists.
    let effective_zones = p.zones.as_slice();
    let zone_check = if effective_zones.is_empty()
        && (from_policy.allowed_zones.is_some() || to_policy.allowed_zones.is_some())
    {
        Err(crate::core::error::Error::policy_violation(
            "MCP sync with zone allowlists requires explicit zones",
            "Pass `zones`, `from`, and `to` in the tool call.",
        ))
    } else {
        effective_zones
            .iter()
            .try_for_each(|zone| from_policy.check_zone(zone).and(to_policy.check_zone(zone)))
    };
    let check = from_policy
        .check_read()
        .and(to_policy.check_write())
        .and(zone_check);

    Ok(run_json("dns_sync", check, async move {
        // When pruning is requested, open the daemon state DB as the ownership
        // ledger so the MCP path matches the CLI/daemon behaviour. The
        // ownership key is derived from the source→destination pair.
        let ledger = if p.prune_synced || p.teardown {
            let path = crate::daemon::resolve_state_db(config);
            let pool = crate::daemon::db::open(&path).map_err(|e| {
                crate::core::error::Error::config(format!("prune_synced requires a state DB: {e}"))
            })?;
            Some(std::sync::Arc::new(
                crate::daemon::db::store::DaemonStateStore::new(pool),
            ))
        } else {
            None
        };
        let ownership = ledger.as_ref().map(|store| {
            let job_key = format!(
                "mcp:{}->{}",
                p.from.as_deref().unwrap_or("?"),
                p.to.as_deref().unwrap_or("?")
            );
            let ledger: &dyn crate::control_plane::sync::SyncLedger = store.as_ref();
            crate::control_plane::sync::Ownership {
                job_key,
                ledger,
                prune: p.prune_synced || p.teardown,
            }
        });

        // Teardown removes every owned record and clears the ledger, then stops.
        if p.teardown {
            let to =
                p.to.as_deref()
                    .ok_or_else(|| crate::core::error::Error::parse("teardown requires `to`"))?;
            let ownership = ownership
                .as_ref()
                .ok_or_else(|| crate::core::error::Error::config("teardown requires a state DB"))?;
            return crate::control_plane::sync::run_sync_teardown(
                Some(config),
                to,
                p.apply,
                ownership,
            )
            .await;
        }

        crate::control_plane::sync::run_sync_json(
            Some(config),
            p.profile.as_deref(),
            p.from.as_deref(),
            p.to.as_deref(),
            &p.zones,
            &p.map,
            p.apply,
            crate::control_plane::sync::SyncDiffOptions::default(),
            ownership.as_ref(),
        )
        .await
    })
    .await)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::control_plane::policy::PolicyRule;

    #[tokio::test]
    async fn restricted_sync_requires_explicit_zones() {
        let config = AppConfig::default();
        let from_policy = Policy::new([PolicyRule::Read], Some(vec!["example.com".to_string()]));
        let to_policy = Policy::new([PolicyRule::Write], None);

        let result = handle_sync(
            &config,
            &from_policy,
            &to_policy,
            SyncParams {
                profile: None,
                from: Some("from".to_string()),
                to: Some("to".to_string()),
                zones: Vec::new(),
                map: Vec::new(),
                apply: false,
                prune_synced: false,
                teardown: false,
            },
        )
        .await
        .unwrap();

        assert_eq!(result.is_error, Some(true));
        let text = result.content[0]
            .as_text()
            .expect("policy denial should be returned as text JSON");
        let value: Value = serde_json::from_str(&text.text).unwrap();
        assert!(
            value["error"]
                .as_str()
                .unwrap()
                .contains("requires explicit zones")
        );
    }
}
