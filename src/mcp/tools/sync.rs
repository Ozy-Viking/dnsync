use rmcp::{ErrorData as McpError, model::*};

use crate::{
    control_plane::{config::AppConfig, policy::Policy},
    mcp::{helpers::run_json, params::SyncParams},
};

pub async fn handle_sync(
    config: &AppConfig,
    from_policy: &Policy,
    to_policy: &Policy,
    p: SyncParams,
) -> Result<CallToolResult, McpError> {
    // Named sync profiles have been superseded by [[jobs]]; zone resolution
    // now relies solely on the explicit `zones` parameter or server allow-lists.
    let _ = config; // config retained for future use
    let effective_zones = p.zones.as_slice();
    let zone_check = if effective_zones.is_empty()
        && (from_policy.allowed_zones.is_some() || to_policy.allowed_zones.is_some())
    {
        Err(crate::core::error::Error::policy_violation(
            "MCP sync with zone allowlists requires explicit zones",
            "Pass `zones` in the tool call or configure zones on the selected sync profile.",
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
        crate::control_plane::sync::run_sync_json(
            Some(config),
            p.profile.as_deref(),
            p.from.as_deref(),
            p.to.as_deref(),
            &p.zones,
            &p.map,
            p.apply,
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
