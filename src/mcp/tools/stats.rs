use rmcp::{ErrorData as McpError, model::*};

use crate::{
    control_plane::policy::Policy,
    core::dns::service::DnsService,
    core::dns::stats,
    mcp::{helpers::run_json, params::StatsParams},
};

pub async fn handle_get_stats<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: StatsParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_get_stats",
        policy.check_read(),
        stats::get_stats(client, p.stats_type.as_deref().unwrap_or("LastDay")),
    )
    .await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::policy::{Policy, PolicyRule};
    use crate::mcp::tools::test_support::FakeService;

    fn params() -> StatsParams {
        StatsParams {
            server_id: "s".into(),
            stats_type: None,
        }
    }

    #[tokio::test]
    async fn get_stats_requires_read() {
        let policy = Policy::new([PolicyRule::Write], None);
        let res = handle_get_stats(&FakeService, &policy, params())
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(true));
        assert!(
            res.content[0]
                .as_text()
                .unwrap()
                .text
                .contains("does not permit read")
        );
    }

    #[tokio::test]
    async fn get_stats_succeeds_with_read() {
        let policy = Policy::new([PolicyRule::Read], None);
        let res = handle_get_stats(&FakeService, &policy, params())
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(false));
    }
}
