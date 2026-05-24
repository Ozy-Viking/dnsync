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
    run_json(
        policy.check_read(),
        stats::get_stats(client, p.stats_type.as_deref().unwrap_or("LastDay")),
    )
    .await
}
