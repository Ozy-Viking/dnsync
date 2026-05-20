use rmcp::{ErrorData as McpError, model::*};

use crate::{
    control_plane::policy::Policy,
    core::dns::service::DnsService,
    core::dns::stats,
    mcp::{
        helpers::{json_result, mcp_err},
        params::StatsParams,
    },
};

pub async fn handle_get_stats<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: StatsParams,
) -> Result<CallToolResult, McpError> {
    policy.check_read().map_err(mcp_err)?;
    stats::get_stats(client, p.stats_type.as_deref().unwrap_or("LastDay"))
        .await
        .map(json_result)
        .map_err(mcp_err)
}
