use rmcp::{ErrorData as McpError, model::*};

use crate::{
    core::dns::stats,
    mcp::{helpers::{json_result, mcp_err}, params::StatsParams},
    core::dns::service::DnsService,
};

pub async fn handle_get_stats<C: DnsService + Send + Sync>(
    client: &C,
    p: StatsParams,
) -> Result<CallToolResult, McpError> {
    stats::get_stats(client, p.stats_type.as_deref().unwrap_or("LastDay"))
        .await
        .map(json_result)
        .map_err(mcp_err)
}
