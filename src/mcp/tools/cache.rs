use rmcp::{ErrorData as McpError, model::*};

use crate::{
    core::dns::cache,
    mcp::{helpers::{json_result, mcp_err}, params::DomainParams},
    control_plane::policy::Policy,
    core::dns::service::DnsService,
};

pub async fn handle_list_cache<C: DnsService + Send + Sync>(
    client: &C,
    p: DomainParams,
) -> Result<CallToolResult, McpError> {
    cache::list_cache(client, &p.domain)
        .await
        .map(json_result)
        .map_err(mcp_err)
}

pub async fn handle_delete_cache_zone<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DomainParams,
) -> Result<CallToolResult, McpError> {
    policy.check_write().map_err(mcp_err)?;
    cache::delete_cache_zone(client, &p.domain)
        .await
        .map(json_result)
        .map_err(mcp_err)
}

pub async fn handle_flush_cache<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
) -> Result<CallToolResult, McpError> {
    policy.check_write().map_err(mcp_err)?;
    cache::flush_cache(client)
        .await
        .map(json_result)
        .map_err(mcp_err)
}
