use rmcp::{ErrorData as McpError, model::*};

use crate::{
    control_plane::policy::Policy,
    core::dns::cache,
    core::dns::service::DnsService,
    mcp::{helpers::run_json, params::DomainParams},
};

pub async fn handle_list_cache<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DomainParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_list_cache",
        policy.check_read(),
        cache::list_cache(client, &p.domain),
    )
    .await)
}

pub async fn handle_delete_cache_zone<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DomainParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_delete_cache_zone",
        policy.check_delete(),
        cache::delete_cache_zone(client, &p.domain),
    )
    .await)
}

pub async fn handle_flush_cache<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_flush_cache",
        policy.check_write(),
        cache::flush_cache(client),
    )
    .await)
}
