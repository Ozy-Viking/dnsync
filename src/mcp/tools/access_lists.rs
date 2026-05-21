use rmcp::{ErrorData as McpError, model::*};

use crate::{
    core::dns::access_lists,
    mcp::{helpers::{json_result, mcp_err}, params::DomainParams},
    control_plane::policy::Policy,
    core::dns::service::DnsService,
};

pub async fn handle_list_blocked<C: DnsService + Send + Sync>(
    client: &C,
) -> Result<CallToolResult, McpError> {
    access_lists::list_blocked(client)
        .await
        .map(json_result)
        .map_err(mcp_err)
}

pub async fn handle_add_blocked<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DomainParams,
) -> Result<CallToolResult, McpError> {
    policy.check_write().map_err(mcp_err)?;
    access_lists::add_blocked(client, &p.domain)
        .await
        .map(json_result)
        .map_err(mcp_err)
}

pub async fn handle_delete_blocked<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DomainParams,
) -> Result<CallToolResult, McpError> {
    policy.check_write().map_err(mcp_err)?;
    access_lists::delete_blocked(client, &p.domain)
        .await
        .map(json_result)
        .map_err(mcp_err)
}

pub async fn handle_list_allowed<C: DnsService + Send + Sync>(
    client: &C,
) -> Result<CallToolResult, McpError> {
    access_lists::list_allowed(client)
        .await
        .map(json_result)
        .map_err(mcp_err)
}

pub async fn handle_add_allowed<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DomainParams,
) -> Result<CallToolResult, McpError> {
    policy.check_write().map_err(mcp_err)?;
    access_lists::add_allowed(client, &p.domain)
        .await
        .map(json_result)
        .map_err(mcp_err)
}

pub async fn handle_delete_allowed<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DomainParams,
) -> Result<CallToolResult, McpError> {
    policy.check_write().map_err(mcp_err)?;
    access_lists::delete_allowed(client, &p.domain)
        .await
        .map(json_result)
        .map_err(mcp_err)
}
