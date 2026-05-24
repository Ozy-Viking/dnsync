use rmcp::{ErrorData as McpError, model::*};

use crate::{
    control_plane::policy::Policy,
    core::dns::access_lists,
    core::dns::service::DnsService,
    mcp::{helpers::run_json, params::DomainParams},
};

pub async fn handle_list_blocked<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
) -> Result<CallToolResult, McpError> {
    run_json(policy.check_read(), access_lists::list_blocked(client)).await
}

pub async fn handle_add_blocked<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DomainParams,
) -> Result<CallToolResult, McpError> {
    run_json(
        policy.check_write(),
        access_lists::add_blocked(client, &p.domain),
    )
    .await
}

pub async fn handle_delete_blocked<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DomainParams,
) -> Result<CallToolResult, McpError> {
    run_json(
        policy.check_delete(),
        access_lists::delete_blocked(client, &p.domain),
    )
    .await
}

pub async fn handle_list_allowed<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
) -> Result<CallToolResult, McpError> {
    run_json(policy.check_read(), access_lists::list_allowed(client)).await
}

pub async fn handle_add_allowed<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DomainParams,
) -> Result<CallToolResult, McpError> {
    run_json(
        policy.check_write(),
        access_lists::add_allowed(client, &p.domain),
    )
    .await
}

pub async fn handle_delete_allowed<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DomainParams,
) -> Result<CallToolResult, McpError> {
    run_json(
        policy.check_delete(),
        access_lists::delete_allowed(client, &p.domain),
    )
    .await
}
