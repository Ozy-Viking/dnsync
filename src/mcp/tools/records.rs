use rmcp::{ErrorData as McpError, model::*};

use crate::{
    control_plane::policy::Policy,
    core::dns::{records, service::ListRecordsOptions},
    core::{dns::service::DnsService, error::Error},
    mcp::{
        helpers::{json_result, mcp_err},
        params::*,
    },
};

pub async fn handle_list_records<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ListRecordsParams,
) -> Result<CallToolResult, McpError> {
    policy
        .check_zone(p.zone.as_deref().unwrap_or(&p.domain))
        .map_err(mcp_err)?;
    client
        .list_records(
            &p.domain,
            p.zone.as_deref(),
            ListRecordsOptions {
                use_local_ip: p.use_local_ip.unwrap_or(false),
                all_subdomains: false,
            },
        )
        .await
        .and_then(|r| serde_json::to_value(&r).map_err(|e| Error::parse(e.to_string())))
        .map(json_result)
        .map_err(mcp_err)
}

pub async fn handle_add_record<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: AddRecordParams,
) -> Result<CallToolResult, McpError> {
    policy.check_write().map_err(mcp_err)?;
    policy.check_zone(&p.zone).map_err(mcp_err)?;
    records::create_record(client, &p.zone, &p.domain, p.ttl.unwrap_or(3600), &p.record)
        .await
        .map(json_result)
        .map_err(mcp_err)
}

pub async fn handle_delete_record<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DeleteRecordParams,
) -> Result<CallToolResult, McpError> {
    policy.check_write().map_err(mcp_err)?;
    policy.check_zone(&p.zone).map_err(mcp_err)?;
    let type_params = p.record.to_api_params();
    records::delete_record(client, &p.zone, &p.domain, &type_params)
        .await
        .map(json_result)
        .map_err(mcp_err)
}
