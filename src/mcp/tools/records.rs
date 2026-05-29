use rmcp::{ErrorData as McpError, model::*};

use crate::{
    control_plane::policy::Policy,
    core::dns::records,
    core::{dns::service::DnsService, error::Error},
    mcp::{helpers::run_json, params::*},
};

pub async fn handle_list_records<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ListRecordsParams,
) -> Result<CallToolResult, McpError> {
    let zone_check = p
        .zone
        .as_deref()
        .or(p.domain.as_deref())
        .map_or(Ok(()), |zone| policy.check_zone(zone));
    Ok(run_json(
        "dns_list_records",
        policy.check_read().and(zone_check),
        async move {
            records::query::list_records_for_query(
                client,
                p.domain.as_deref(),
                p.zone.as_deref(),
                p.all_subdomains.unwrap_or(false),
                p.use_local_ip.unwrap_or(false),
            )
            .await
            .and_then(|r| serde_json::to_value(&r).map_err(|e| Error::parse(e.to_string())))
        },
    )
    .await)
}

pub async fn handle_add_record<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: AddRecordParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_add_record",
        policy.check_write().and(policy.check_zone(&p.zone)),
        records::create_record(client, &p.zone, &p.domain, p.ttl.unwrap_or(3600), &p.record),
    )
    .await)
}

pub async fn handle_delete_record<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DeleteRecordParams,
) -> Result<CallToolResult, McpError> {
    let type_params = p.record.to_api_params();
    Ok(run_json(
        "dns_delete_record",
        policy.check_delete().and(policy.check_zone(&p.zone)),
        records::delete_record(client, &p.zone, &p.domain, &type_params),
    )
    .await)
}
