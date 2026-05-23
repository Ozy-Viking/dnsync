use rmcp::{ErrorData as McpError, model::*};

use crate::{
    control_plane::policy::Policy,
    core::dns::service::DnsService,
    core::dns::zones,
    mcp::{
        helpers::{json_result, mcp_err, text_result},
        params::*,
    },
};

pub async fn handle_list_zones<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ListZonesParams,
) -> Result<CallToolResult, McpError> {
    policy.check_read().map_err(mcp_err)?;
    zones::list_zones(
        client,
        p.page_number.unwrap_or(1),
        p.zones_per_page.unwrap_or(50),
    )
    .await
    .map(json_result)
    .map_err(mcp_err)

}

pub async fn handle_create_zone<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: CreateZoneParams,
) -> Result<CallToolResult, McpError> {
    policy.check_write().map_err(mcp_err)?;
    policy.check_zone(&p.zone).map_err(mcp_err)?;
    zones::create_zone(client, &p.zone, &p.zone_type)
        .await
        .map(json_result)
        .map_err(mcp_err)
}

pub async fn handle_delete_zone<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ZoneParams,
) -> Result<CallToolResult, McpError> {
    policy.check_delete().map_err(mcp_err)?;
    policy.check_zone(&p.zone).map_err(mcp_err)?;
    zones::delete_zone(client, &p.zone)
        .await
        .map(json_result)
        .map_err(mcp_err)
}

pub async fn handle_enable_zone<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ZoneParams,
) -> Result<CallToolResult, McpError> {
    policy.check_write().map_err(mcp_err)?;
    policy.check_zone(&p.zone).map_err(mcp_err)?;
    zones::enable_zone(client, &p.zone)
        .await
        .map(json_result)
        .map_err(mcp_err)
}

pub async fn handle_disable_zone<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ZoneParams,
) -> Result<CallToolResult, McpError> {
    policy.check_write().map_err(mcp_err)?;
    policy.check_zone(&p.zone).map_err(mcp_err)?;
    zones::disable_zone(client, &p.zone)
        .await
        .map(json_result)
        .map_err(mcp_err)
}

pub async fn handle_import_zone_file<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ImportZoneFileParams,
) -> Result<CallToolResult, McpError> {
    policy.check_write().map_err(mcp_err)?;
    policy.check_zone(&p.zone).map_err(mcp_err)?;
    let file_name = p.file_name.unwrap_or_else(|| format!("{}.txt", p.zone));
    zones::import_zone_file(
        client,
        &p.zone,
        file_name,
        p.content.into_bytes(),
        p.options.overwrite,
        p.options.overwrite_zone,
        p.options.overwrite_soa_serial,
    )
    .await
    .map(json_result)
    .map_err(mcp_err)
}

pub async fn handle_export_zone_file<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ExportZoneFileParams,
) -> Result<CallToolResult, McpError> {
    policy.check_read().map_err(mcp_err)?;
    policy.check_zone(&p.zone).map_err(mcp_err)?;
    zones::export_zone_file(client, &p.zone)
        .await
        .map(text_result)
        .map_err(mcp_err)
}
