use rmcp::{ErrorData as McpError, model::*};

use crate::{
    control_plane::policy::Policy,
    core::dns::service::DnsService,
    core::dns::zones,
    mcp::{
        helpers::{run_json, run_text},
        params::*,
    },
};

pub async fn handle_list_zones<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ListZonesParams,
) -> Result<CallToolResult, McpError> {
    run_json(
        policy.check_read(),
        zones::list_zones(
            client,
            p.page_number.unwrap_or(1),
            p.zones_per_page.unwrap_or(50),
        ),
    )
    .await
}

pub async fn handle_create_zone<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: CreateZoneParams,
) -> Result<CallToolResult, McpError> {
    run_json(
        policy.check_write().and(policy.check_zone(&p.zone)),
        zones::create_zone(client, &p.zone, &p.zone_type),
    )
    .await
}

pub async fn handle_delete_zone<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ZoneParams,
) -> Result<CallToolResult, McpError> {
    run_json(
        policy.check_delete().and(policy.check_zone(&p.zone)),
        zones::delete_zone(client, &p.zone),
    )
    .await
}

pub async fn handle_enable_zone<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ZoneParams,
) -> Result<CallToolResult, McpError> {
    run_json(
        policy.check_write().and(policy.check_zone(&p.zone)),
        zones::enable_zone(client, &p.zone),
    )
    .await
}

pub async fn handle_disable_zone<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ZoneParams,
) -> Result<CallToolResult, McpError> {
    run_json(
        policy.check_write().and(policy.check_zone(&p.zone)),
        zones::disable_zone(client, &p.zone),
    )
    .await
}

pub async fn handle_import_zone_file<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ImportZoneFileParams,
) -> Result<CallToolResult, McpError> {
    let file_name = p.file_name.unwrap_or_else(|| format!("{}.txt", p.zone));
    run_json(
        policy.check_write().and(policy.check_zone(&p.zone)),
        zones::import_zone_file(
            client,
            &p.zone,
            file_name,
            p.content.into_bytes(),
            p.options.overwrite,
            p.options.overwrite_zone,
            p.options.overwrite_soa_serial,
        ),
    )
    .await
}

pub async fn handle_export_zone_file<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ExportZoneFileParams,
) -> Result<CallToolResult, McpError> {
    run_text(
        policy.check_read().and(policy.check_zone(&p.zone)),
        zones::export_zone_file(client, &p.zone),
    )
    .await
}
