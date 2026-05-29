//! Zone transfer orchestration between configured servers.

use serde_json::Value;

use crate::{
    control_plane::config::{AppConfig, DnsServerConfig},
    core::error::{Error, Result},
    vendors::runtime::VendorClient,
};

#[derive(Debug, Clone, serde::Serialize)]
pub struct ZoneTransferResult {
    pub zone: String,
    pub from: String,
    pub to: String,
    pub bytes: usize,
    pub import_result: Value,
}

pub async fn transfer_zone(
    app_config: Option<&AppConfig>,
    zone: &str,
    from_id: &str,
    to_id: &str,
    overwrite: bool,
    overwrite_zone: bool,
) -> Result<ZoneTransferResult> {
    let Some(cfg) = app_config else {
        return Err(Error::parse(
            "zone transfer requires a config file with --from and --to server entries",
        ));
    };

    let from_server = cfg.selected_server(Some(from_id))?;
    let to_server = cfg.selected_server(Some(to_id))?;

    let zone_file = server_export_zone(from_server, zone).await?;
    let bytes = zone_file.len();
    let file_name = format!("{zone}.txt");
    let import_result = server_import_zone(
        to_server,
        zone,
        file_name,
        zone_file.into_bytes(),
        overwrite,
        overwrite_zone,
    )
    .await?;

    Ok(ZoneTransferResult {
        zone: zone.to_string(),
        from: from_id.to_string(),
        to: to_id.to_string(),
        bytes,
        import_result,
    })
}

async fn server_export_zone(server: &DnsServerConfig, zone: &str) -> Result<String> {
    VendorClient::export_zone_for_server(server, zone).await
}

async fn server_import_zone(
    server: &DnsServerConfig,
    zone: &str,
    file_name: String,
    file_bytes: Vec<u8>,
    overwrite: bool,
    overwrite_zone: bool,
) -> Result<Value> {
    VendorClient::import_zone_for_server(
        server,
        zone,
        file_name,
        file_bytes,
        overwrite,
        overwrite_zone,
    )
    .await
}
