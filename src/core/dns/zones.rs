use clap::Args;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use crate::core::{
    dns::service::{
        ZoneExport, ZoneImport, ZoneOptionsRead, ZoneOptionsWrite, ZoneRead, ZoneWrite,
    },
    error::Result,
};

/// Shared DNS zone summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSummary {
    pub name: String,
    pub zone_type: String,
    pub disabled: bool,
}

/// Overwrite flags for zone-file imports. Used by both CLI and MCP.
#[derive(Debug, Clone, Args, Deserialize, JsonSchema)]
pub struct ZoneImportOptions {
    /// Overwrite existing record sets for imported types (default: true)
    #[arg(long, default_value_t = true)]
    #[serde(default = "default_overwrite")]
    pub overwrite: bool,
    /// Delete all existing records before importing — clean replace (default: false)
    #[arg(long, default_value_t = false)]
    #[serde(default)]
    pub overwrite_zone: bool,
    /// Use the SOA serial from the file instead of auto-incrementing (default: false)
    #[arg(long, default_value_t = false)]
    #[serde(default)]
    pub overwrite_soa_serial: bool,
}

fn default_overwrite() -> bool {
    true
}

/// List DNS zones through a vendor-neutral zone reader.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn list_zones<C: ZoneRead + ?Sized>(
    client: &C,
    page: u32,
    per_page: u32,
) -> Result<Value> {
    client.list_zones(page, per_page).await
}

/// Create a DNS zone through a vendor-neutral zone writer.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn create_zone<C: ZoneWrite + ?Sized>(
    client: &C,
    zone: &str,
    zone_type: &str,
) -> Result<Value> {
    client.create_zone(zone, zone_type).await
}

/// Delete a DNS zone through a vendor-neutral zone writer.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn delete_zone<C: ZoneWrite + ?Sized>(client: &C, zone: &str) -> Result<Value> {
    client.delete_zone(zone).await
}

/// Enable a DNS zone through a vendor-neutral zone writer.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn enable_zone<C: ZoneWrite + ?Sized>(client: &C, zone: &str) -> Result<Value> {
    client.enable_zone(zone).await
}

/// Disable a DNS zone through a vendor-neutral zone writer.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn disable_zone<C: ZoneWrite + ?Sized>(client: &C, zone: &str) -> Result<Value> {
    client.disable_zone(zone).await
}

/// Import a zone file through a vendor-neutral zone importer.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn import_zone_file<C: ZoneImport + ?Sized>(
    client: &C,
    zone: &str,
    file_name: String,
    file_bytes: Vec<u8>,
    overwrite: bool,
    overwrite_zone: bool,
    overwrite_soa_serial: bool,
) -> Result<Value> {
    client
        .import_zone_file(
            zone,
            file_name,
            file_bytes,
            overwrite,
            overwrite_zone,
            overwrite_soa_serial,
        )
        .await
}

/// Export a zone file through a vendor-neutral zone exporter.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn export_zone_file<C: ZoneExport + ?Sized>(client: &C, zone: &str) -> Result<String> {
    client.export_zone_file(zone).await
}

/// Get zone-level options for the named zone.
///
/// Returns vendor-specific zone configuration (transfer settings, type, etc.).
/// Returns `Error::Unsupported` for vendors that do not expose zone options.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn get_zone_options<C: ZoneOptionsRead + ?Sized>(
    client: &C,
    zone: &str,
) -> Result<Value> {
    client.get_zone_options(zone).await
}

/// Set zone-level options for the named zone.
///
/// The `options` value must be a JSON object whose keys map to zone option
/// names recognised by the backend. Technitium applies partial updates —
/// only provided keys are changed.
///
/// Returns `Error::Unsupported` for vendors that do not support zone options write.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn set_zone_options<C: ZoneOptionsWrite + ?Sized>(
    client: &C,
    zone: &str,
    options: &Value,
) -> Result<Value> {
    client.set_zone_options(zone, options).await
}
