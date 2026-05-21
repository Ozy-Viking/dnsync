use serde_json::Value;

use crate::core::{dns::service::SettingsRead, error::Result};

/// Get DNS server settings through a vendor-neutral settings reader.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn get_settings<C: SettingsRead + ?Sized>(client: &C) -> Result<Value> {
    client.get_settings().await
}
