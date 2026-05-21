use serde_json::Value;

use crate::core::{
    dns::service::{AccessListRead, AccessListWrite},
    error::Result,
};

/// List manually blocked DNS domains through a vendor-neutral access-list reader.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn list_blocked<C: AccessListRead + ?Sized>(client: &C) -> Result<Value> {
    client.list_blocked().await
}

/// List manually allowed DNS domains through a vendor-neutral access-list reader.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn list_allowed<C: AccessListRead + ?Sized>(client: &C) -> Result<Value> {
    client.list_allowed().await
}

/// Add a domain to the blocked list through a vendor-neutral access-list writer.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn add_blocked<C: AccessListWrite + ?Sized>(client: &C, domain: &str) -> Result<Value> {
    client.add_blocked(domain).await
}

/// Delete a domain from the blocked list through a vendor-neutral access-list writer.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn delete_blocked<C: AccessListWrite + ?Sized>(
    client: &C,
    domain: &str,
) -> Result<Value> {
    client.delete_blocked(domain).await
}

/// Add a domain to the allowed list through a vendor-neutral access-list writer.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn add_allowed<C: AccessListWrite + ?Sized>(client: &C, domain: &str) -> Result<Value> {
    client.add_allowed(domain).await
}

/// Delete a domain from the allowed list through a vendor-neutral access-list writer.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn delete_allowed<C: AccessListWrite + ?Sized>(
    client: &C,
    domain: &str,
) -> Result<Value> {
    client.delete_allowed(domain).await
}
