use serde_json::Value;

use crate::core::{
    dns::service::{CacheRead, CacheWrite},
    error::Result,
};

/// List DNS cache entries for a domain through a vendor-neutral cache reader.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn list_cache<C: CacheRead + ?Sized>(client: &C, domain: &str) -> Result<Value> {
    client.list_cache(domain).await
}

/// Delete cached DNS entries for a domain through a vendor-neutral cache writer.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn delete_cache_zone<C: CacheWrite + ?Sized>(client: &C, domain: &str) -> Result<Value> {
    client.delete_cache_zone(domain).await
}

/// Flush the entire DNS cache through a vendor-neutral cache writer.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn flush_cache<C: CacheWrite + ?Sized>(client: &C) -> Result<Value> {
    client.flush_cache().await
}
