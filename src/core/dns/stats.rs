use serde_json::Value;

use crate::core::{dns::service::StatsRead, error::Result};

/// Get DNS dashboard statistics through a vendor-neutral stats reader.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn get_stats<C: StatsRead + ?Sized>(client: &C, stats_type: &str) -> Result<Value> {
    client.get_stats(stats_type).await
}
