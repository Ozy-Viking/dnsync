//! DNS record domain types and vendor-neutral record operations.

mod data;
mod enums;
mod selector;

pub mod query;

pub use data::*;
pub use enums::*;
pub use selector::*;

// Shared imports, re-exported so submodules can pull them in via `use super::*;`.
pub(crate) use std::net::{Ipv4Addr, Ipv6Addr};

pub(crate) use clap::Subcommand;
pub(crate) use schemars::JsonSchema;
pub(crate) use serde::{Deserialize, Serialize};
pub(crate) use serde_json::Value;

pub(crate) use crate::core::{
    dns::{
        responses::ListRecordsResponse,
        service::{ListRecordsOptions, RecordWrite, ZoneRead},
    },
    error::Result,
};

/// List DNS records through a vendor-neutral zone reader.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn list_records<C: ZoneRead + ?Sized>(
    client: &C,
    domain: &str,
    zone: Option<&str>,
    options: ListRecordsOptions,
) -> Result<ListRecordsResponse> {
    client.list_records(domain, zone, options).await
}

/// Create a DNS record through a vendor-neutral record writer.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn create_record<C: RecordWrite + ?Sized>(
    client: &C,
    zone: &str,
    domain: &str,
    ttl: u32,
    record: &RecordData,
) -> Result<Value> {
    client.add_record(zone, domain, ttl, record).await
}

/// Delete DNS records through a vendor-neutral record writer.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn delete_record<'a, C: RecordWrite + ?Sized>(
    client: &'a C,
    zone: &'a str,
    domain: &'a str,
    type_params: &'a [(&'a str, String)],
) -> Result<Value> {
    client.delete_record(zone, domain, type_params).await
}

#[cfg(test)]
mod tests;
