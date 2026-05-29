//! Vendor-neutral DNS service contracts.
//!
//! Vendor adapters implement these traits so the CLI and MCP layers can depend
//! on DNS capabilities instead of concrete vendor clients.

use std::future::Future;

use serde_json::Value;

use crate::control_plane::config::VendorKind;
use crate::core::dns::capabilities::VendorCapabilities;
use crate::core::dns::logs::LogsRead;
use crate::core::dns::records::RecordData;
use crate::core::dns::responses::ListRecordsResponse;
use crate::core::error::Result;

#[derive(Debug, Clone, Copy, Default)]
pub struct ListRecordsOptions {
    pub use_local_ip: bool,
    /// Fetch all records in the zone so the caller can filter for a domain and its subdomains.
    pub all_subdomains: bool,
}

pub trait DnsVendor {
    fn kind(&self) -> VendorKind;

    fn capabilities(&self) -> VendorCapabilities;
}

pub trait ZoneRead {
    fn list_zones(
        &self,
        page: u32,
        per_page: u32,
    ) -> impl Future<Output = Result<Value>> + Send + '_;

    fn list_records<'a>(
        &'a self,
        domain: &'a str,
        zone: Option<&'a str>,
        options: ListRecordsOptions,
    ) -> impl Future<Output = Result<ListRecordsResponse>> + Send + 'a;
}

pub trait ZoneWrite {
    fn create_zone<'a>(
        &'a self,
        zone: &'a str,
        zone_type: &'a str,
    ) -> impl Future<Output = Result<Value>> + Send + 'a;

    fn delete_zone<'a>(&'a self, zone: &'a str) -> impl Future<Output = Result<Value>> + Send + 'a;

    fn enable_zone<'a>(&'a self, zone: &'a str) -> impl Future<Output = Result<Value>> + Send + 'a;

    fn disable_zone<'a>(&'a self, zone: &'a str)
    -> impl Future<Output = Result<Value>> + Send + 'a;
}

pub trait RecordWrite {
    fn add_record<'a>(
        &'a self,
        zone: &'a str,
        domain: &'a str,
        ttl: u32,
        record: &'a RecordData,
    ) -> impl Future<Output = Result<Value>> + Send + 'a;

    fn delete_record<'a>(
        &'a self,
        zone: &'a str,
        domain: &'a str,
        type_params: &'a [(&'a str, String)],
    ) -> impl Future<Output = Result<Value>> + Send + 'a;
}

pub trait CacheRead {
    fn list_cache<'a>(&'a self, domain: &'a str)
    -> impl Future<Output = Result<Value>> + Send + 'a;
}

pub trait CacheWrite {
    fn delete_cache_zone<'a>(
        &'a self,
        domain: &'a str,
    ) -> impl Future<Output = Result<Value>> + Send + 'a;

    fn flush_cache(&self) -> impl Future<Output = Result<Value>> + Send + '_;
}

pub trait StatsRead {
    fn get_stats<'a>(
        &'a self,
        stats_type: &'a str,
    ) -> impl Future<Output = Result<Value>> + Send + 'a;
}

pub trait AccessListRead {
    fn list_blocked(&self) -> impl Future<Output = Result<Value>> + Send + '_;

    fn list_allowed(&self) -> impl Future<Output = Result<Value>> + Send + '_;
}

pub trait AccessListWrite {
    fn add_blocked<'a>(
        &'a self,
        domain: &'a str,
    ) -> impl Future<Output = Result<Value>> + Send + 'a;

    fn delete_blocked<'a>(
        &'a self,
        domain: &'a str,
    ) -> impl Future<Output = Result<Value>> + Send + 'a;

    fn add_allowed<'a>(
        &'a self,
        domain: &'a str,
    ) -> impl Future<Output = Result<Value>> + Send + 'a;

    fn delete_allowed<'a>(
        &'a self,
        domain: &'a str,
    ) -> impl Future<Output = Result<Value>> + Send + 'a;
}

pub trait ZoneImport {
    fn import_zone_file<'a>(
        &'a self,
        zone: &'a str,
        file_name: String,
        file_bytes: Vec<u8>,
        overwrite: bool,
        overwrite_zone: bool,
        overwrite_soa_serial: bool,
    ) -> impl Future<Output = Result<Value>> + Send + 'a;
}

pub trait ZoneExport {
    fn export_zone_file<'a>(
        &'a self,
        zone: &'a str,
    ) -> impl Future<Output = Result<String>> + Send + 'a;
}

pub trait SettingsRead {
    fn get_settings(&self) -> impl Future<Output = Result<Value>> + Send + '_;
}

pub trait DnsRead:
    DnsVendor + ZoneRead + CacheRead + StatsRead + AccessListRead + SettingsRead + ZoneExport + LogsRead
{
}

impl<T> DnsRead for T where
    T: DnsVendor
        + ZoneRead
        + CacheRead
        + StatsRead
        + AccessListRead
        + SettingsRead
        + ZoneExport
        + LogsRead
{
}

pub trait DnsWrite: ZoneWrite + RecordWrite + CacheWrite + AccessListWrite + ZoneImport {}

impl<T> DnsWrite for T where T: ZoneWrite + RecordWrite + CacheWrite + AccessListWrite + ZoneImport {}

pub trait DnsService: DnsRead + DnsWrite + Send + Sync {}

impl<T> DnsService for T where T: DnsRead + DnsWrite + Send + Sync {}
