//! Technitium implementations of the vendor-neutral DNS service traits.

use serde_json::Value;

use crate::control_plane::config::VendorKind;
use crate::core::dns::capabilities::VendorCapabilities;
use crate::core::dns::records::RecordData;
use crate::core::dns::responses::ListRecordsResponse;
use crate::core::dns::service::{
    AccessListRead, AccessListWrite, CacheRead, CacheWrite, DnsVendor, RecordWrite, SettingsRead,
    StatsRead, ZoneImport, ZoneRead, ZoneWrite,
};
use crate::core::error::Result;
use crate::vendors::technitium::client::TechnitiumClient;

impl DnsVendor for TechnitiumClient {
    fn kind(&self) -> VendorKind {
        VendorKind::Technitium
    }

    fn capabilities(&self) -> VendorCapabilities {
        VendorCapabilities {
            zones: true,
            records: true,
            cache: true,
            access_lists: true,
            settings: true,
            zone_import: true,
        }
    }
}

impl ZoneRead for TechnitiumClient {
    async fn list_zones(&self, page: u32, per_page: u32) -> Result<Value> {
        self.get(
            "/api/zones/list",
            &[
                ("pageNumber", &page.to_string()),
                ("zonesPerPage", &per_page.to_string()),
            ],
        )
        .await
    }

    async fn list_records(&self, domain: &str, zone: Option<&str>) -> Result<ListRecordsResponse> {
        let mut params = vec![("domain", domain)];
        if let Some(z) = zone {
            params.push(("zone", z));
        }
        let raw = self.get("/api/zones/records/get", &params).await?;
        ListRecordsResponse::from_value(&raw)
    }
}

impl ZoneWrite for TechnitiumClient {
    async fn create_zone(&self, zone: &str, zone_type: &str) -> Result<Value> {
        self.post("/api/zones/create", &[("zone", zone), ("type", zone_type)])
            .await
    }

    async fn delete_zone(&self, zone: &str) -> Result<Value> {
        self.post("/api/zones/delete", &[("zone", zone)]).await
    }

    async fn enable_zone(&self, zone: &str) -> Result<Value> {
        self.post("/api/zones/enable", &[("zone", zone)]).await
    }

    async fn disable_zone(&self, zone: &str) -> Result<Value> {
        self.post("/api/zones/disable", &[("zone", zone)]).await
    }
}

impl RecordWrite for TechnitiumClient {
    async fn add_record(
        &self,
        zone: &str,
        domain: &str,
        ttl: u32,
        record: &RecordData,
    ) -> Result<Value> {
        let ttl_s = ttl.to_string();
        let type_params = record.to_api_params();

        let mut form: Vec<(&str, &str)> = vec![("zone", zone), ("domain", domain), ("ttl", &ttl_s)];
        let type_refs: Vec<(&str, &str)> =
            type_params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        form.extend(type_refs);

        self.post("/api/zones/records/add", &form).await
    }

    async fn delete_record(
        &self,
        zone: &str,
        domain: &str,
        type_params: &[(&str, String)],
    ) -> Result<Value> {
        let mut form: Vec<(&str, &str)> = vec![("zone", zone), ("domain", domain)];
        let type_refs: Vec<(&str, &str)> =
            type_params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        form.extend(type_refs);
        self.post("/api/zones/records/delete", &form).await
    }
}

impl CacheRead for TechnitiumClient {
    async fn list_cache(&self, domain: &str) -> Result<Value> {
        self.get("/api/cache/list", &[("domain", domain)]).await
    }
}

impl CacheWrite for TechnitiumClient {
    async fn delete_cache_zone(&self, domain: &str) -> Result<Value> {
        self.post("/api/cache/delete", &[("domain", domain)]).await
    }

    async fn flush_cache(&self) -> Result<Value> {
        self.get("/api/cache/flush", &[]).await
    }
}

impl StatsRead for TechnitiumClient {
    async fn get_stats(&self, stats_type: &str) -> Result<Value> {
        self.get("/api/dashboard/stats/get", &[("type", stats_type)])
            .await
    }
}

impl AccessListRead for TechnitiumClient {
    async fn list_blocked(&self) -> Result<Value> {
        self.get("/api/blocked/list", &[]).await
    }

    async fn list_allowed(&self) -> Result<Value> {
        self.get("/api/allowed/list", &[]).await
    }
}

impl AccessListWrite for TechnitiumClient {
    async fn add_blocked(&self, domain: &str) -> Result<Value> {
        self.post("/api/blocked/add", &[("domain", domain)]).await
    }

    async fn delete_blocked(&self, domain: &str) -> Result<Value> {
        self.post("/api/blocked/delete", &[("domain", domain)])
            .await
    }

    async fn add_allowed(&self, domain: &str) -> Result<Value> {
        self.post("/api/allowed/add", &[("domain", domain)]).await
    }

    async fn delete_allowed(&self, domain: &str) -> Result<Value> {
        self.post("/api/allowed/delete", &[("domain", domain)])
            .await
    }
}

impl ZoneImport for TechnitiumClient {
    async fn import_zone_file(
        &self,
        zone: &str,
        file_name: String,
        file_bytes: Vec<u8>,
        overwrite: bool,
        overwrite_zone: bool,
        overwrite_soa_serial: bool,
    ) -> Result<Value> {
        self.post_file(
            "/api/zones/import",
            &[
                ("zone", zone),
                ("overwrite", if overwrite { "true" } else { "false" }),
                (
                    "overwriteZone",
                    if overwrite_zone { "true" } else { "false" },
                ),
                (
                    "overwriteSoaSerial",
                    if overwrite_soa_serial {
                        "true"
                    } else {
                        "false"
                    },
                ),
            ],
            file_name,
            file_bytes,
        )
        .await
    }
}

impl SettingsRead for TechnitiumClient {
    async fn get_settings(&self) -> Result<Value> {
        self.get("/api/settings/get", &[]).await
    }
}
