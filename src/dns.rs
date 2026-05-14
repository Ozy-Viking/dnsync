//! Core DNS operations. Both the MCP server and CLI call these functions —
//! neither constructs HTTP params or knows API paths directly.

use serde_json::Value;

use crate::client::TechnitiumClient;
use crate::error::Result;
use crate::response::ListRecordsResponse;
use crate::types::RecordData;

// ─── Zones ───────────────────────────────────────────────────────────────────

pub async fn list_zones(client: &TechnitiumClient, page: u32, per_page: u32) -> Result<Value> {
    client
        .get(
            "/api/zones/list",
            &[
                ("pageNumber", &page.to_string()),
                ("zonesPerPage", &per_page.to_string()),
            ],
        )
        .await
}

pub async fn create_zone(client: &TechnitiumClient, zone: &str, zone_type: &str) -> Result<Value> {
    client
        .post("/api/zones/create", &[("zone", zone), ("type", zone_type)])
        .await
}

pub async fn delete_zone(client: &TechnitiumClient, zone: &str) -> Result<Value> {
    client.post("/api/zones/delete", &[("zone", zone)]).await
}

pub async fn enable_zone(client: &TechnitiumClient, zone: &str) -> Result<Value> {
    client.post("/api/zones/enable", &[("zone", zone)]).await
}

pub async fn disable_zone(client: &TechnitiumClient, zone: &str) -> Result<Value> {
    client.post("/api/zones/disable", &[("zone", zone)]).await
}

// ─── Records ─────────────────────────────────────────────────────────────────

pub async fn list_records(
    client: &TechnitiumClient,
    domain: &str,
    zone: Option<&str>,
) -> Result<ListRecordsResponse> {
    let mut params = vec![("domain", domain)];
    if let Some(z) = zone {
        params.push(("zone", z));
    }
    let raw = client.get("/api/zones/records/get", &params).await?;
    ListRecordsResponse::from_value(&raw)
}

pub async fn add_record(
    client: &TechnitiumClient,
    zone: &str,
    domain: &str,
    ttl: u32,
    record: &RecordData,
) -> Result<Value> {
    let ttl_s = ttl.to_string();
    let type_params = record.to_api_params();

    let mut form: Vec<(&str, &str)> = vec![("zone", zone), ("domain", domain), ("ttl", &ttl_s)];
    let type_refs: Vec<(&str, &str)> = type_params.iter().map(|(k, v)| (*k, v.as_str())).collect();
    form.extend(type_refs);

    client.post("/api/zones/records/add", &form).await
}

pub async fn delete_record(
    client: &TechnitiumClient,
    zone: &str,
    domain: &str,
    type_params: &[(&str, String)],
) -> Result<Value> {
    let mut form: Vec<(&str, &str)> = vec![("zone", zone), ("domain", domain)];
    let type_refs: Vec<(&str, &str)> = type_params.iter().map(|(k, v)| (*k, v.as_str())).collect();
    form.extend(type_refs);
    client.post("/api/zones/records/delete", &form).await
}

// ─── Cache ────────────────────────────────────────────────────────────────────

pub async fn list_cache(client: &TechnitiumClient, domain: &str) -> Result<Value> {
    client.get("/api/cache/list", &[("domain", domain)]).await
}

pub async fn delete_cache_zone(client: &TechnitiumClient, domain: &str) -> Result<Value> {
    client
        .post("/api/cache/delete", &[("domain", domain)])
        .await
}

pub async fn flush_cache(client: &TechnitiumClient) -> Result<Value> {
    client.get("/api/cache/flush", &[]).await
}

// ─── Stats ────────────────────────────────────────────────────────────────────

pub async fn get_stats(client: &TechnitiumClient, stats_type: &str) -> Result<Value> {
    client
        .get("/api/dashboard/stats/get", &[("type", stats_type)])
        .await
}

// ─── Blocked zones ────────────────────────────────────────────────────────────

pub async fn list_blocked(client: &TechnitiumClient) -> Result<Value> {
    client.get("/api/blocked/list", &[]).await
}

pub async fn add_blocked(client: &TechnitiumClient, domain: &str) -> Result<Value> {
    client.post("/api/blocked/add", &[("domain", domain)]).await
}

pub async fn delete_blocked(client: &TechnitiumClient, domain: &str) -> Result<Value> {
    client
        .post("/api/blocked/delete", &[("domain", domain)])
        .await
}

// ─── Allowed zones ────────────────────────────────────────────────────────────

pub async fn list_allowed(client: &TechnitiumClient) -> Result<Value> {
    client.get("/api/allowed/list", &[]).await
}

pub async fn add_allowed(client: &TechnitiumClient, domain: &str) -> Result<Value> {
    client.post("/api/allowed/add", &[("domain", domain)]).await
}

pub async fn delete_allowed(client: &TechnitiumClient, domain: &str) -> Result<Value> {
    client
        .post("/api/allowed/delete", &[("domain", domain)])
        .await
}

// ─── Zone file import ─────────────────────────────────────────────────────────

pub async fn import_zone_file(
    client: &TechnitiumClient,
    zone: &str,
    file_name: String,
    file_bytes: Vec<u8>,
    overwrite: bool,
    overwrite_zone: bool,
    overwrite_soa_serial: bool,
) -> Result<Value> {
    client
        .post_file(
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

// ─── Settings ─────────────────────────────────────────────────────────────────

pub async fn get_settings(client: &TechnitiumClient) -> Result<Value> {
    client.get("/api/settings/get", &[]).await
}
