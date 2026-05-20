use serde_json::Value;

use crate::control_plane::config::{AppConfig, DnsServerConfig};
use crate::core::dns::responses::ListRecordsResponse;
use crate::core::dns::service::{ListRecordsOptions, ZoneRead};
use crate::core::error::Result;
use crate::vendors::runtime::VendorClient;
use crate::vendors::VendorKind;

// ── Per-server record query result ────────────────────────────────────────────

pub struct ServerQueryResult {
    pub server_id: String,
    pub vendor: VendorKind,
    pub response: ListRecordsResponse,
}

// ── Zone-name helpers ─────────────────────────────────────────────────────────

/// Extract zone/domain names from a `list_zones` response.
/// Handles the three known vendor formats:
/// - Technitium: `{"response": {"zones": [{"name": "..."}]}}`
/// - Pangolin:   `{"domains": [{"baseDomain": "..."}]}`
/// - Cloudflare: `[{"name": "..."}]`  (array at root after envelope unwrap)
pub fn extract_zone_names(value: &Value) -> Vec<String> {
    // Technitium
    if let Some(arr) = value
        .get("response")
        .and_then(|r| r.get("zones"))
        .and_then(|z| z.as_array())
    {
        let names: Vec<_> = arr
            .iter()
            .filter_map(|z| z.get("name").and_then(|n| n.as_str()).map(str::to_string))
            .collect();
        if !names.is_empty() {
            return names;
        }
    }
    // Pangolin
    if let Some(arr) = value.get("domains").and_then(|d| d.as_array()) {
        let names: Vec<_> = arr
            .iter()
            .filter_map(|d| {
                d.get("baseDomain")
                    .and_then(|n| n.as_str())
                    .map(str::to_string)
            })
            .collect();
        if !names.is_empty() {
            return names;
        }
    }
    // Cloudflare (array at root)
    if let Some(arr) = value.as_array() {
        let names: Vec<_> = arr
            .iter()
            .filter_map(|z| z.get("name").and_then(|n| n.as_str()).map(str::to_string))
            .collect();
        if !names.is_empty() {
            return names;
        }
    }
    Vec::new()
}

/// Query every hosted zone for records whose DNS name equals `label`.
/// When `all_subdomains` is true, records beneath `label` in each zone are also included.
/// Zones where the label does not exist are silently skipped.
pub async fn search_bare_label_in_zones<C: ZoneRead + Send + Sync>(
    client: &C,
    label: &str,
    all_subdomains: bool,
    options: ListRecordsOptions,
) -> Result<ListRecordsResponse> {
    let zones_value = client.list_zones(1, 1000).await?;
    let zone_names = extract_zone_names(&zones_value);

    let mut all_zone_records = Vec::new();
    for zone_name in &zone_names {
        let target_fqdn = format!("{label}.{zone_name}");
        if all_subdomains {
            let mut resp = match client
                .list_records(zone_name, Some(zone_name.as_str()), options)
                .await
            {
                Ok(r) => r,
                Err(_) => continue,
            };
            filter_records_by_domain(&mut resp, &target_fqdn, true);
            all_zone_records.extend(resp.zones);
        } else {
            match client
                .list_records(&target_fqdn, Some(zone_name.as_str()), options)
                .await
            {
                Ok(mut resp) => {
                    // Cloudflare ignores the domain argument and returns the full
                    // zone record set, so filter to the exact target FQDN.
                    filter_records_by_domain(&mut resp, &target_fqdn, false);
                    all_zone_records.extend(resp.zones);
                }
                Err(_) => {}
            }
        }
    }
    Ok(ListRecordsResponse {
        zones: all_zone_records,
    })
}

/// Query every hosted zone and return its complete record set.
pub async fn list_records_for_all_zones<C: ZoneRead + Send + Sync>(
    client: &C,
    options: ListRecordsOptions,
) -> Result<ListRecordsResponse> {
    let zones_value = client.list_zones(1, 1000).await?;
    let zone_names = extract_zone_names(&zones_value);

    let mut all_zone_records = Vec::new();
    for zone_name in &zone_names {
        let resp = client
            .list_records(zone_name, Some(zone_name.as_str()), options)
            .await?;
        all_zone_records.extend(resp.zones);
    }

    Ok(ListRecordsResponse {
        zones: all_zone_records,
    })
}

/// Retain only records whose FQDN matches `target_fqdn` (or, when `all_subdomains`
/// is true, any record at or under `target_fqdn`). Zones that become empty are dropped.
pub fn filter_records_by_domain(
    response: &mut ListRecordsResponse,
    target_fqdn: &str,
    all_subdomains: bool,
) {
    let target = target_fqdn.trim_end_matches('.').to_lowercase();
    for zone_records in &mut response.zones {
        let zone = zone_records.zone.name.to_lowercase();
        zone_records.records.retain(|r| {
            let record_name = r.name.trim_end_matches('.').to_lowercase();
            let record_fqdn = if record_name == "@" {
                zone.clone()
            } else if record_name == zone || record_name.ends_with(&format!(".{zone}")) {
                record_name
            } else {
                format!("{record_name}.{zone}")
            };
            if all_subdomains {
                record_fqdn == target || record_fqdn.ends_with(&format!(".{target}"))
            } else {
                record_fqdn == target
            }
        });
    }
    response.zones.retain(|z| !z.records.is_empty());
}

// ── Multi-server record query ─────────────────────────────────────────────────

/// Query records across multiple servers. Returns per-server results; errors for
/// individual servers are returned inside the `Result` so callers can decide how
/// to handle partial failures.
pub async fn query_records_across_servers(
    selected_servers: &[&DnsServerConfig],
    domain: Option<&str>,
    zone: Option<&str>,
    all_subdomains: bool,
    options: ListRecordsOptions,
) -> Vec<(String, VendorKind, Result<ListRecordsResponse>)> {
    use crate::core::dns::util::{infer_zone, resolve_fqdn};

    let domain_query = domain.map(|domain| {
        let effective_fqdn = resolve_fqdn(domain, zone);
        let is_bare_label = zone.is_none() && !effective_fqdn.contains('.');
        let (query_domain, query_zone) = if !is_bare_label && all_subdomains {
            let zone_name = zone
                .map(str::to_string)
                .or_else(|| infer_zone(&effective_fqdn).filter(|z| z.contains('.')))
                .unwrap_or_else(|| effective_fqdn.clone());
            (zone_name.clone(), Some(zone_name))
        } else {
            (effective_fqdn.clone(), zone.map(str::to_string))
        };
        (effective_fqdn, is_bare_label, query_domain, query_zone)
    });

    let mut results = Vec::new();
    for server in selected_servers {
        let client = match VendorClient::from_server(server) {
            Ok(c) => c,
            Err(e) => {
                results.push((server.id.clone(), server.vendor, Err(e)));
                continue;
            }
        };

        let result = match &domain_query {
            None => list_records_for_all_zones(&client, options).await,
            Some((effective_fqdn, true, _, _)) => {
                search_bare_label_in_zones(&client, effective_fqdn, all_subdomains, options).await
            }
            Some((_, false, query_domain, query_zone)) => {
                client
                    .list_records(query_domain, query_zone.as_deref(), options)
                    .await
            }
        };

        let result = result.map(|mut response| {
            if let Some((effective_fqdn, false, _, _)) = &domain_query
                && all_subdomains
            {
                filter_records_by_domain(&mut response, effective_fqdn, true);
            }
            response
        });

        results.push((server.id.clone(), server.vendor, result));
    }
    results
}

// ── Zone transfer ─────────────────────────────────────────────────────────────

pub async fn server_export_zone(server: &DnsServerConfig, zone: &str) -> Result<String> {
    VendorClient::export_zone_for_server(server, zone).await
}

pub async fn server_import_zone(
    server: &DnsServerConfig,
    zone: &str,
    file_name: String,
    file_bytes: Vec<u8>,
    overwrite: bool,
    overwrite_zone: bool,
) -> Result<Value> {
    VendorClient::import_zone_for_server(server, zone, file_name, file_bytes, overwrite, overwrite_zone).await
}

/// Export a zone from one server and import it into another. Returns the import
/// result value (if non-null) that callers can display.
pub async fn transfer_zone(
    cfg: &AppConfig,
    zone: &str,
    from_id: &str,
    to_id: &str,
    overwrite: bool,
    overwrite_zone: bool,
) -> Result<Option<Value>> {
    let from_server = cfg.selected_server(Some(from_id))?;
    let to_server = cfg.selected_server(Some(to_id))?;

    let zone_file = server_export_zone(from_server, zone).await?;

    let file_name = format!("{zone}.txt");
    let result = server_import_zone(
        to_server,
        zone,
        file_name,
        zone_file.into_bytes(),
        overwrite,
        overwrite_zone,
    )
    .await?;

    Ok(if result.is_null() { None } else { Some(result) })
}

// ── Client construction ───────────────────────────────────────────────────────

/// Select servers from config by ID. Returns an error if any ID is unknown.
pub fn select_servers<'a>(
    cfg: &'a AppConfig,
    server_ids: &[String],
) -> Result<Vec<&'a DnsServerConfig>> {
    let mut picked = Vec::with_capacity(server_ids.len());
    for id in server_ids {
        picked.push(cfg.selected_server(Some(id.as_str()))?);
    }
    Ok(picked)
}
