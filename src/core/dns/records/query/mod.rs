use serde_json::Value;

use crate::core::{
    dns::{
        responses::ListRecordsResponse,
        service::{ListRecordsOptions, ZoneRead},
    },
    error::Result,
};

/// Build the fully-qualified domain name from a possibly-relative label and an optional zone.
///
/// Examples:
/// - `("huly", Some("hankin.io"))` → `"huly.hankin.io"`
/// - `("huly.hankin.io", Some("hankin.io"))` → `"huly.hankin.io"` (already qualified)
/// - `("@", Some("hankin.io"))` → `"hankin.io"` (zone apex)
/// - `("huly.hankin.io", None)` → `"huly.hankin.io"` (passed through)
#[must_use]
pub fn resolve_fqdn(domain: &str, zone: Option<&str>) -> String {
    let Some(zone) = zone else {
        return domain.trim_end_matches('.').to_string();
    };
    let domain = domain.trim_end_matches('.');
    let zone = zone.trim_end_matches('.');
    if domain == "@" {
        return zone.to_string();
    }
    let d_lower = domain.to_lowercase();
    let z_lower = zone.to_lowercase();
    if d_lower == z_lower || d_lower.ends_with(&format!(".{z_lower}")) {
        domain.to_string()
    } else {
        format!("{domain}.{zone}")
    }
}

/// Strip the leftmost DNS label to get the likely parent zone name.
/// Returns `None` for single-label names (e.g. `"hankin"`).
#[must_use]
pub fn infer_zone(fqdn: &str) -> Option<String> {
    let fqdn = fqdn.trim_end_matches('.');
    fqdn.find('.').map(|pos| fqdn[pos + 1..].to_string())
}

/// Extract zone/domain names from a `list_zones` response.
/// Handles the three known vendor formats:
/// - Technitium: `{"response": {"zones": [{"name": "..."}]}}`
/// - Pangolin:   `{"domains": [{"baseDomain": "..."}]}`
/// - Cloudflare: `[{"name": "..."}]` (array at root after envelope unwrap)
#[must_use]
pub fn extract_zone_names(value: &Value) -> Vec<String> {
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

/// Count the raw number of zone entries in a `list_zones` page, before any
/// name extraction/filtering. Used to drive pagination termination so that
/// entries with missing/non-string names don't make a full page look short.
#[must_use]
pub fn zone_page_len(value: &Value) -> usize {
    if let Some(arr) = value
        .get("response")
        .and_then(|r| r.get("zones"))
        .and_then(|z| z.as_array())
    {
        return arr.len();
    }
    if let Some(arr) = value.get("domains").and_then(|d| d.as_array()) {
        return arr.len();
    }
    if let Some(arr) = value.as_array() {
        return arr.len();
    }
    0
}

/// List every zone name on a server, paging until a short/empty page is seen.
///
/// Pagination stops based on the raw page size (see [`zone_page_len`]) rather
/// than the count of successfully-extracted names, so deployments with more
/// than `page_size` zones are fully enumerated.
///
/// # Errors
///
/// Returns any error reported by the backend's `list_zones`.
pub async fn list_all_zone_names<C: ZoneRead + Send + Sync>(
    client: &C,
    page_size: u32,
) -> Result<Vec<String>> {
    let mut page = 1;
    let mut names = Vec::new();
    loop {
        let value = client.list_zones(page, page_size).await?;
        let raw_len = zone_page_len(&value);
        names.extend(extract_zone_names(&value));
        if raw_len < page_size as usize {
            break;
        }
        page += 1;
    }
    Ok(names)
}

/// Resolve CLI/MCP-style record-list inputs into one vendor-neutral record query.
///
/// # Errors
///
/// Returns errors from zone listing or record listing operations.
pub async fn list_records_for_query<C: ZoneRead + Send + Sync>(
    client: &C,
    domain: Option<&str>,
    zone: Option<&str>,
    all_subdomains: bool,
    use_local_ip: bool,
) -> Result<ListRecordsResponse> {
    let options = ListRecordsOptions {
        use_local_ip,
        all_subdomains,
    };

    let Some(domain) = domain else {
        return list_records_for_all_zones(client, options).await;
    };

    let effective_fqdn = resolve_fqdn(domain, zone);
    let is_bare_label = zone.is_none() && !effective_fqdn.contains('.');

    if is_bare_label {
        return search_bare_label_in_zones(client, &effective_fqdn, all_subdomains, options).await;
    }

    let (query_domain, query_zone) = if all_subdomains {
        let zone_name = zone
            .map(str::to_string)
            .or_else(|| infer_zone(&effective_fqdn).filter(|z| z.contains('.')))
            .unwrap_or_else(|| effective_fqdn.clone());
        (zone_name.clone(), Some(zone_name))
    } else {
        (effective_fqdn.clone(), zone.map(str::to_string))
    };

    let mut response = client
        .list_records(&query_domain, query_zone.as_deref(), options)
        .await?;

    if all_subdomains {
        filter_records_by_domain(&mut response, &effective_fqdn, true);
    }

    Ok(response)
}

/// Query every hosted zone for records whose DNS name equals `label`.
/// When `all_subdomains` is true, records beneath `label` in each zone are also included.
/// Zones where the label does not exist are silently skipped.
///
/// # Errors
///
/// Returns an error if listing zones fails. Per-zone misses are skipped to
/// preserve bare-label search behavior across heterogeneous vendors.
pub async fn search_bare_label_in_zones<C: ZoneRead + Send + Sync>(
    client: &C,
    label: &str,
    all_subdomains: bool,
    options: ListRecordsOptions,
) -> Result<ListRecordsResponse> {
    let zone_names = list_all_zone_names(client, 1000).await?;

    let mut all_zone_records = Vec::new();
    for zone_name in &zone_names {
        let target_fqdn = format!("{label}.{zone_name}");
        if all_subdomains {
            let Ok(mut resp) = client
                .list_records(zone_name, Some(zone_name.as_str()), options)
                .await
            else {
                continue;
            };
            filter_records_by_domain(&mut resp, &target_fqdn, true);
            all_zone_records.extend(resp.zones);
        } else if let Ok(mut resp) = client
            .list_records(&target_fqdn, Some(zone_name.as_str()), options)
            .await
        {
            // Some vendors ignore the domain argument and return the full
            // zone record set, so filter to the exact target FQDN.
            filter_records_by_domain(&mut resp, &target_fqdn, false);
            all_zone_records.extend(resp.zones);
        }
    }
    Ok(ListRecordsResponse {
        zones: all_zone_records,
    })
}

/// Query every hosted zone and return its complete record set.
///
/// # Errors
///
/// Returns an error if listing zones fails or a zone record-list request fails.
pub async fn list_records_for_all_zones<C: ZoneRead + Send + Sync>(
    client: &C,
    options: ListRecordsOptions,
) -> Result<ListRecordsResponse> {
    let zone_names = list_all_zone_names(client, 1000).await?;

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

#[cfg(test)]
mod tests;
