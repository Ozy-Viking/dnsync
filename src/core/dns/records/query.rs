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
    let zones_value = client.list_zones(1, 1000).await?;
    let zone_names = extract_zone_names(&zones_value);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::dns::responses::{ZoneInfo, ZoneRecord, ZoneRecords};
    use rstest::{fixture, rstest};
    use serde_json::{Value, json};
    use std::sync::Mutex;

    #[fixture]
    fn options() -> ListRecordsOptions {
        ListRecordsOptions::default()
    }

    #[fixture]
    fn mixed_options() -> ListRecordsOptions {
        ListRecordsOptions {
            use_local_ip: true,
            all_subdomains: true,
        }
    }

    fn make_zone(name: &str) -> ZoneInfo {
        ZoneInfo {
            id: None,
            name: name.to_string(),
            zone_type: "Primary".to_string(),
            disabled: false,
            dnssec_status: None,
        }
    }

    fn make_record(name: &str) -> ZoneRecord {
        ZoneRecord {
            name: name.to_string(),
            record_type: "A".to_string(),
            ttl: 300,
            disabled: false,
            comments: String::new(),
            expiry_ttl: 0,
            data: json!({"ipAddress": "1.2.3.4"}),
            parsed: None,
        }
    }

    struct FakeZoneRead {
        zones: Value,
        calls: Mutex<Vec<(String, Option<String>, ListRecordsOptions)>>,
    }

    impl FakeZoneRead {
        fn new(zones: Value) -> Self {
            Self {
                zones,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(String, Option<String>, ListRecordsOptions)> {
            self.calls
                .lock()
                .expect("calls mutex should not be poisoned")
                .clone()
        }
    }

    impl ZoneRead for FakeZoneRead {
        async fn list_zones(&self, _page: u32, _per_page: u32) -> Result<Value> {
            Ok(self.zones.clone())
        }

        async fn list_records<'a>(
            &'a self,
            domain: &'a str,
            zone: Option<&'a str>,
            options: ListRecordsOptions,
        ) -> Result<ListRecordsResponse> {
            self.calls
                .lock()
                .expect("calls mutex should not be poisoned")
                .push((domain.to_string(), zone.map(str::to_string), options));
            Ok(ListRecordsResponse::single(
                make_zone(zone.unwrap_or(domain)),
                vec![make_record("@"), make_record("huly"), make_record("sub.huly")],
            ))
        }
    }

    #[rstest]
    #[case::relative_label("huly", Some("hankin.io"), "huly.hankin.io")]
    #[case::already_qualified("huly.hankin.io", Some("hankin.io"), "huly.hankin.io")]
    #[case::zone_apex("@", Some("hankin.io"), "hankin.io")]
    #[case::no_zone("huly.hankin.io", None, "huly.hankin.io")]
    #[case::domain_equal_zone("hankin.io", Some("hankin.io"), "hankin.io")]
    #[case::trailing_dots("huly.", Some("hankin.io."), "huly.hankin.io")]
    #[case::mixed_case("Huly.Hankin.IO", Some("hankin.io"), "Huly.Hankin.IO")]
    fn resolve_fqdn_preserves_existing_behavior(
        #[case] domain: &str,
        #[case] zone: Option<&str>,
        #[case] expected: &str,
    ) {
        assert_eq!(resolve_fqdn(domain, zone), expected);
    }

    #[rstest]
    #[case::subdomain("huly.hankin.io", Some("hankin.io"))]
    #[case::single_label("hankin", None)]
    #[case::trailing_dot("huly.hankin.io.", Some("hankin.io"))]
    #[case::tld_guard_source("example.com", Some("com"))]
    fn infer_zone_strips_first_label(#[case] fqdn: &str, #[case] expected: Option<&str>) {
        assert_eq!(infer_zone(fqdn).as_deref(), expected);
    }

    #[rstest]
    fn inferred_tld_is_filtered_by_callers_before_all_subdomains_query() {
        let filtered = infer_zone("example.com").filter(|zone| zone.contains('.'));
        assert!(filtered.is_none(), "TLD result should be filtered out");
    }

    #[rstest]
    #[case::technitium(json!({"response": {"zones": [{"name": "hankin.io"}, {"name": "example.com"}]}}), vec!["hankin.io", "example.com"])]
    #[case::pangolin(json!({"domains": [{"baseDomain": "app.hankin.io"}, {"baseDomain": "other.io"}]}), vec!["app.hankin.io", "other.io"])]
    #[case::cloudflare(json!([{"id": "abc", "name": "hankin.io"}, {"id": "def", "name": "example.com"}]), vec!["hankin.io", "example.com"])]
    #[case::unknown(json!({"other": "stuff"}), Vec::<&str>::new())]
    fn extract_zone_names_handles_vendor_shapes(
        #[case] value: Value,
        #[case] expected: Vec<&str>,
    ) {
        assert_eq!(extract_zone_names(&value), expected);
    }

    #[rstest]
    #[tokio::test]
    async fn list_records_for_all_zones_queries_each_zone_apex(options: ListRecordsOptions) {
        let client = FakeZoneRead::new(json!({
            "response": {
                "zones": [{"name": "hankin.io"}, {"name": "example.com"}]
            }
        }));

        let response = list_records_for_all_zones(&client, options)
            .await
            .expect("all zones should list");

        let calls: Vec<(String, Option<String>)> = client
            .calls()
            .into_iter()
            .map(|(domain, zone, _)| (domain, zone))
            .collect();
        assert_eq!(
            calls,
            vec![
                ("hankin.io".to_string(), Some("hankin.io".to_string())),
                ("example.com".to_string(), Some("example.com".to_string())),
            ]
        );
        let zone_names: Vec<&str> = response
            .zones
            .iter()
            .map(|z| z.zone.name.as_str())
            .collect();
        assert_eq!(zone_names, vec!["hankin.io", "example.com"]);
    }

    #[rstest]
    #[tokio::test]
    async fn list_records_for_all_zones_preserves_query_options(mixed_options: ListRecordsOptions) {
        let client = FakeZoneRead::new(json!({"response": {"zones": [{"name": "hankin.io"}]}}));

        list_records_for_all_zones(&client, mixed_options)
            .await
            .expect("all zones should list");

        let actual_options = client.calls()[0].2;
        assert_eq!(actual_options.use_local_ip, mixed_options.use_local_ip);
        assert_eq!(actual_options.all_subdomains, mixed_options.all_subdomains);
    }

    #[rstest]
    #[tokio::test]
    async fn list_records_for_all_zones_empty_zones_returns_empty(options: ListRecordsOptions) {
        let client = FakeZoneRead::new(json!({"response": {"zones": []}}));

        let response = list_records_for_all_zones(&client, options)
            .await
            .expect("empty zones should still succeed");

        assert!(client.calls().is_empty());
        assert!(response.zones.is_empty());
    }

    #[rstest]
    #[tokio::test]
    async fn bare_label_search_queries_each_zone_with_label(options: ListRecordsOptions) {
        let client = FakeZoneRead::new(json!({"response": {"zones": [{"name": "hankin.io"}, {"name": "example.com"}]}}));

        search_bare_label_in_zones(&client, "huly", false, options)
            .await
            .expect("bare label search should succeed");

        let calls: Vec<(String, Option<String>)> = client
            .calls()
            .into_iter()
            .map(|(domain, zone, _)| (domain, zone))
            .collect();
        assert_eq!(
            calls,
            vec![
                ("huly.hankin.io".to_string(), Some("hankin.io".to_string())),
                ("huly.example.com".to_string(), Some("example.com".to_string())),
            ]
        );
    }

    #[rstest]
    #[tokio::test]
    async fn bare_label_all_subdomains_queries_zone_apex_and_filters(
        mixed_options: ListRecordsOptions,
    ) {
        let client = FakeZoneRead::new(json!({"response": {"zones": [{"name": "hankin.io"}]}}));

        let response = search_bare_label_in_zones(&client, "huly", true, mixed_options)
            .await
            .expect("bare label all-subdomain search should succeed");

        let calls = client.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "hankin.io");
        assert_eq!(calls[0].1.as_deref(), Some("hankin.io"));
        assert_eq!(calls[0].2.use_local_ip, mixed_options.use_local_ip);
        assert_eq!(calls[0].2.all_subdomains, mixed_options.all_subdomains);
        let names: Vec<&str> = response.zones[0]
            .records
            .iter()
            .map(|record| record.name.as_str())
            .collect();
        assert_eq!(names, vec!["huly", "sub.huly"]);
    }

    #[rstest]
    #[case::exact_relative(vec!["huly", "other"], "huly.hankin.io", false, vec!["huly"])]
    #[case::exact_fqdn(vec!["huly.hankin.io", "other.hankin.io"], "huly.hankin.io", false, vec!["huly.hankin.io"])]
    #[case::exact_trailing_dot(vec!["huly.hankin.io."], "huly.hankin.io", false, vec!["huly.hankin.io."])]
    #[case::zone_apex(vec!["@", "www"], "hankin.io", false, vec!["@"]) ]
    #[case::all_subdomains(vec!["huly", "sub.huly", "other", "@"], "huly.hankin.io", true, vec!["huly", "sub.huly"])]
    #[case::duplicates(vec!["huly", "huly", "other"], "huly.hankin.io", false, vec!["huly", "huly"])]
    #[case::mixed_case(vec!["Huly", "other"], "huly.hankin.io", false, vec!["Huly"])]
    fn filter_records_by_domain_keeps_expected_matches(
        #[case] record_names: Vec<&str>,
        #[case] target: &str,
        #[case] all_subdomains: bool,
        #[case] expected_names: Vec<&str>,
    ) {
        let mut resp = ListRecordsResponse {
            zones: vec![ZoneRecords {
                zone: make_zone("hankin.io"),
                records: record_names.into_iter().map(make_record).collect(),
            }],
        };

        filter_records_by_domain(&mut resp, target, all_subdomains);

        let names: Vec<&str> = resp
            .zones
            .first()
            .map(|zone| zone.records.iter().map(|record| record.name.as_str()).collect())
            .unwrap_or_default();
        assert_eq!(names, expected_names);
    }

    #[rstest]
    fn filter_records_by_domain_drops_empty_zones() {
        let mut resp = ListRecordsResponse {
            zones: vec![ZoneRecords {
                zone: make_zone("hankin.io"),
                records: vec![make_record("other")],
            }],
        };

        filter_records_by_domain(&mut resp, "huly.hankin.io", false);

        assert!(resp.zones.is_empty());
    }
}
