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
            vec![
                make_record("@"),
                make_record("huly"),
                make_record("sub.huly"),
            ],
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
fn extract_zone_names_handles_vendor_shapes(#[case] value: Value, #[case] expected: Vec<&str>) {
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
    let client = FakeZoneRead::new(
        json!({"response": {"zones": [{"name": "hankin.io"}, {"name": "example.com"}]}}),
    );

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
            (
                "huly.example.com".to_string(),
                Some("example.com".to_string())
            ),
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
        .map(|zone| {
            zone.records
                .iter()
                .map(|record| record.name.as_str())
                .collect()
        })
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
