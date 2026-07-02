use super::*;
use crate::core::secret::ApiToken;
use mockito::{Matcher, ServerGuard};
use rstest::{fixture, rstest};

#[fixture]
async fn server() -> ServerGuard {
    mockito::Server::new_async().await
}

fn make_server_client(server: &ServerGuard, site: &str) -> UnifiClient {
    UnifiClient::new(server.url(), ApiToken::new("test-token"), site.to_string())
        .expect("test client builds")
}

fn make_client() -> UnifiClient {
    UnifiClient::new(
        "https://unifi.local/proxy/network/integration/v1".to_string(),
        ApiToken::new("test-token"),
        "11111111-1111-1111-1111-111111111111".to_string(),
    )
    .unwrap()
}

#[rstest]
#[tokio::test]
async fn list_zones_returns_vendor_neutral_payload(#[future] server: ServerGuard) {
    let mut server = server.await;
    let sites = server
        .mock("GET", "/sites")
        .match_query(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"offset":0,"limit":25,"count":1,"totalCount":1,
                "data":[{"id":"site-uuid","name":"Default"}]}"#,
        )
        .create_async()
        .await;
    let client = make_server_client(&server, "Default");

    let result = client.list_zones(1, 25).await.expect("zones list");

    sites.assert_async().await;
    assert_eq!(
        result,
        serde_json::json!({
            "response": {
                "zones": [{
                    "id": "site-uuid",
                    "name": "Default",
                    "type": "UniFi/Site",
                    "disabled": false,
                    "dnssecStatus": null
                }]
            }
        })
    );
}

#[rstest]
#[tokio::test]
async fn list_records_rejects_unknown_explicit_zone_without_default_fallback(
    #[future] server: ServerGuard,
) {
    let mut server = server.await;
    let sites = server
        .mock("GET", "/sites")
        .match_query(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"offset":0,"limit":200,"count":1,"totalCount":1,
                "data":[{"id":"site-uuid","name":"Default"}]}"#,
        )
        .create_async()
        .await;
    let client = make_server_client(&server, "Default");

    let err = client
        .list_records(
            "example.com",
            Some("Missing"),
            ListRecordsOptions::default(),
        )
        .await
        .expect_err("unknown explicit zone must fail");

    sites.assert_async().await;
    assert!(matches!(err, Error::Api { message } if message.contains("Missing")));
}

#[rstest]
#[tokio::test]
async fn list_records_reuses_cached_configured_site_id(#[future] server: ServerGuard) {
    let mut server = server.await;
    let sites = server
        .mock("GET", "/sites")
        .match_query(Matcher::Any)
        .expect(1)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"offset":0,"limit":200,"count":1,"totalCount":1,
                "data":[{"id":"site-uuid","name":"Default"}]}"#,
        )
        .create_async()
        .await;
    let policies = server
        .mock("GET", "/sites/site-uuid/dns/policies")
        .match_query(Matcher::Any)
        .expect(2)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"offset":0,"limit":200,"count":0,"totalCount":0,"data":[]}"#)
        .create_async()
        .await;
    let client = make_server_client(&server, "Default");

    for _ in 0..2 {
        client
            .list_records("example.com", None, ListRecordsOptions::default())
            .await
            .expect("records list");
    }

    sites.assert_async().await;
    policies.assert_async().await;
}

// ── kind / capabilities ──────────────────────────────────────────────────

#[test]
fn kind_returns_unifi() {
    assert_eq!(make_client().kind(), VendorKind::Unifi);
}

#[test]
fn capabilities_advertise_records_and_settings() {
    let caps = make_client().capabilities();
    assert!(caps.zones);
    assert!(caps.records);
    assert!(!caps.cache);
    assert!(!caps.access_lists);
    // `get_settings` exposes the site list for UUID discovery.
    assert!(caps.settings);
    assert!(!caps.zone_import);
    assert!(!caps.zone_export);
}

// ── unsupported operations ───────────────────────────────────────────────

macro_rules! assert_unsupported {
    ($call:expr) => {
        match $call.await.unwrap_err() {
            Error::Unsupported { vendor, .. } => assert_eq!(vendor, "UniFi"),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    };
}

#[tokio::test]
async fn create_zone_is_unsupported() {
    assert_unsupported!(make_client().create_zone("example.com", "Primary"));
}

#[tokio::test]
async fn delete_zone_is_unsupported() {
    assert_unsupported!(make_client().delete_zone("example.com"));
}

#[tokio::test]
async fn enable_zone_is_unsupported() {
    assert_unsupported!(make_client().enable_zone("example.com"));
}

#[tokio::test]
async fn disable_zone_is_unsupported() {
    assert_unsupported!(make_client().disable_zone("example.com"));
}

#[tokio::test]
async fn list_cache_is_unsupported() {
    assert_unsupported!(make_client().list_cache("example.com"));
}

#[tokio::test]
async fn delete_cache_zone_is_unsupported() {
    assert_unsupported!(make_client().delete_cache_zone("example.com"));
}

#[tokio::test]
async fn flush_cache_is_unsupported() {
    assert_unsupported!(make_client().flush_cache());
}

#[tokio::test]
async fn get_stats_is_unsupported() {
    assert_unsupported!(make_client().get_stats("last7days"));
}

#[tokio::test]
async fn list_blocked_is_unsupported() {
    assert_unsupported!(make_client().list_blocked());
}

#[tokio::test]
async fn list_allowed_is_unsupported() {
    assert_unsupported!(make_client().list_allowed());
}

#[tokio::test]
async fn add_blocked_is_unsupported() {
    assert_unsupported!(make_client().add_blocked("evil.example.com"));
}

#[tokio::test]
async fn delete_blocked_is_unsupported() {
    assert_unsupported!(make_client().delete_blocked("evil.example.com"));
}

#[tokio::test]
async fn add_allowed_is_unsupported() {
    assert_unsupported!(make_client().add_allowed("ok.example.com"));
}

#[tokio::test]
async fn delete_allowed_is_unsupported() {
    assert_unsupported!(make_client().delete_allowed("ok.example.com"));
}

#[tokio::test]
async fn import_zone_file_is_unsupported() {
    assert_unsupported!(make_client().import_zone_file(
        "example.com",
        "zone.txt".to_string(),
        vec![],
        true,
        false,
        false,
    ));
}

#[tokio::test]
async fn export_zone_file_is_unsupported() {
    assert_unsupported!(make_client().export_zone_file("example.com"));
}

// ── resolve_fqdn ─────────────────────────────────────────────────────────

#[test]
fn at_resolves_to_zone() {
    assert_eq!(resolve_fqdn("@", "example.com"), "example.com");
}

#[test]
fn relative_label_joins_with_zone() {
    assert_eq!(resolve_fqdn("www", "example.com"), "www.example.com");
}

#[test]
fn absolute_fqdn_is_kept() {
    assert_eq!(
        resolve_fqdn("www.example.com", "example.com"),
        "www.example.com"
    );
}

#[test]
fn trailing_dot_is_stripped() {
    assert_eq!(
        resolve_fqdn("www.example.com.", "example.com"),
        "www.example.com"
    );
}

#[test]
fn relative_dotted_label_is_appended_to_zone() {
    assert_eq!(resolve_fqdn("a.b", "example.com"), "a.b.example.com");
}

#[test]
fn unrelated_fqdn_is_still_appended_to_zone() {
    // A name that is not under the zone is treated as relative and
    // appended — UniFi has no concept of cross-zone references.
    assert_eq!(
        resolve_fqdn("other.net", "example.com"),
        "other.net.example.com"
    );
}

// ── add_record rejects unsupported types pre-flight ─────────────────────

#[tokio::test]
async fn add_record_rejects_unsupported_type_without_network_call() {
    let client = make_client();
    let err = client
        .add_record(
            "example.com",
            "@",
            300,
            &RecordData::Ns {
                nameserver: "ns1.example.com".into(),
                glue: None,
            },
        )
        .await
        .unwrap_err();
    // Should be Unsupported, not Network — mapping rejects before any HTTP.
    assert!(matches!(
        err,
        Error::Unsupported {
            vendor: "UniFi",
            ..
        }
    ));
}
