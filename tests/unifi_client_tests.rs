//! Wire-level integration tests for `UnifiClient`.
//!
//! UniFi is the one vendor client that does not reuse the shared `HttpClient`:
//! it authenticates with an `X-API-KEY` header, resolves a human-readable site
//! name to a UUID via `GET /sites`, and paginates list endpoints. None of that
//! wire behaviour is covered by the response-parsing unit tests, so it is
//! exercised here against a mock controller.

#![cfg(feature = "unifi")]

use dnslib::error::Error;
use dnslib::secret::ApiToken;
use dnslib::vendors::unifi::client::UnifiClient;
use mockito::{Matcher, ServerGuard};
use rstest::{fixture, rstest};

/// Creates a new asynchronous mock server for use in tests.
///
/// The returned guard manages the server's lifetime and provides the base URL
/// for configuring HTTP clients and registering mock endpoints.
///
/// # Examples
///
/// ```
/// # use mockito::ServerGuard;
/// # async fn run() {
/// let server: ServerGuard = server().await;
/// let base = server.url();
/// assert!(base.starts_with("http"));
/// # }
/// ```
#[fixture]
async fn server() -> ServerGuard {
    mockito::Server::new_async().await
}

/// Constructs a `UnifiClient` pointed at the given mock `server` and configured for `site`.
///
/// The client is created with a fixed API token "`api-key-123`" so it can be used in tests that
/// assert authentication headers and request paths.
///
/// # Examples
///
/// ```ignore
/// // `make_client` is a helper local to this test file.
/// let server = mockito::Server::new_async().await;
/// let client = make_client(&server, "Default");
/// ```
fn make_client(server: &ServerGuard, site: &str) -> UnifiClient {
    UnifiClient::new(server.url(), ApiToken::new("api-key-123"), site.into())
        .expect("client builds")
}

/// Verifies that listing sites includes the configured API key header and returns parsed site entries.
///
/// This integration test starts a mock server that expects a `GET /sites` request with header
/// `x-api-key: api-key-123`, responds with a single site JSON entry, and asserts the client
/// returns that entry.
///
/// # Examples
///
/// ```no_run
/// // Setup a server and client, then call:
/// // let sites = client.list_all_sites().await.unwrap();
/// // assert_eq!(sites[0].id, "site-uuid");
/// ```
#[rstest]
#[tokio::test]
async fn list_all_sites_sends_api_key_and_returns_sites(#[future] server: ServerGuard) {
    let mut server = server.await;
    let mock = server
        .mock("GET", "/sites")
        .match_query(Matcher::Any)
        .match_header("x-api-key", "api-key-123")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"offset":0,"limit":200,"count":1,"totalCount":1,
                "data":[{"id":"site-uuid","name":"Default"}]}"#,
        )
        .create_async()
        .await;

    let client = make_client(&server, "Default");
    let sites = client.list_all_sites().await.expect("ok");

    mock.assert_async().await;
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].id, "site-uuid");
}

#[rstest]
#[tokio::test]
async fn resolve_site_id_matches_configured_name(#[future] server: ServerGuard) {
    let mut server = server.await;
    let _mock = server
        .mock("GET", "/sites")
        .match_query(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"offset":0,"limit":200,"count":2,"totalCount":2,
                "data":[{"id":"uuid-a","name":"Office"},{"id":"uuid-b","name":"Default"}]}"#,
        )
        .create_async()
        .await;

    // Configured with the human-readable name; resolves to the UUID.
    let client = make_client(&server, "default");
    let id = client.resolve_site_id().await.expect("resolves");
    assert_eq!(id, "uuid-b");
}

#[rstest]
#[tokio::test]
async fn resolve_site_id_unknown_site_lists_available(#[future] server: ServerGuard) {
    let mut server = server.await;
    let _mock = server
        .mock("GET", "/sites")
        .match_query(Matcher::Any)
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"offset":0,"limit":200,"count":1,"totalCount":1,
                "data":[{"id":"uuid-a","name":"Office"}]}"#,
        )
        .create_async()
        .await;

    let client = make_client(&server, "Missing");
    let err = client.resolve_site_id().await.unwrap_err();
    match err {
        Error::Api { message } => {
            assert!(message.contains("Missing"), "msg: {message}");
            assert!(
                message.contains("Office"),
                "should list available sites: {message}"
            );
        }
        other => panic!("expected Api error, got {other:?}"),
    }
}

#[rstest]
#[tokio::test]
async fn list_all_sites_paginates_until_total_reached(#[future] server: ServerGuard) {
    let mut server = server.await;

    // Page 1 (offset=0): one of two sites — loop must continue.
    let page1 = server
        .mock("GET", "/sites")
        .match_query(Matcher::UrlEncoded("offset".into(), "0".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"offset":0,"limit":200,"count":1,"totalCount":2,
                "data":[{"id":"uuid-a","name":"A"}]}"#,
        )
        .create_async()
        .await;

    // Page 2 (offset=1): the second site — reaching totalCount terminates.
    let page2 = server
        .mock("GET", "/sites")
        .match_query(Matcher::UrlEncoded("offset".into(), "1".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"offset":1,"limit":200,"count":1,"totalCount":2,
                "data":[{"id":"uuid-b","name":"B"}]}"#,
        )
        .create_async()
        .await;

    let client = make_client(&server, "A");
    let sites = client.list_all_sites().await.expect("ok");

    page1.assert_async().await;
    page2.assert_async().await;
    assert_eq!(sites.len(), 2);
    assert_eq!(sites[0].id, "uuid-a");
    assert_eq!(sites[1].id, "uuid-b");
}

/// Verifies that DNS policy listing resolves the configured site name to its UUID and then requests that site's DNS policies.
///
/// This test starts a mock server that first returns a sites listing containing a site named "Default" with id
/// `site-uuid`, then expects a GET to `/sites/site-uuid/dns/policies` with the API key header and returns one DNS
/// policy. The test asserts the client resolves the site name, queries the correct endpoint, and returns the policy
/// with the expected id and domain.
///
/// # Examples
///
/// ```ignore
/// # async fn example(server: mockito::ServerGuard) {
/// let client = make_client(&server, "Default");
/// let policies = client.list_all_dns_policies(None).await.expect("ok");
/// assert!(policies.iter().any(|p| p.domain == "host.example.com"));
/// # }
/// ```
#[rstest]
#[tokio::test]
async fn list_all_dns_policies_resolves_site_then_queries_policies(#[future] server: ServerGuard) {
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

    // The policies path must include the resolved site UUID.
    let policies = server
        .mock("GET", "/sites/site-uuid/dns/policies")
        .match_query(Matcher::Any)
        .match_header("x-api-key", "api-key-123")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"offset":0,"limit":200,"count":1,"totalCount":1,
                "data":[{"id":"p1","type":"A_RECORD","enabled":true,
                         "domain":"host.example.com","ipv4Address":"1.2.3.4"}]}"#,
        )
        .create_async()
        .await;

    let client = make_client(&server, "Default");
    let found = client.list_all_dns_policies(None).await.expect("ok");

    sites.assert_async().await;
    policies.assert_async().await;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, "p1");
    assert_eq!(found[0].domain, "host.example.com");
}
