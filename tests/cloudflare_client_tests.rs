//! Wire-level integration tests for `CloudflareClient` against a mock HTTP
//! server. Complements the in-module unit tests of `parse_response` by
//! exercising the real request path: bearer auth, the success envelope, and
//! error-status → typed-error mapping.

#![cfg(feature = "cloudflare")]

use dnslib::error::Error;
use dnslib::secret::ApiToken;
use dnslib::vendors::cloudflare::client::CloudflareClient;
use mockito::ServerGuard;
use rstest::{fixture, rstest};

#[fixture]
async fn server() -> ServerGuard {
    mockito::Server::new_async().await
}

fn make_client(server: &ServerGuard) -> CloudflareClient {
    CloudflareClient::new(server.url(), ApiToken::new("cf-token")).expect("client builds")
}

#[rstest]
#[tokio::test]
async fn get_unwraps_success_envelope(#[future] server: ServerGuard) {
    let mut server = server.await;
    let mock = server
        .mock("GET", "/zones")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"success":true,"errors":[],"messages":[],"result":{"id":"z1","name":"example.com"}}"#)
        .create_async()
        .await;

    let client = make_client(&server);
    let value = client.get("/zones", &[]).await.expect("ok");

    mock.assert_async().await;
    // The client returns the inner `result`, not the envelope.
    assert_eq!(value["id"], "z1");
    assert_eq!(value["name"], "example.com");
}

#[rstest]
#[tokio::test]
async fn get_sends_bearer_auth(#[future] server: ServerGuard) {
    let mut server = server.await;
    let mock = server
        .mock("GET", "/zones")
        .match_header("authorization", "Bearer cf-token")
        .with_status(200)
        .with_body(r#"{"success":true,"errors":[],"messages":[],"result":null}"#)
        .create_async()
        .await;

    let client = make_client(&server);
    let _ = client.get("/zones", &[]).await;

    mock.assert_async().await;
}

#[rstest]
#[tokio::test]
async fn unsuccessful_envelope_maps_to_api_error(#[future] server: ServerGuard) {
    let mut server = server.await;
    let _mock = server
        .mock("GET", "/zones")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(r#"{"success":false,"errors":[{"code":1001,"message":"zone not found"}],"messages":[],"result":null}"#)
        .create_async()
        .await;

    let client = make_client(&server);
    let err = client.get("/zones", &[]).await.unwrap_err();
    assert!(
        matches!(err, Error::Api { ref message } if message == "zone not found"),
        "got {err:?}"
    );
}

#[rstest]
#[tokio::test]
async fn forbidden_status_maps_to_forbidden_error(#[future] server: ServerGuard) {
    let mut server = server.await;
    let _mock = server
        .mock("POST", "/zones")
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}],"messages":[],"result":null}"#)
        .create_async()
        .await;

    let client = make_client(&server);
    let err = client
        .post("/zones", &serde_json::json!({"name": "example.com"}))
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Forbidden { ref message } if message == "Invalid access token"),
        "got {err:?}"
    );
}
