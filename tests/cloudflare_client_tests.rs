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

/// Create and start a new asynchronous mockito server for use in tests.
///
/// This fixture starts an independent mock HTTP server and returns its guard,
/// which keeps the server running for the duration of the test.
///
/// # Examples
///
/// ```
/// # async fn __example() {
/// let mut guard = server().await;
/// // use `guard.url()` to configure clients to hit the mock server
/// # }
/// ```
#[fixture]
async fn server() -> ServerGuard {
    mockito::Server::new_async().await
}

/// Constructs a CloudflareClient configured to target the provided mockito server using a fixed API token.
///
/// The returned client is initialized with the mock server's base URL and an API token with value `"cf-token"`.
///
/// # Examples
///
/// ```
/// // in tests: let server = mockito::Server::new();
/// // let client = make_client(&server);
/// // // use `client` to perform requests against the mock server
/// ```
fn make_client(server: &ServerGuard) -> CloudflareClient {
    CloudflareClient::new(server.url(), ApiToken::new("cf-token")).expect("client builds")
}

/// Verifies that a successful Cloudflare JSON envelope returned by GET is unwrapped to the inner `result`.
///
/// This test sends a mocked `GET /zones` response where the envelope has `"success": true` and a `result` object,
/// then asserts the client returns that `result` (not the full envelope).
///
/// # Examples
///
/// ```
/// // Mock server returns: {"success":true, "result": {"id":"z1","name":"example.com"}}
/// // client.get("/zones", &[]).await.expect("ok") will yield the `result` object.
/// ```
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

/// Checks that a Cloudflare error envelope with an API error is converted into `Error::Api`.
///
/// Sets up a mock 400 response whose JSON envelope contains an API error message and
/// asserts that `CloudflareClient::get` returns `Error::Api` with the same message.
///
/// # Examples
///
/// ```rust
/// // Arrange: create client pointing at a mock server that returns the envelope:
/// // {"success":false,"errors":[{"code":1001,"message":"zone not found"}],"result":null}
/// let client = make_client(&server);
/// let err = client.get("/zones", &[]).await.unwrap_err();
/// assert!(matches!(err, Error::Api { ref message } if message == "zone not found"));
/// ```
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

/// Verifies that a 403 Cloudflare envelope is converted into an `Error::Forbidden` containing the server-provided message.
///
/// # Examples
///
/// ```
/// # use mockito::ServerGuard;
/// # use dnslib::error::Error;
/// # async fn run_example(mut server: ServerGuard) {
/// let _m = server
///     .mock("POST", "/zones")
///     .with_status(403)
///     .with_header("content-type", "application/json")
///     .with_body(r#"{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}],"messages":[],"result":null}"#)
///     .create_async()
///     .await;
///
/// let client = make_client(&server);
/// let err = client
///     .post("/zones", &serde_json::json!({"name": "example.com"}))
///     .await
///     .unwrap_err();
/// assert!(matches!(err, Error::Forbidden { ref message } if message == "Invalid access token"));
/// # }
/// ```
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
