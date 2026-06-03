//! Wire-level integration tests for `PiholeClient`.
//!
//! Pi-hole v6 uses session auth: each request first exchanges the password for
//! a session SID via `POST /api/auth`, then sends that SID as a bearer token.
//! These tests verify that two-step round-trip — behaviour the in-module unit
//! tests (which only cover `parse_response`) cannot reach.

#![cfg(feature = "pihole")]

use dnslib::error::Error;
use dnslib::secret::ApiToken;
use dnslib::vendors::pihole::client::PiholeClient;
use mockito::ServerGuard;
use rstest::{fixture, rstest};

#[fixture]
async fn server() -> ServerGuard {
    mockito::Server::new_async().await
}

/// Create a PiholeClient configured to use the mock server's URL with a fixed test API token.
///
/// The client is constructed with `ApiToken::new("hunter2")` and will panic if construction fails.
///
/// # Examples
///
/// ```no_run
/// # async fn run() {
/// let server = mockito::Server::new_async().await.unwrap();
/// let client = make_client(&server);
/// // use `client` to exercise requests against the mock server
/// # }
/// ```
fn make_client(server: &ServerGuard) -> PiholeClient {
    PiholeClient::new(server.url(), ApiToken::new("hunter2")).expect("client builds")
}

/// Verifies that the client authenticates with `/api/auth` and forwards the returned session SID
/// as a `Bearer` token on subsequent requests.
///
/// This test stands up an async mock server that returns a valid session SID from `/api/auth`,
/// then asserts that a following request (here `/api/config`) includes `Authorization: Bearer <sid>`
/// and that the response is parsed as JSON containing `config.dns`.
///
/// # Examples
///
/// ```
/// // The test verifies that after authenticating the client sends the session SID as a Bearer token:
/// # async fn example(server: mockito::ServerGuard) {
/// #   let mut server = server.await;
/// #   // mock setup omitted
/// let client = make_client(&server);
/// let _ = client.get("/api/config", &[]).await;
/// # }
/// ```
#[rstest]
#[tokio::test]
async fn get_authenticates_then_sends_sid_as_bearer(#[future] server: ServerGuard) {
    let mut server = server.await;

    let auth = server
        .mock("POST", "/api/auth")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"session":{"valid":true,"sid":"SID-XYZ"}}"#)
        .create_async()
        .await;

    let data = server
        .mock("GET", "/api/config")
        // The SID obtained from /api/auth must be presented as a bearer token.
        .match_header("authorization", "Bearer SID-XYZ")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"config":{"dns":{}}}"#)
        .create_async()
        .await;

    let client = make_client(&server);
    let value = client.get("/api/config", &[]).await.expect("ok");

    auth.assert_async().await;
    data.assert_async().await;
    assert!(value["config"]["dns"].is_object());
}

#[rstest]
#[tokio::test]
async fn auth_failure_surfaces_as_forbidden(#[future] server: ServerGuard) {
    let mut server = server.await;
    let auth = server
        .mock("POST", "/api/auth")
        .with_status(401)
        .with_header("content-type", "application/json")
        .with_body(r#"{"error":{"key":"unauthorized","message":"Invalid password"}}"#)
        .create_async()
        .await;

    let client = make_client(&server);
    let err = client.get("/api/config", &[]).await.unwrap_err();

    auth.assert_async().await;
    assert!(
        matches!(err, Error::Forbidden { ref message } if message == "Invalid password"),
        "got {err:?}"
    );
}

/// Verifies that an auth response that omits `session.sid` is treated as a parse error.
///
/// The test sets up a mock `POST /api/auth` response containing `"session":{"valid":false}`
/// without a `sid` field, constructs a `PiholeClient`, invokes `client.get("/api/config", &[])`,
/// and asserts the returned error is `Error::Parse`.
///
/// # Examples
///
/// ```rust
/// # use dnslib::error::Error;
/// # async fn _example(server: mockito::ServerGuard) {
/// // Arrange: mock auth response missing `session.sid`
/// // (test fixture setup omitted)
/// // Act: perform request and capture error
/// let err = /* client.get("/api/config", &[]).await.unwrap_err() */ unimplemented!();
/// // Assert: error is a parse error
/// assert!(matches!(err, Error::Parse { .. }));
/// # }
/// ```
#[rstest]
#[tokio::test]
async fn missing_sid_in_auth_response_is_parse_error(#[future] server: ServerGuard) {
    let mut server = server.await;
    let _auth = server
        .mock("POST", "/api/auth")
        .with_status(200)
        .with_header("content-type", "application/json")
        // No session.sid field.
        .with_body(r#"{"session":{"valid":false}}"#)
        .create_async()
        .await;

    let client = make_client(&server);
    let err = client.get("/api/config", &[]).await.unwrap_err();
    assert!(matches!(err, Error::Parse { .. }), "got {err:?}");
}
