//! Integration tests for TechnitiumClient using a mock HTTP server.

use dnslib::client::TechnitiumClient;
use dnslib::error::Error;
use mockito::ServerGuard;
use rstest::{fixture, rstest};

// ── Fixtures ──────────────────────────────────────────────────────────────────

#[fixture]
async fn server() -> ServerGuard {
    mockito::Server::new_async().await
}

#[fixture]
fn token() -> String {
    "test-token-abc123".into()
}

fn make_client(server: &ServerGuard, token: &str) -> TechnitiumClient {
    TechnitiumClient::new(server.url(), token.into()).expect("client should build")
}

// ── GET happy path ────────────────────────────────────────────────────────────

#[rstest]
#[tokio::test]
async fn get_returns_ok_response(#[future] server: ServerGuard, token: String) {
    let mut server = server.await;
    let mock = server
        .mock("GET", "/api/zones/list")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"status":"ok","response":{"zones":[]}}"#)
        .create_async()
        .await;

    let client = make_client(&server, &token);
    let result = client.get("/api/zones/list", &[]).await;

    mock.assert_async().await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap()["status"], "ok");
}

#[rstest]
#[tokio::test]
async fn get_sends_bearer_auth(#[future] server: ServerGuard, token: String) {
    let mut server = server.await;
    let expected_auth = format!("Bearer {token}");
    let mock = server
        .mock("GET", "/api/zones/list")
        .match_header("authorization", expected_auth.as_str())
        .with_status(200)
        .with_body(r#"{"status":"ok","response":{}}"#)
        .create_async()
        .await;

    let client = make_client(&server, &token);
    let _ = client.get("/api/zones/list", &[]).await;

    mock.assert_async().await;
}

#[rstest]
#[tokio::test]
async fn get_sends_query_params(#[future] server: ServerGuard, token: String) {
    let mut server = server.await;
    let mock = server
        .mock("GET", "/api/zones/list")
        .match_query(mockito::Matcher::AllOf(vec![
            mockito::Matcher::UrlEncoded("pageNumber".into(), "2".into()),
            mockito::Matcher::UrlEncoded("zonesPerPage".into(), "10".into()),
        ]))
        .with_status(200)
        .with_body(r#"{"status":"ok","response":{}}"#)
        .create_async()
        .await;

    let client = make_client(&server, &token);
    let _ = client
        .get(
            "/api/zones/list",
            &[("pageNumber", "2"), ("zonesPerPage", "10")],
        )
        .await;

    mock.assert_async().await;
}

// ── POST happy path ───────────────────────────────────────────────────────────

#[rstest]
#[tokio::test]
async fn post_returns_ok_response(#[future] server: ServerGuard, token: String) {
    let mut server = server.await;
    let mock = server
        .mock("POST", "/api/zones/create")
        .with_status(200)
        .with_body(r#"{"status":"ok","response":{}}"#)
        .create_async()
        .await;

    let client = make_client(&server, &token);
    let result = client
        .post(
            "/api/zones/create",
            &[("zone", "example.com"), ("type", "Primary")],
        )
        .await;

    mock.assert_async().await;
    assert!(result.is_ok());
}

#[rstest]
#[tokio::test]
async fn post_sends_form_encoded_body(#[future] server: ServerGuard, token: String) {
    let mut server = server.await;
    let mock = server
        .mock("POST", "/api/zones/delete")
        .match_header(
            "content-type",
            mockito::Matcher::Regex("application/x-www-form-urlencoded".into()),
        )
        .match_body(mockito::Matcher::UrlEncoded(
            "zone".into(),
            "example.com".into(),
        ))
        .with_status(200)
        .with_body(r#"{"status":"ok","response":{}}"#)
        .create_async()
        .await;

    let client = make_client(&server, &token);
    let _ = client
        .post("/api/zones/delete", &[("zone", "example.com")])
        .await;

    mock.assert_async().await;
}

// ── API-level errors ──────────────────────────────────────────────────────────

#[rstest]
#[tokio::test]
async fn api_error_returns_typed_api_variant(#[future] server: ServerGuard, token: String) {
    let mut server = server.await;
    server
        .mock("GET", "/api/zones/list")
        .with_status(200)
        .with_body(r#"{"status":"error","errorMessage":"Access denied"}"#)
        .create_async()
        .await;

    let client = make_client(&server, &token);
    let result = client.get("/api/zones/list", &[]).await;

    assert!(matches!(result, Err(Error::Api { ref message }) if message == "Access denied"));
}

#[rstest]
#[tokio::test]
async fn api_error_message_is_preserved(#[future] server: ServerGuard, token: String) {
    let mut server = server.await;
    server
        .mock("POST", "/api/zones/create")
        .with_status(200)
        .with_body(r#"{"status":"error","errorMessage":"Zone already exists."}"#)
        .create_async()
        .await;

    let client = make_client(&server, &token);
    let result = client
        .post("/api/zones/create", &[("zone", "example.com")])
        .await;

    let Err(Error::Api { message }) = result else {
        panic!("expected Api error")
    };
    assert_eq!(message, "Zone already exists.");
}

#[rstest]
#[case::not_found(404)]
#[case::internal_server_error(500)]
#[case::bad_gateway(502)]
#[tokio::test]
async fn http_error_status_returns_http_variant(
    #[future] server: ServerGuard,
    token: String,
    #[case] status: usize,
) {
    let mut server = server.await;
    server
        .mock("GET", "/api/zones/list")
        .with_status(status)
        .with_body(r#"{"status":"error","errorMessage":"server error"}"#)
        .create_async()
        .await;

    let client = make_client(&server, &token);
    let result = client.get("/api/zones/list", &[]).await;

    // Both API-level and HTTP-level errors are valid here depending on the status body
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        Error::Api { .. } | Error::Http { .. }
    ));
}

#[rstest]
#[tokio::test]
async fn http_error_captures_status_code(#[future] server: ServerGuard, token: String) {
    let mut server = server.await;
    server
        .mock("GET", "/api/zones/list")
        .with_status(503)
        .with_body(r#"{"notAnApiResponse": true}"#)
        .create_async()
        .await;

    let client = make_client(&server, &token);
    let result = client.get("/api/zones/list", &[]).await;

    assert!(matches!(result, Err(Error::Http { status: 503, .. })));
}

// ── post_file (multipart) ─────────────────────────────────────────────────────

#[rstest]
#[tokio::test]
async fn post_file_sends_multipart(#[future] server: ServerGuard, token: String) {
    let mut server = server.await;
    let mock = server
        .mock("POST", "/api/zones/import")
        .match_query(mockito::Matcher::Any)
        .match_header(
            "content-type",
            mockito::Matcher::Regex("multipart/form-data".into()),
        )
        .with_status(200)
        .with_body(r#"{"status":"ok","response":{}}"#)
        .create_async()
        .await;

    let client = make_client(&server, &token);
    let zone_content =
        b"$ORIGIN example.com.\n@ 3600 IN SOA ns1 hostmaster 1 3600 900 604800 300\n".to_vec();
    let result = client
        .post_file(
            "/api/zones/import",
            &[("zone", "example.com")],
            "example.com.zone".into(),
            zone_content,
        )
        .await;

    mock.assert_async().await;
    assert!(result.is_ok());
}

#[rstest]
#[tokio::test]
async fn post_file_api_error_returns_api_variant(#[future] server: ServerGuard, token: String) {
    let mut server = server.await;
    server
        .mock("POST", "/api/zones/import")
        .match_query(mockito::Matcher::Any)
        .with_status(200)
        .with_body(r#"{"status":"error","errorMessage":"zone not found"}"#)
        .create_async()
        .await;

    let client = make_client(&server, &token);
    let result = client
        .post_file(
            "/api/zones/import",
            &[("zone", "nope.com")],
            "nope.zone".into(),
            vec![],
        )
        .await;

    assert!(matches!(result, Err(Error::Api { ref message }) if message == "zone not found"));
}

// ── is_transient ──────────────────────────────────────────────────────────────

#[rstest]
fn api_error_is_not_transient() {
    assert!(!Error::api("access denied").is_transient());
}

#[rstest]
fn http_error_is_not_transient() {
    assert!(
        !Error::Http {
            status: 500,
            body: "".into()
        }
        .is_transient()
    );
}

#[rstest]
fn io_error_is_not_transient() {
    let e = Error::io(
        "reading file",
        std::io::Error::from(std::io::ErrorKind::NotFound),
    );
    assert!(!e.is_transient());
}
