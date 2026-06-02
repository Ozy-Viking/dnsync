//! Wire-level integration tests for `PangolinClient`. Exercises the real
//! request path: bearer auth and the Pangolin response envelope
//! (`{"success":..,"data":..,"message":..,"status":..}`).

#![cfg(feature = "pangolin")]

use dnslib::error::Error;
use dnslib::secret::ApiToken;
use dnslib::vendors::pangolin::client::PangolinClient;
use mockito::ServerGuard;
use rstest::{fixture, rstest};

#[fixture]
async fn server() -> ServerGuard {
    mockito::Server::new_async().await
}

fn make_client(server: &ServerGuard) -> PangolinClient {
    PangolinClient::new(server.url(), ApiToken::new("pg-token"), "org-1".into())
        .expect("client builds")
}

#[rstest]
#[tokio::test]
async fn get_returns_inner_data(#[future] server: ServerGuard) {
    let mut server = server.await;
    let mock = server
        .mock("GET", "/resources")
        .match_header("authorization", "Bearer pg-token")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"success":true,"error":false,"message":"ok","status":200,"data":{"resources":[{"id":7}]}}"#)
        .create_async()
        .await;

    let client = make_client(&server);
    let value = client.get("/resources", &[]).await.expect("ok");

    mock.assert_async().await;
    // The envelope is stripped, leaving the inner `data`.
    assert_eq!(value["resources"][0]["id"], 7);
    assert_eq!(client.org_id, "org-1");
}

#[rstest]
#[tokio::test]
async fn unsuccessful_envelope_maps_to_api_error(#[future] server: ServerGuard) {
    let mut server = server.await;
    let _mock = server
        .mock("GET", "/resources")
        .with_status(400)
        .with_header("content-type", "application/json")
        .with_body(
            r#"{"success":false,"error":true,"message":"bad request","status":400,"data":null}"#,
        )
        .create_async()
        .await;

    let client = make_client(&server);
    let err = client.get("/resources", &[]).await.unwrap_err();
    assert!(
        matches!(err, Error::Api { ref message } if message == "bad request"),
        "got {err:?}"
    );
}

#[rstest]
#[tokio::test]
async fn forbidden_envelope_maps_to_forbidden_error(#[future] server: ServerGuard) {
    let mut server = server.await;
    let _mock = server
        .mock("GET", "/resources")
        .with_status(403)
        .with_header("content-type", "application/json")
        .with_body(r#"{"success":false,"error":true,"message":"Key does not have root access","status":403,"data":null}"#)
        .create_async()
        .await;

    let client = make_client(&server);
    let err = client.get("/resources", &[]).await.unwrap_err();
    assert!(
        matches!(err, Error::Forbidden { ref message } if message == "Key does not have root access"),
        "got {err:?}"
    );
}
