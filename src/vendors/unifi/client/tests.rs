
use super::*;
use serde_json::json;

fn make_resp(status: u16, body: Value) -> reqwest::Response {
    http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(body.to_string())
        .map(reqwest::Response::from)
        .unwrap()
}

fn make_empty_resp(status: u16) -> reqwest::Response {
    http::Response::builder()
        .status(status)
        .body(String::new())
        .map(reqwest::Response::from)
        .unwrap()
}

#[tokio::test]
async fn success_returns_body() {
    let resp = make_resp(200, json!({ "id": "abc" }));
    let v = parse_json_response(resp).await.unwrap();
    assert_eq!(v["id"], "abc");
}

#[tokio::test]
async fn forbidden_maps_to_forbidden_error() {
    let resp = make_resp(
        403,
        json!({
            "statusCode": 403,
            "statusName": "Forbidden",
            "message": "Invalid API key"
        }),
    );
    let err = parse_json_response(resp).await.unwrap_err();
    assert!(matches!(err, Error::Forbidden { ref message } if message == "Invalid API key"));
}

#[tokio::test]
async fn client_error_maps_to_api_error() {
    let resp = make_resp(
        400,
        json!({
            "statusCode": 400,
            "statusName": "BadRequest",
            "message": "domain is required"
        }),
    );
    let err = parse_json_response(resp).await.unwrap_err();
    assert!(matches!(err, Error::Api { ref message } if message == "domain is required"));
}

#[tokio::test]
async fn empty_success_returns_null() {
    let resp = make_empty_resp(200);
    let v = parse_json_response(resp).await.unwrap();
    assert!(v.is_null());
}

#[tokio::test]
async fn empty_failure_returns_http_error() {
    let resp = make_empty_resp(502);
    let err = parse_json_response(resp).await.unwrap_err();
    assert!(matches!(err, Error::Http { status: 502, .. }));
}

#[tokio::test]
async fn delete_empty_success_returns_ok_null() {
    let resp = make_empty_resp(200);
    let v = parse_optional_json_response(resp).await.unwrap();
    assert!(v.is_null());
}

#[test]
fn unifi_error_message_prefers_message_over_status_name() {
    let v = json!({"message": "boom", "statusName": "Ouch"});
    assert_eq!(unifi_error_message(&v).as_deref(), Some("boom"));
}

#[test]
fn unifi_error_message_falls_back_to_status_name() {
    let v = json!({"statusName": "Ouch"});
    assert_eq!(unifi_error_message(&v).as_deref(), Some("Ouch"));
}
