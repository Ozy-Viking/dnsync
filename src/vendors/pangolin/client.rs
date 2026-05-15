use reqwest::{Client, Response};
use serde_json::Value;

use crate::core::error::{Error, Result};

/// Pangolin API client.
///
/// All Pangolin responses use the envelope:
/// `{"data": {...}, "success": true, "error": false, "message": "...", "status": 200}`
#[derive(Clone)]
pub struct PangolinClient {
    pub http: Client,
    pub base_url: String,
    pub token: String,
    pub org_id: String,
}

impl PangolinClient {
    pub fn new(base_url: String, token: String, org_id: String) -> Result<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(Error::Network)?;
        Ok(Self {
            http,
            base_url,
            token,
            org_id,
        })
    }

    /// GET the given path (relative to base_url) with query parameters.
    /// Strips the Pangolin envelope and returns the inner `data` value.
    pub async fn get(&self, path: &str, params: &[(&str, String)]) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .query(params)
            .send()
            .await
            .map_err(Error::Network)?;
        parse_response(resp).await
    }
}

async fn parse_response(resp: Response) -> Result<Value> {
    let http_status = resp.status();

    // Always attempt JSON parsing first — Pangolin returns structured errors even for
    // 4xx/5xx responses (e.g. 403 "Key does not have root access").
    let body: Value = resp.json().await.map_err(|e| {
        if e.is_decode() {
            Error::InvalidJson(e)
        } else {
            Error::Network(e)
        }
    })?;

    let success = body.get("success").and_then(|s| s.as_bool()).unwrap_or(false);
    let api_status = body.get("status").and_then(|s| s.as_u64()).unwrap_or(0);

    if success {
        return Ok(body.get("data").cloned().unwrap_or(Value::Null));
    }

    // Extract the human-readable message from the envelope.
    let message = body
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown error")
        .to_string();

    // 403 — insufficient API key permissions.
    if http_status.as_u16() == 403 || api_status == 403 {
        return Err(Error::forbidden(message));
    }

    // Other API-level errors (success: false with a message).
    if body.get("error").and_then(|e| e.as_bool()).unwrap_or(false)
        || !http_status.is_success()
    {
        return Err(Error::Api { message });
    }

    Err(Error::Http {
        status: http_status.as_u16(),
        body: body.to_string(),
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
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

    #[tokio::test]
    async fn success_envelope_returns_data() {
        let resp = make_resp(200, json!({
            "data": { "orgs": [] },
            "success": true,
            "error": false,
            "message": "ok",
            "status": 200
        }));
        let val = parse_response(resp).await.unwrap();
        assert_eq!(val, json!({ "orgs": [] }));
    }

    #[tokio::test]
    async fn forbidden_envelope_returns_forbidden_error() {
        let resp = make_resp(403, json!({
            "data": null,
            "success": false,
            "error": true,
            "message": "Key does not have root access",
            "status": 403,
            "stack": null
        }));
        let err = parse_response(resp).await.unwrap_err();
        assert!(matches!(err, Error::Forbidden { ref message } if message == "Key does not have root access"));
    }

    #[tokio::test]
    async fn api_error_envelope_returns_api_error() {
        let resp = make_resp(400, json!({
            "data": null,
            "success": false,
            "error": true,
            "message": "zone not found",
            "status": 400,
            "stack": null
        }));
        let err = parse_response(resp).await.unwrap_err();
        assert!(matches!(err, Error::Api { ref message } if message == "zone not found"));
    }
}
