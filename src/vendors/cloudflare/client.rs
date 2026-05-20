use reqwest::{Client, Response, multipart};
use serde_json::Value;

use crate::core::error::{Error, Result};
use crate::core::secret::ApiToken;

/// Cloudflare DNS API client.
///
/// All Cloudflare responses use the envelope:
/// `{"result": {...}, "success": true, "errors": [], "messages": []}`
#[derive(Clone, Debug)]
pub struct CloudflareClient {
    pub http: Client,
    pub base_url: String,
    token: ApiToken,
}

impl CloudflareClient {
    pub fn new(base_url: String, token: ApiToken) -> Result<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(Error::Network)?;
        Ok(Self {
            http,
            base_url,
            token,
        })
    }

    pub async fn get(&self, path: &str, params: &[(&str, String)]) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let span = tracing::debug_span!("http.get", path, http.status = tracing::field::Empty);
        let _enter = span.enter();
        tracing::debug!("sending GET");
        let resp = self
            .http
            .get(&url)
            .bearer_auth(self.token.expose_for_auth())
            .query(params)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "GET failed");
                Error::Network(e)
            })?;
        span.record("http.status", resp.status().as_u16());
        tracing::debug!("received response");
        parse_response(resp).await
    }

    pub async fn post(&self, path: &str, body: &Value) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let span = tracing::debug_span!("http.post", path, http.status = tracing::field::Empty);
        let _enter = span.enter();
        tracing::debug!("sending POST");
        let resp = self
            .http
            .post(&url)
            .bearer_auth(self.token.expose_for_auth())
            .json(body)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "POST failed");
                Error::Network(e)
            })?;
        span.record("http.status", resp.status().as_u16());
        tracing::debug!("received response");
        parse_response(resp).await
    }

    pub async fn post_multipart(
        &self,
        path: &str,
        file_name: String,
        file_bytes: Vec<u8>,
    ) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let span = tracing::debug_span!(
            "http.post_multipart",
            path,
            http.status = tracing::field::Empty
        );
        let _enter = span.enter();
        tracing::debug!("sending POST (multipart)");

        let file_part = multipart::Part::bytes(file_bytes)
            .file_name(file_name)
            .mime_str("text/plain")
            .map_err(Error::Mime)?;

        let form = multipart::Form::new().part("file", file_part);

        let resp = self
            .http
            .post(&url)
            .bearer_auth(self.token.expose_for_auth())
            .multipart(form)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "POST (multipart) failed");
                Error::Network(e)
            })?;
        span.record("http.status", resp.status().as_u16());
        tracing::debug!("received response");
        parse_response(resp).await
    }

    pub async fn get_text(&self, path: &str, params: &[(&str, String)]) -> Result<String> {
        let url = format!("{}{}", self.base_url, path);
        let span = tracing::debug_span!("http.get_text", path, http.status = tracing::field::Empty);
        let _enter = span.enter();
        tracing::debug!("sending GET (text)");

        let resp = self
            .http
            .get(&url)
            .bearer_auth(self.token.expose_for_auth())
            .query(params)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "GET (text) failed");
                Error::Network(e)
            })?;
        span.record("http.status", resp.status().as_u16());
        tracing::debug!("received response");
        parse_text_response(resp).await
    }

    pub async fn delete(&self, path: &str) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let span = tracing::debug_span!("http.delete", path, http.status = tracing::field::Empty);
        let _enter = span.enter();
        tracing::debug!("sending DELETE");
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(self.token.expose_for_auth())
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "DELETE failed");
                Error::Network(e)
            })?;
        span.record("http.status", resp.status().as_u16());
        tracing::debug!("received response");
        parse_response(resp).await
    }
}

async fn parse_text_response(resp: Response) -> Result<String> {
    let status = resp.status();
    if status.is_success() {
        return resp.text().await.map_err(Error::Network);
    }
    let text = resp.text().await.unwrap_or_default();
    let message = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|body| {
            body.get("errors")
                .and_then(|e| e.as_array())
                .and_then(|a| a.first())
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .map(ToOwned::to_owned)
        })
        .unwrap_or(text);
    if status.as_u16() == 403 {
        Err(Error::forbidden(message))
    } else {
        Err(Error::Api { message })
    }
}

async fn parse_response(resp: Response) -> Result<Value> {
    let status = resp.status();
    let body: Value = resp.json().await.map_err(|e| {
        if e.is_decode() {
            Error::InvalidJson(e)
        } else {
            Error::Network(e)
        }
    })?;

    let success = body
        .get("success")
        .and_then(|s| s.as_bool())
        .unwrap_or(false);

    if success {
        return Ok(body.get("result").cloned().unwrap_or(Value::Null));
    }

    let message = body
        .get("errors")
        .and_then(|e| e.as_array())
        .and_then(|a| a.first())
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or("unknown error")
        .to_string();

    if status.as_u16() == 403 {
        return Err(Error::forbidden(message));
    }

    Err(Error::Api { message })
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
    async fn success_envelope_returns_result() {
        let resp = make_resp(
            200,
            json!({
                "result": { "id": "zone123", "name": "example.com" },
                "success": true,
                "errors": [],
                "messages": []
            }),
        );
        let val = parse_response(resp).await.unwrap();
        assert_eq!(val["id"], "zone123");
        assert_eq!(val["name"], "example.com");
    }

    #[tokio::test]
    async fn success_with_null_result_returns_null() {
        let resp = make_resp(
            200,
            json!({ "result": null, "success": true, "errors": [], "messages": [] }),
        );
        let val = parse_response(resp).await.unwrap();
        assert!(val.is_null());
    }

    #[tokio::test]
    async fn forbidden_returns_forbidden_error() {
        let resp = make_resp(
            403,
            json!({
                "result": null,
                "success": false,
                "errors": [{ "code": 9109, "message": "Invalid access token" }],
                "messages": []
            }),
        );
        let err = parse_response(resp).await.unwrap_err();
        assert!(
            matches!(err, Error::Forbidden { ref message } if message == "Invalid access token")
        );
    }

    #[tokio::test]
    async fn api_error_returns_first_error_message() {
        let resp = make_resp(
            400,
            json!({
                "result": null,
                "success": false,
                "errors": [{ "code": 1001, "message": "zone not found" }],
                "messages": []
            }),
        );
        let err = parse_response(resp).await.unwrap_err();
        assert!(matches!(err, Error::Api { ref message } if message == "zone not found"));
    }

    #[tokio::test]
    async fn empty_errors_array_uses_unknown_error() {
        let resp = make_resp(
            500,
            json!({ "result": null, "success": false, "errors": [], "messages": [] }),
        );
        let err = parse_response(resp).await.unwrap_err();
        assert!(matches!(err, Error::Api { ref message } if message == "unknown error"));
    }
}
