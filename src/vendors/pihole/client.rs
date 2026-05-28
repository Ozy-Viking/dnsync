use reqwest::{Client, Response};
use serde_json::Value;

use crate::core::error::{Error, Result};
use crate::core::secret::ApiToken;

/// Pi-hole v6 REST API client.
///
/// Pi-hole uses session-based authentication: the password is exchanged for a
/// session SID via `POST /api/auth`, and that SID is sent as a Bearer token on
/// every subsequent request.  Because sessions expire (default 1800 s), each
/// public HTTP method obtains a fresh SID so callers don't need to manage state.
#[derive(Clone, Debug)]
pub struct PiholeClient {
    pub http: Client,
    pub base_url: String,
    password: ApiToken,
}

impl PiholeClient {
    pub fn new(base_url: String, password: ApiToken) -> Result<Self> {
        let base_url = base_url.trim_end_matches('/').to_string();
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(Error::Network)?;
        Ok(Self {
            http,
            base_url,
            password,
        })
    }

    /// Authenticate and return the session SID.
    async fn session_id(&self) -> Result<String> {
        let url = format!("{}/api/auth", self.base_url);
        let body = serde_json::json!({ "password": self.password.expose_for_auth() });
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "Pi-hole authentication request failed");
                Error::Network(e)
            })?;
        let status = resp.status();
        let data: Value = resp.json().await.map_err(|e| {
            if e.is_decode() {
                Error::InvalidJson(e)
            } else {
                Error::Network(e)
            }
        })?;
        if !status.is_success() {
            let message = data
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("authentication failed")
                .to_string();
            return if status.as_u16() == 401 || status.as_u16() == 403 {
                Err(Error::forbidden(message))
            } else {
                Err(Error::Api { message })
            };
        }
        data.get("session")
            .and_then(|s| s.get("sid"))
            .and_then(|s| s.as_str())
            .map(ToOwned::to_owned)
            .ok_or_else(|| Error::parse("Pi-hole auth response missing session SID"))
    }

    pub async fn get(&self, path: &str, params: &[(&str, String)]) -> Result<Value> {
        let sid = self.session_id().await?;
        let url = format!("{}{}", self.base_url, path);
        let span = tracing::debug_span!("http.get", path, http.status = tracing::field::Empty);
        let _enter = span.enter();
        tracing::debug!("sending GET");
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&sid)
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
        let sid = self.session_id().await?;
        let url = format!("{}{}", self.base_url, path);
        let span = tracing::debug_span!("http.post", path, http.status = tracing::field::Empty);
        let _enter = span.enter();
        tracing::debug!("sending POST");
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&sid)
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

    pub async fn delete(&self, path: &str) -> Result<Value> {
        let sid = self.session_id().await?;
        let url = format!("{}{}", self.base_url, path);
        let span = tracing::debug_span!("http.delete", path, http.status = tracing::field::Empty);
        let _enter = span.enter();
        tracing::debug!("sending DELETE");
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&sid)
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

    pub async fn delete_with_body(&self, path: &str, body: &Value) -> Result<Value> {
        let sid = self.session_id().await?;
        let url = format!("{}{}", self.base_url, path);
        let span = tracing::debug_span!("http.delete", path, http.status = tracing::field::Empty);
        let _enter = span.enter();
        tracing::debug!("sending DELETE");
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&sid)
            .json(body)
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

async fn parse_response(resp: Response) -> Result<Value> {
    let status = resp.status();

    // 204 No Content (successful DELETE operations return no body)
    if status == reqwest::StatusCode::NO_CONTENT {
        return Ok(serde_json::json!({}));
    }

    let body: Value = resp.json().await.map_err(|e| {
        if e.is_decode() {
            Error::InvalidJson(e)
        } else {
            Error::Network(e)
        }
    })?;

    if status.is_success() {
        return Ok(body);
    }

    let message = body
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or("unknown error")
        .to_string();

    if status.as_u16() == 401 || status.as_u16() == 403 {
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

    fn make_client() -> PiholeClient {
        PiholeClient::new(
            "http://pi.hole".to_string(),
            crate::core::secret::ApiToken::new("test-password"),
        )
        .unwrap()
    }

    #[test]
    fn client_builds_successfully() {
        let client = make_client();
        assert_eq!(client.base_url, "http://pi.hole");
    }

    #[test]
    fn trailing_slash_stripped_from_base_url() {
        let client = PiholeClient::new(
            "http://pi.hole/".to_string(),
            crate::core::secret::ApiToken::new("pass"),
        )
        .unwrap();
        assert_eq!(client.base_url, "http://pi.hole");
    }

    #[tokio::test]
    async fn no_content_response_returns_empty_object() {
        let resp = http::Response::builder()
            .status(204)
            .body("".to_string())
            .map(reqwest::Response::from)
            .unwrap();
        let val = parse_response(resp).await.unwrap();
        assert!(val.is_object());
    }

    #[tokio::test]
    async fn success_response_returns_body() {
        let resp = make_resp(200, json!({"dns": [{"ip": "1.2.3.4", "host": "myhost.local"}]}));
        let val = parse_response(resp).await.unwrap();
        assert_eq!(val["dns"][0]["ip"], "1.2.3.4");
    }

    #[tokio::test]
    async fn forbidden_response_returns_forbidden_error() {
        let resp = make_resp(
            403,
            json!({"error": {"key": "unauthorized", "message": "Unauthorized", "hint": null}}),
        );
        let err = parse_response(resp).await.unwrap_err();
        assert!(matches!(err, Error::Forbidden { ref message } if message == "Unauthorized"));
    }

    #[tokio::test]
    async fn unauthorized_response_returns_forbidden_error() {
        let resp = make_resp(
            401,
            json!({"error": {"key": "unauthorized", "message": "Invalid password", "hint": null}}),
        );
        let err = parse_response(resp).await.unwrap_err();
        assert!(matches!(err, Error::Forbidden { ref message } if message == "Invalid password"));
    }

    #[tokio::test]
    async fn api_error_returns_message() {
        let resp = make_resp(
            400,
            json!({"error": {"key": "bad_request", "message": "Invalid domain", "hint": null}}),
        );
        let err = parse_response(resp).await.unwrap_err();
        assert!(matches!(err, Error::Api { ref message } if message == "Invalid domain"));
    }

    #[tokio::test]
    async fn missing_error_key_uses_unknown_error() {
        let resp = make_resp(500, json!({}));
        let err = parse_response(resp).await.unwrap_err();
        assert!(matches!(err, Error::Api { ref message } if message == "unknown error"));
    }
}
