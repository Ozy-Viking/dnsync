use reqwest::{Client, Response, multipart};
use serde_json::Value;

use crate::core::error::{Error, Result};
use crate::core::secret::ApiToken;

#[derive(Clone, Debug)]
pub struct TechnitiumClient {
    pub http: Client,
    pub base_url: String,
    token: ApiToken,
}

impl TechnitiumClient {
    pub fn new(base_url: String, token: ApiToken) -> Result<Self> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .no_proxy()
            .build()
            .map_err(Error::Network)?;
        Ok(Self {
            http,
            base_url,
            token,
        })
    }

    /// GET with query params.
    pub async fn get(&self, path: &str, params: &[(&str, &str)]) -> Result<Value> {
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

    /// POST with form-encoded body.
    pub async fn post(&self, path: &str, form: &[(&str, &str)]) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let span = tracing::debug_span!("http.post", path, http.status = tracing::field::Empty);
        let _enter = span.enter();
        tracing::debug!("sending POST");
        let resp = self
            .http
            .post(&url)
            .bearer_auth(self.token.expose_for_auth())
            .form(form)
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

    /// POST multipart/form-data with a zone file part.
    /// Query params carry the zone name and overwrite flags.
    pub async fn post_file(
        &self,
        path: &str,
        params: &[(&str, &str)],
        file_name: String,
        file_bytes: Vec<u8>,
    ) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let zone = params.iter().find(|(k, _)| *k == "zone").map(|(_, v)| *v).unwrap_or("");
        let span = tracing::debug_span!("http.post_file", path, zone, http.status = tracing::field::Empty);
        let _enter = span.enter();
        tracing::debug!("sending POST (multipart)");

        let file_part = multipart::Part::bytes(file_bytes)
            .file_name(file_name)
            .mime_str("text/plain")
            .map_err(Error::Mime)?;

        let form = multipart::Form::new().part("zoneFile", file_part);

        let resp = self
            .http
            .post(&url)
            .bearer_auth(self.token.expose_for_auth())
            .query(params)
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
}

async fn parse_response(resp: Response) -> Result<Value> {
    let status = resp.status();
    let body: Value = resp.json().await.map_err(|e| {
        // reqwest uses the same error type for network and decode errors;
        // if we got a response the failure is a decode error
        if e.is_decode() {
            Error::InvalidJson(e)
        } else {
            Error::Network(e)
        }
    })?;

    match body.get("status").and_then(|s| s.as_str()) {
        Some("ok") => Ok(body),
        Some("error") => {
            let message = body
                .get("errorMessage")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error")
                .to_string();
            Err(Error::Api { message })
        }
        _ if !status.is_success() => Err(Error::Http {
            status: status.as_u16(),
            body: body.to_string(),
        }),
        _ => Ok(body),
    }
}
