use reqwest::{Response, multipart};
use serde_json::Value;

use crate::core::error::{Error, Result};
use crate::core::secret::ApiToken;
use crate::vendors::http::HttpClient;

#[derive(Clone, Debug)]
pub struct TechnitiumClient {
    http: HttpClient,
}

impl TechnitiumClient {
    pub fn new(base_url: String, token: ApiToken) -> Result<Self> {
        Ok(Self {
            http: HttpClient::new(base_url, token, true)?,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.http.base_url
    }

    /// GET with query params.
    pub async fn get(&self, path: &str, params: &[(&str, &str)]) -> Result<Value> {
        let req = self.http.get(path).query(params);
        let resp = self.http.send("GET", path, req).await?;
        parse_response(resp).await
    }

    /// POST with form-encoded body.
    pub async fn post(&self, path: &str, form: &[(&str, &str)]) -> Result<Value> {
        let req = self.http.post(path).form(form);
        let resp = self.http.send("POST", path, req).await?;
        parse_response(resp).await
    }

    /// GET that returns a plain-text body (e.g. zone file export).
    pub async fn get_text(&self, path: &str, params: &[(&str, &str)]) -> Result<String> {
        let req = self.http.get(path).query(params);
        let resp = self.http.send("GET", path, req).await?;
        let status = resp.status();
        if status.is_success() {
            return resp.text().await.map_err(Error::Network);
        }
        let message = resp
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|b| {
                b.get("errorMessage")
                    .and_then(|m| m.as_str())
                    .map(ToOwned::to_owned)
            })
            .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
        Err(Error::Api { message })
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
        let file_part = multipart::Part::bytes(file_bytes)
            .file_name(file_name)
            .mime_str("text/plain")
            .map_err(Error::Mime)?;
        let form = multipart::Form::new().part("zoneFile", file_part);
        let req = self.http.post(path).query(params).multipart(form);
        let resp = self.http.send("POST", path, req).await?;
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
