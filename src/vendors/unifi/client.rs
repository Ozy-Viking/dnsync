//! UniFi Network Integration API client (DNS policies only).
//!
//! UniFi authenticates with an `X-API-KEY` header rather than HTTP bearer
//! auth, so this client builds its own `reqwest::Client` rather than reusing
//! the shared `vendors::http::HttpClient`.
//!
//! All paths are appended to `base_url`. The expected effective URL is
//! `<base_url>/sites/{siteId}/dns/policies[...]`, where `base_url` typically
//! ends in `/proxy/network/integration/v1` on a local controller.

use std::time::Duration;

use reqwest::{Client, RequestBuilder, Response};
use serde_json::Value;
use tokio::sync::OnceCell;
use tracing::Instrument;

use crate::core::error::{Error, Result};
use crate::core::secret::ApiToken;

use super::responses::{
    UnifiDnsPolicy, UnifiDnsPolicyPage, UnifiSite, match_site, parse_page, parse_site_page,
};

/// Maximum page size accepted by the UniFi DNS policy list endpoint.
pub const MAX_PAGE_LIMIT: u32 = 200;

/// Default page size when the caller does not specify one.
pub const DEFAULT_PAGE_LIMIT: u32 = 200;

/// UniFi DNS-policy client.
///
/// `site` holds the user-configured value — typically the human-readable site
/// name (e.g. `"Default"`), but a UUID is also accepted. The first DNS call
/// resolves that label to the controller's actual site UUID via
/// `GET /v1/sites` and caches it for the lifetime of the client.
#[derive(Clone, Debug)]
pub struct UnifiClient {
    http: Client,
    base_url: String,
    token: ApiToken,
    site: String,
    resolved_site_id: std::sync::Arc<OnceCell<String>>,
}

impl UnifiClient {
    /// Build a new client. Uses a 30-second timeout to match the rest of the
    /// vendor clients in this crate.
    pub fn new(base_url: String, token: ApiToken, site: String) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(Error::Network)?;
        Ok(Self {
            http,
            base_url,
            token,
            site,
            resolved_site_id: std::sync::Arc::new(OnceCell::new()),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The configured site identifier as supplied via config or env vars.
    /// This is what the user typed and may be either a name or a UUID.
    pub fn site(&self) -> &str {
        &self.site
    }

    /// Test-only helper for verifying credential plumbing without forcing the
    /// production code to expose the token via `Debug`.
    #[cfg(test)]
    pub fn token_for_test(&self) -> &str {
        self.token.expose_for_auth()
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn policies_path(&self, site_id: &str) -> String {
        format!("/sites/{site_id}/dns/policies")
    }

    fn policy_path(&self, site_id: &str, policy_id: &str) -> String {
        format!("/sites/{site_id}/dns/policies/{policy_id}")
    }

    /// Resolve the configured `site` (name or UUID) to the canonical UniFi
    /// site UUID.
    ///
    /// On first call this performs `GET /v1/sites` and matches the
    /// configured value against each site's `id`, `name`, and
    /// `internalReference` (case-insensitively). The resolved UUID is cached
    /// for the lifetime of the client so subsequent DNS calls don't pay the
    /// site-list cost.
    ///
    /// If no site matches the configured value, returns `Error::Api` whose
    /// message lists every valid human-readable site name so the user can
    /// fix their config without leaving the CLI.
    pub async fn resolve_site_id(&self) -> Result<&str> {
        let cached = self
            .resolved_site_id
            .get_or_try_init(|| async {
                let sites = self.list_all_sites().await?;
                match match_site(&sites, &self.site) {
                    Some(site) => Ok(site.id.clone()),
                    None => {
                        let available = if sites.is_empty() {
                            "<no sites visible to this API key>".to_string()
                        } else {
                            sites
                                .iter()
                                .map(|s| s.display_name())
                                .collect::<Vec<_>>()
                                .join(", ")
                        };
                        Err(Error::Api {
                            message: format!(
                                "UniFi site '{}' not found on this controller; available sites: [{}]",
                                self.site, available
                            ),
                        })
                    }
                }
            })
            .await?;
        Ok(cached.as_str())
    }

    fn auth(&self, req: RequestBuilder) -> RequestBuilder {
        req.header("X-API-KEY", self.token.expose_for_auth())
            .header("Accept", "application/json")
    }

    async fn send(
        &self,
        method: &'static str,
        path: &str,
        builder: RequestBuilder,
    ) -> Result<Response> {
        let span = tracing::debug_span!(
            "http.request",
            method,
            path,
            http.status = tracing::field::Empty
        );
        async {
            tracing::debug!("sending request");
            let resp = self.auth(builder).send().await.map_err(|e| {
                tracing::warn!(error = %e, "request failed");
                Error::Network(e)
            })?;
            tracing::Span::current().record("http.status", resp.status().as_u16());
            tracing::debug!("received response");
            Ok(resp)
        }
        .instrument(span)
        .await
    }

    // ── Raw HTTP verbs ──────────────────────────────────────────────────────

    async fn get(&self, path: &str, params: &[(&str, String)]) -> Result<Value> {
        let req = self.http.get(self.url(path)).query(params);
        let resp = self.send("GET", path, req).await?;
        parse_json_response(resp).await
    }

    async fn post(&self, path: &str, body: &Value) -> Result<Value> {
        let req = self.http.post(self.url(path)).json(body);
        let resp = self.send("POST", path, req).await?;
        parse_json_response(resp).await
    }

    async fn put(&self, path: &str, body: &Value) -> Result<Value> {
        let req = self.http.put(self.url(path)).json(body);
        let resp = self.send("PUT", path, req).await?;
        parse_json_response(resp).await
    }

    async fn delete(&self, path: &str) -> Result<Value> {
        let req = self.http.delete(self.url(path));
        let resp = self.send("DELETE", path, req).await?;
        parse_optional_json_response(resp).await
    }

    // ── Site discovery ──────────────────────────────────────────────────────

    /// `GET /v1/sites` — single page of sites accessible to this API key.
    pub async fn list_sites_page(
        &self,
        offset: u32,
        limit: u32,
    ) -> Result<super::responses::UnifiSitePage> {
        let limit = limit.min(MAX_PAGE_LIMIT);
        let params: Vec<(&str, String)> =
            vec![("offset", offset.to_string()), ("limit", limit.to_string())];
        let value = self.get("/sites", &params).await?;
        parse_site_page(value)
            .map_err(|e| Error::parse(format!("decoding UniFi site page: {e}")))
    }

    /// Fetch every site by paginating until exhausted.
    ///
    /// Same termination logic as `list_all_dns_policies`: stops on empty page,
    /// known `totalCount`, or short page; capped at 1000 pages.
    pub async fn list_all_sites(&self) -> Result<Vec<UnifiSite>> {
        let mut out: Vec<UnifiSite> = Vec::new();
        let mut offset = 0u32;
        let mut pages = 0u32;
        loop {
            let page = self.list_sites_page(offset, DEFAULT_PAGE_LIMIT).await?;
            let returned = page.data.len() as u32;
            let total = page.total();
            out.extend(page.data);
            offset += returned.max(1);
            pages += 1;
            if returned == 0 {
                break;
            }
            if let Some(total) = total {
                if out.len() as u32 >= total {
                    break;
                }
            } else if returned < DEFAULT_PAGE_LIMIT {
                break;
            }
            if pages >= 1000 {
                return Err(Error::parse(
                    "UniFi site pagination exceeded 1000 pages without terminating",
                ));
            }
        }
        Ok(out)
    }

    // ── DNS-policy endpoints ────────────────────────────────────────────────

    /// `GET /sites/{siteId}/dns/policies` — single page.
    ///
    /// Caller controls pagination through `offset` and `limit`. `limit` is
    /// clamped to the documented maximum of 200.
    pub async fn list_dns_policies_page(
        &self,
        offset: u32,
        limit: u32,
        filter: Option<&str>,
    ) -> Result<UnifiDnsPolicyPage> {
        let limit = limit.min(MAX_PAGE_LIMIT);
        let mut params: Vec<(&str, String)> =
            vec![("offset", offset.to_string()), ("limit", limit.to_string())];
        if let Some(f) = filter {
            params.push(("filter", f.to_string()));
        }
        let site_id = self.resolve_site_id().await?.to_string();
        let path = self.policies_path(&site_id);
        let value = self.get(&path, &params).await?;
        parse_page(value).map_err(|e| Error::parse(format!("decoding UniFi DNS policy page: {e}")))
    }

    /// Fetch every DNS policy by paginating until exhausted.
    ///
    /// Termination: stops when an empty page is returned, or when `totalCount`
    /// (if present) has been reached. Hard cap of 1000 pages guards against
    /// pathological controller responses.
    pub async fn list_all_dns_policies(&self, filter: Option<&str>) -> Result<Vec<UnifiDnsPolicy>> {
        let mut out: Vec<UnifiDnsPolicy> = Vec::new();
        let mut offset = 0u32;
        let mut pages = 0u32;
        loop {
            let page = self
                .list_dns_policies_page(offset, DEFAULT_PAGE_LIMIT, filter)
                .await?;
            let returned = page.data.len() as u32;
            let total = page.total();
            out.extend(page.data);
            offset += returned.max(1); // ensure progress even if controller returns count=0
            pages += 1;

            // Stop conditions: empty page, reached known total, or page cap.
            if returned == 0 {
                break;
            }
            if let Some(total) = total {
                if out.len() as u32 >= total {
                    break;
                }
            } else if returned < DEFAULT_PAGE_LIMIT {
                // No totalCount header — short page means we're done.
                break;
            }
            if pages >= 1000 {
                return Err(Error::parse(
                    "UniFi DNS policy pagination exceeded 1000 pages without terminating",
                ));
            }
        }
        Ok(out)
    }

    /// `POST /sites/{siteId}/dns/policies`
    pub async fn create_dns_policy(&self, body: &Value) -> Result<UnifiDnsPolicy> {
        let site_id = self.resolve_site_id().await?.to_string();
        let path = self.policies_path(&site_id);
        let value = self.post(&path, body).await?;
        serde_json::from_value(value)
            .map_err(|e| Error::parse(format!("decoding UniFi create DNS policy response: {e}")))
    }

    /// `GET /sites/{siteId}/dns/policies/{dnsPolicyId}`
    pub async fn get_dns_policy(&self, policy_id: &str) -> Result<UnifiDnsPolicy> {
        let site_id = self.resolve_site_id().await?.to_string();
        let path = self.policy_path(&site_id, policy_id);
        let value = self.get(&path, &[]).await?;
        serde_json::from_value(value)
            .map_err(|e| Error::parse(format!("decoding UniFi get DNS policy response: {e}")))
    }

    /// `PUT /sites/{siteId}/dns/policies/{dnsPolicyId}`
    ///
    /// UniFi requires the full create/update payload — partial updates are
    /// not supported. Caller is responsible for sending all fields.
    pub async fn update_dns_policy(&self, policy_id: &str, body: &Value) -> Result<UnifiDnsPolicy> {
        let site_id = self.resolve_site_id().await?.to_string();
        let path = self.policy_path(&site_id, policy_id);
        let value = self.put(&path, body).await?;
        serde_json::from_value(value)
            .map_err(|e| Error::parse(format!("decoding UniFi update DNS policy response: {e}")))
    }

    /// `DELETE /sites/{siteId}/dns/policies/{dnsPolicyId}`
    pub async fn delete_dns_policy(&self, policy_id: &str) -> Result<()> {
        let site_id = self.resolve_site_id().await?.to_string();
        let path = self.policy_path(&site_id, policy_id);
        self.delete(&path).await?;
        Ok(())
    }
}

/// Parse a UniFi JSON response into a `Value`.
///
/// UniFi error responses follow `{"statusCode": 4xx, "statusName": "...",
/// "message": "..."}` and may also include a `details` array. Non-2xx
/// responses are mapped to the standard dnsync error variants.
async fn parse_json_response(resp: Response) -> Result<Value> {
    let status = resp.status();
    let bytes = resp.bytes().await.map_err(Error::Network)?;

    if bytes.is_empty() {
        if status.is_success() {
            return Ok(Value::Null);
        }
        return Err(Error::Http {
            status: status.as_u16(),
            body: String::new(),
        });
    }

    let value: Value = serde_json::from_slice(&bytes).map_err(|e| {
        // Use a faux parse error rather than InvalidJson(reqwest::Error)
        // because we already consumed the response bytes.
        let _ = e;
        Error::Parse {
            context: format!(
                "UniFi response body is not valid JSON (status {}): {}",
                status.as_u16(),
                String::from_utf8_lossy(&bytes)
                    .chars()
                    .take(200)
                    .collect::<String>(),
            ),
        }
    })?;

    if status.is_success() {
        return Ok(value);
    }

    let message = unifi_error_message(&value).unwrap_or_else(|| value.to_string());

    if status.as_u16() == 403 {
        return Err(Error::forbidden(message));
    }
    if status.is_client_error() || status.is_server_error() {
        // 4xx/5xx with an error payload — surface as a vendor API error.
        return Err(Error::Api { message });
    }

    Err(Error::Http {
        status: status.as_u16(),
        body: value.to_string(),
    })
}

/// Like `parse_json_response`, but treats an empty body as success — DELETE
/// often returns 200 OK with no payload.
async fn parse_optional_json_response(resp: Response) -> Result<Value> {
    let status = resp.status();
    if status.is_success() {
        let bytes = resp.bytes().await.map_err(Error::Network)?;
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        return serde_json::from_slice::<Value>(&bytes).map_err(|_| Error::Parse {
            context: format!(
                "UniFi DELETE response was not valid JSON (status {})",
                status.as_u16()
            ),
        });
    }
    parse_json_response(resp).await
}

/// Pull a human-readable error string out of a UniFi error envelope.
fn unifi_error_message(value: &Value) -> Option<String> {
    if let Some(msg) = value.get("message").and_then(|m| m.as_str()) {
        return Some(msg.to_string());
    }
    if let Some(msg) = value.get("statusName").and_then(|m| m.as_str()) {
        return Some(msg.to_string());
    }
    None
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
}
