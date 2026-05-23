//! Shared HTTP scaffolding for vendor API clients.
//!
//! Holds the `reqwest::Client`, base URL, and bearer token; provides the
//! per-request tracing/auth/error-mapping boilerplate. Vendor clients embed an
//! [`HttpClient`], build their own request bodies/queries, then call
//! [`HttpClient::send`] to dispatch and apply the standard instrumentation.
//! Envelope parsing stays in the vendor module since each API's response shape
//! differs.

use std::time::Duration;

use reqwest::{Client, RequestBuilder, Response};

use crate::core::error::{Error, Result};
use crate::core::secret::ApiToken;

#[derive(Clone, Debug)]
pub struct HttpClient {
    http: Client,
    pub base_url: String,
    token: ApiToken,
}

impl HttpClient {
    /// Build a new client. `no_proxy` matches Technitium's existing behaviour
    /// — it disables proxy detection so requests to LAN-hosted DNS servers
    /// don't get routed through an HTTP_PROXY env var.
    pub fn new(base_url: String, token: ApiToken, no_proxy: bool) -> Result<Self> {
        let mut builder = Client::builder().timeout(Duration::from_secs(30));
        if no_proxy {
            builder = builder.no_proxy();
        }
        let http = builder.build().map_err(Error::Network)?;
        Ok(Self {
            http,
            base_url,
            token,
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    pub fn get(&self, path: &str) -> RequestBuilder {
        self.http.get(self.url(path))
    }

    pub fn post(&self, path: &str) -> RequestBuilder {
        self.http.post(self.url(path))
    }

    pub fn delete(&self, path: &str) -> RequestBuilder {
        self.http.delete(self.url(path))
    }

    /// Attach bearer auth, dispatch the request inside an `http.{method}` tracing
    /// span, map transport errors to `Error::Network`, and record the response
    /// status on the span. Vendor envelope parsing is the caller's job.
    pub async fn send(
        &self,
        method: &'static str,
        path: &str,
        builder: RequestBuilder,
    ) -> Result<Response> {
        let span =
            tracing::debug_span!("http.request", method, path, http.status = tracing::field::Empty);
        let _enter = span.enter();
        tracing::debug!("sending request");
        let resp = builder
            .bearer_auth(self.token.expose_for_auth())
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "request failed");
                Error::Network(e)
            })?;
        span.record("http.status", resp.status().as_u16());
        tracing::debug!("received response");
        Ok(resp)
    }
}
