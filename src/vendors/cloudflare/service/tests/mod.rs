//! Tests for the Cloudflare DNS service implementation.

use super::*;
pub(crate) use serde_json::json;

mod behaviour;
mod mapping;

fn make_client() -> CloudflareClient {
    CloudflareClient::new(
        "https://api.cloudflare.com/client/v4".to_string(),
        crate::core::secret::ApiToken::new("test-token"),
    )
    .unwrap()
}
