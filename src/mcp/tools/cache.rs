use rmcp::{ErrorData as McpError, model::*};

use crate::{
    control_plane::policy::Policy,
    core::dns::cache,
    core::dns::service::DnsService,
    mcp::{helpers::run_json, params::DomainParams},
};

pub async fn handle_list_cache<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DomainParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_list_cache",
        policy.check_read(),
        cache::list_cache(client, &p.domain),
    )
    .await)
}

pub async fn handle_delete_cache_zone<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DomainParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_delete_cache_zone",
        policy.check_delete(),
        cache::delete_cache_zone(client, &p.domain),
    )
    .await)
}

/// Flushes the DNS cache if the provided policy permits a write operation.
///
/// # Returns
///
/// A `CallToolResult` containing the JSON tool response for the `"dns_flush_cache"` operation, or an `McpError` if the operation fails.
///
/// # Examples
///
/// ```
/// # use crate::mcp::tools::cache::handle_flush_cache;
/// # use crate::mcp::Policy;
/// # use crate::mcp::tests::FakeService;
/// # tokio_test::block_on(async {
/// let client = FakeService;
/// let policy = Policy::allow_write(); // policy that permits write
/// let res = handle_flush_cache(&client, &policy).await.unwrap();
/// assert_eq!(res.is_error, Some(false));
/// # });
/// ```
pub async fn handle_flush_cache<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_flush_cache",
        policy.check_write(),
        cache::flush_cache(client),
    )
    .await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::policy::{Policy, PolicyRule};
    use crate::mcp::tools::test_support::FakeService;

    /// Creates a test `DomainParams` with `server_id` set to `"s"` and `domain` set to `"example.com"`.
    ///
    /// # Examples
    ///
    /// ```
    /// let p = params();
    /// assert_eq!(p.server_id, "s");
    /// assert_eq!(p.domain, "example.com");
    /// ```
    fn params() -> DomainParams {
        DomainParams {
            server_id: "s".into(),
            domain: "example.com".into(),
        }
    }

    #[tokio::test]
    async fn list_cache_requires_read() {
        let policy = Policy::new([PolicyRule::Write], None);
        let res = handle_list_cache(&FakeService, &policy, params())
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(true));
        assert!(
            res.content[0]
                .as_text()
                .unwrap()
                .text
                .contains("does not permit read")
        );
    }

    #[tokio::test]
    async fn list_cache_succeeds_with_read() {
        let policy = Policy::new([PolicyRule::Read], None);
        let res = handle_list_cache(&FakeService, &policy, params())
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(false));
    }

    #[tokio::test]
    async fn flush_cache_requires_write() {
        let policy = Policy::new([PolicyRule::Read], None);
        let res = handle_flush_cache(&FakeService, &policy).await.unwrap();
        assert_eq!(res.is_error, Some(true));
        assert!(
            res.content[0]
                .as_text()
                .unwrap()
                .text
                .contains("does not permit write")
        );
    }

    #[tokio::test]
    async fn flush_cache_succeeds_with_write() {
        let policy = Policy::new([PolicyRule::Write], None);
        let res = handle_flush_cache(&FakeService, &policy).await.unwrap();
        assert_eq!(res.is_error, Some(false));
    }

    #[tokio::test]
    async fn delete_cache_zone_requires_delete() {
        let policy = Policy::new([PolicyRule::Write], None);
        let res = handle_delete_cache_zone(&FakeService, &policy, params())
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(true));
        assert!(
            res.content[0]
                .as_text()
                .unwrap()
                .text
                .contains("does not permit delete")
        );
    }

    #[tokio::test]
    async fn delete_cache_zone_succeeds_with_delete() {
        let policy = Policy::new([PolicyRule::Delete], None);
        let res = handle_delete_cache_zone(&FakeService, &policy, params())
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(false));
    }
}
