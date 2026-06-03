use rmcp::{ErrorData as McpError, model::*};

use crate::{
    control_plane::policy::Policy,
    core::dns::access_lists,
    core::dns::service::DnsService,
    mcp::{helpers::run_json, params::DomainParams},
};

pub async fn handle_list_blocked<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_list_blocked",
        policy.check_read(),
        access_lists::list_blocked(client),
    )
    .await)
}

pub async fn handle_add_blocked<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DomainParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_add_blocked",
        policy.check_write(),
        access_lists::add_blocked(client, &p.domain),
    )
    .await)
}

pub async fn handle_delete_blocked<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DomainParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_delete_blocked",
        policy.check_delete(),
        access_lists::delete_blocked(client, &p.domain),
    )
    .await)
}

pub async fn handle_list_allowed<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_list_allowed",
        policy.check_read(),
        access_lists::list_allowed(client),
    )
    .await)
}

pub async fn handle_add_allowed<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DomainParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_add_allowed",
        policy.check_write(),
        access_lists::add_allowed(client, &p.domain),
    )
    .await)
}

/// Deletes a domain from the DNS allowed list if the policy permits it.
///
/// # Returns
///
/// `Ok(CallToolResult)` containing the tool response when the deletion was initiated successfully; `Err(McpError)` if an error occurred (permission check or service error).
///
/// # Examples
///
/// ```ignore
/// # use crate::{handle_delete_allowed, DomainParams, Policy, FakeService};
/// # tokio_test::block_on(async {
/// let client = FakeService::new();
/// let policy = Policy::new([], None);
/// let params = DomainParams { server_id: "s", domain: "example.com" };
/// let _res = handle_delete_allowed(&client, &policy, params).await;
/// # });
/// ```
pub async fn handle_delete_allowed<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DomainParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_delete_allowed",
        policy.check_delete(),
        access_lists::delete_allowed(client, &p.domain),
    )
    .await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::policy::{Policy, PolicyRule};
    use crate::mcp::tools::test_support::FakeService;

    /// Create a DomainParams instance for tests with `server_id` set to `"s"` and `domain` set to `"ads.example"`.
    ///
    /// Returns a `DomainParams` preconfigured for use in the module's unit tests.
    ///
    /// # Examples
    ///
    /// ```
    /// let p = params();
    /// assert_eq!(p.server_id, "s");
    /// assert_eq!(p.domain, "ads.example");
    /// ```
    fn params() -> DomainParams {
        DomainParams {
            server_id: "s".into(),
            domain: "ads.example".into(),
        }
    }

    #[tokio::test]
    async fn list_blocked_requires_read() {
        let policy = Policy::new([PolicyRule::Write], None);
        let res = handle_list_blocked(&FakeService, &policy).await.unwrap();
        assert_eq!(res.is_error, Some(true));
    }

    #[tokio::test]
    async fn list_allowed_succeeds_with_read() {
        let policy = Policy::new([PolicyRule::Read], None);
        let res = handle_list_allowed(&FakeService, &policy).await.unwrap();
        assert_eq!(res.is_error, Some(false));
    }

    #[tokio::test]
    async fn add_blocked_requires_write() {
        let policy = Policy::new([PolicyRule::Read], None);
        let res = handle_add_blocked(&FakeService, &policy, params())
            .await
            .unwrap();
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
    async fn add_allowed_succeeds_with_write() {
        let policy = Policy::new([PolicyRule::Write], None);
        let res = handle_add_allowed(&FakeService, &policy, params())
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(false));
    }

    #[tokio::test]
    async fn delete_blocked_requires_delete() {
        let policy = Policy::new([PolicyRule::Write], None);
        let res = handle_delete_blocked(&FakeService, &policy, params())
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
    async fn delete_allowed_succeeds_with_delete() {
        let policy = Policy::new([PolicyRule::Delete], None);
        let res = handle_delete_allowed(&FakeService, &policy, params())
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(false));
    }
}
