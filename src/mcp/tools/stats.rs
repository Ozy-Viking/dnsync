use rmcp::{ErrorData as McpError, model::*};

use crate::{
    control_plane::policy::Policy,
    core::dns::service::DnsService,
    core::dns::stats,
    mcp::{helpers::run_json, params::StatsParams},
};

/// Fetches DNS statistics for the given parameters while enforcing the policy's read permission.
///
/// On success returns the tool call result produced for the `dns_get_stats` tool; on failure returns an `McpError`.
///
/// # Examples
///
/// ```ignore
/// # use crate::{handle_get_stats, Policy, StatsParams, FakeService};
/// # async fn example() {
/// let policy = Policy::with_read_allowed(); // create a policy that permits read
/// let params = StatsParams { server_id: "s".into(), stats_type: None };
/// let result = handle_get_stats(&FakeService, &policy, params).await.unwrap();
/// assert!(result.is_error == Some(false));
/// # }
/// ```
pub async fn handle_get_stats<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: StatsParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_get_stats",
        policy.check_read(),
        stats::get_stats(client, p.stats_type.as_deref().unwrap_or("LastDay")),
    )
    .await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::policy::{Policy, PolicyRule};
    use crate::mcp::tools::test_support::FakeService;

    /// Constructs a `StatsParams` with `server_id` set to `"s"` and `stats_type` set to `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// let p = params();
    /// assert_eq!(p.server_id, "s");
    /// assert!(p.stats_type.is_none());
    /// ```
    fn params() -> StatsParams {
        StatsParams {
            server_id: "s".into(),
            stats_type: None,
        }
    }

    /// Verifies that `handle_get_stats` fails when the provided `Policy` does not permit read access.
    ///
    /// The test constructs a `Policy` granting only `Write`, calls `handle_get_stats`, and asserts
    /// the result indicates an error and that the returned error text contains "does not permit read".
    #[tokio::test]
    async fn get_stats_requires_read() {
        let policy = Policy::new([PolicyRule::Write], None);
        let res = handle_get_stats(&FakeService, &policy, params())
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
    async fn get_stats_succeeds_with_read() {
        let policy = Policy::new([PolicyRule::Read], None);
        let res = handle_get_stats(&FakeService, &policy, params())
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(false));
    }
}
