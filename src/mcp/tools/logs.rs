use rmcp::{ErrorData as McpError, model::*};

use crate::{
    control_plane::policy::Policy,
    core::dns::{logs, service::DnsService},
    mcp::{helpers::run_json, params::LogsParams},
};

pub async fn handle_logs<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    params: LogsParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json("dns_logs", policy.check_read(), async move {
        let lines = logs::get_logs(client, params.into()).await?;
        serde_json::to_value(lines).map_err(|err| {
            crate::core::error::Error::parse(format!("failed to serialize logs: {err}"))
        })
    })
    .await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::policy::{Policy, PolicyRule};
    use crate::mcp::tools::test_support::FakeService;

    fn params() -> LogsParams {
        LogsParams {
            server_id: "s".into(),
            lines: None,
            start: None,
            end: None,
            level: None,
        }
    }

    #[tokio::test]
    async fn logs_requires_read() {
        let policy = Policy::new([PolicyRule::Write], None);
        let res = handle_logs(&FakeService, &policy, params()).await.unwrap();
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
    async fn logs_succeeds_with_read() {
        let policy = Policy::new([PolicyRule::Read], None);
        let res = handle_logs(&FakeService, &policy, params()).await.unwrap();
        assert_eq!(res.is_error, Some(false));
    }
}
