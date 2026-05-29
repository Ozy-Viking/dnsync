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
