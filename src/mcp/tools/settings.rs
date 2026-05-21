use rmcp::{ErrorData as McpError, model::*};

use crate::{
    core::dns::service::DnsService,
    core::dns::settings,
    mcp::helpers::{json_result, mcp_err},
};

pub async fn handle_get_settings<C: DnsService + Send + Sync>(
    client: &C,
) -> Result<CallToolResult, McpError> {
    settings::get_settings(client)
        .await
        .map(json_result)
        .map_err(mcp_err)
}
