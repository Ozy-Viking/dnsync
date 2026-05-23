use rmcp::{ErrorData as McpError, model::*};

use crate::{
    control_plane::policy::Policy,
    core::dns::service::DnsService,
    core::dns::settings,
    mcp::helpers::run_json,
};

pub async fn handle_get_settings<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
) -> Result<CallToolResult, McpError> {
    run_json(policy.check_read(), settings::get_settings(client)).await
}
