//! MCP settings tool handlers.

use super::*;

#[tool_router(router = settings_router, vis = "pub(crate)")]
impl DnsServer {
    // ── Settings ──────────────────────────────────────────────────────────

    /// Retrieve the active DNS configuration for the specified server.
    ///
    /// The `server_id` in `ServerScopeParams` must identify one of the configured servers (see `dns_list_servers`).
    ///
    /// On success returns a `CallToolResult` containing the server settings; on failure returns an `McpError`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # async fn example_usage(server: &crate::mcp::server::DnsServer) {
    /// use axum::extract::Parameters;
    /// use crate::mcp::params::ServerScopeParams;
    ///
    /// let params = ServerScopeParams { server_id: "primary".to_string() };
    /// let res = server.dns_get_settings(Parameters(params)).await;
    /// // `res` is `Ok(CallToolResult)` on success
    /// # }
    /// ```
    #[tool(description = "Get the current DNS server configuration. \
    Use `server_id` from dns_list_servers.")]
    pub(crate) async fn dns_get_settings(
        &self,
        Parameters(p): Parameters<ServerScopeParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_get_settings", server_id = %p.server_id, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        let show_secrets = self.show_settings_secrets(&p.server_id).map_err(mcp_err)?;
        settings_tools::handle_get_settings(&client, &policy, show_secrets).await
    }

    #[tool(
        description = "Write server-level settings on a DNS server (Technitium only). \
    Accepts a JSON object — only provided keys are changed. Requires write access. \
    Use `server_id` from dns_list_servers. Example: {\"zoneTransferAllowedNetworks\": [\"10.0.0.0/8\"]}."
    )]
    pub(crate) async fn dns_set_settings(
        &self,
        Parameters(p): Parameters<SetSettingsParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_set_settings", server_id = %p.server_id, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        settings_tools::handle_set_settings(&client, &policy, &p.settings).await
    }
}
