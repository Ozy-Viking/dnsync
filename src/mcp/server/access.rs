//! MCP access tool handlers.

use super::*;

#[tool_router(router = access_router, vis = "pub(crate)")]
impl DnsServer {
    // ── Blocked ───────────────────────────────────────────────────────────

    /// List manually blocked domain names for a configured server.
    ///
    /// Resolves the target server by `server_id` and returns the blocked-domain list as a tool call result.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use crate::mcp::server::DnsServer;
    /// # use crate::mcp::params::ServerScopeParams;
    /// # use crate::mcp::tools::Parameters;
    /// # async fn example(server: &DnsServer) -> Result<(), crate::core::error::McpError> {
    /// let params = Parameters(ServerScopeParams { server_id: "primary".into() });
    /// let res = server.dns_list_blocked_zones(params).await?;
    /// println!("{}", res);
    /// # Ok(())
    /// # }
    /// ```
    #[tool(description = "List all manually blocked domains. \
    Use `server_id` from dns_list_servers.")]
    pub(crate) async fn dns_list_blocked_zones(
        &self,
        Parameters(p): Parameters<ServerScopeParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_list_blocked_zones", server_id = %p.server_id, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        access_lists::handle_list_blocked(&client, &policy).await
    }

    /// Adds a domain to the specified server's blocked list so that the DNS server will refuse to resolve it.
    ///
    /// The `DomainParams.server_id` selects which configured DNS server to affect (discoverable via `dns_list_servers`).
    ///
    /// # Returns
    ///
    /// `Ok(CallToolResult)` on success, `Err(McpError)` on failure.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use crate::mcp::params::DomainParams;
    /// # async fn example(server: &crate::mcp::server::DnsServer) {
    /// let params = DomainParams { server_id: "default".into(), domain: "example.com".into() };
    /// let res = server.dns_add_blocked_zone(crate::mcp::Parameters(params)).await;
    /// assert!(res.is_ok());
    /// # }
    /// ```
    #[tool(
        description = "Block a domain, causing the DNS server to refuse to resolve it. \
    Use `server_id` from dns_list_servers."
    )]
    pub(crate) async fn dns_add_blocked_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_add_blocked_zone", server_id = %p.server_id, domain = %p.domain, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        access_lists::handle_add_blocked(&client, &policy, p).await
    }

    /// Remove a domain from a server's manual blocked (deny) list.
    ///
    /// The `server_id` identifies which configured DNS backend to operate on; use
    /// `dns_list_servers` to discover available IDs.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use crate::mcp::server::DnsServer;
    /// # use crate::mcp::params::DomainParams;
    /// # use crate::mcp::tools::CallToolResult;
    /// # use crate::mcp::error::McpError;
    /// # use axum::extract::Parameters;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), McpError> {
    /// let server = /* construct or obtain a DnsServer instance */;
    /// let params = DomainParams { server_id: "primary".into(), domain: "example.com".into() };
    /// let result: CallToolResult = server.dns_delete_blocked_zone(Parameters(params)).await?;
    /// # Ok(()) }
    /// ```
    #[tool(description = "Unblock a domain. \
    Use `server_id` from dns_list_servers.")]
    pub(crate) async fn dns_delete_blocked_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_delete_blocked_zone", server_id = %p.server_id, domain = %p.domain, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        access_lists::handle_delete_blocked(&client, &policy, p).await
    }

    // ── Allowed ───────────────────────────────────────────────────────────

    /// List whitelisted (allowed) domains for the specified DNS server.
    ///
    /// # Returns
    ///
    /// `Ok(CallToolResult)` containing the allowed domains list, `Err(McpError)` on failure.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // In an async context:
    /// let params = ServerScopeParams { server_id: "example-server".to_string() };
    /// let result = server.dns_list_allowed_zones(Parameters(params)).await;
    /// assert!(result.is_ok());
    /// ```
    #[tool(description = "List all whitelisted domains. \
    Use `server_id` from dns_list_servers.")]
    pub(crate) async fn dns_list_allowed_zones(
        &self,
        Parameters(p): Parameters<ServerScopeParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_list_allowed_zones", server_id = %p.server_id, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        access_lists::handle_list_allowed(&client, &policy).await
    }

    /// Adds a domain to a server's allow list so it will be permitted even if present on a block list.
    ///
    /// The `DomainParams.server_id` selects which configured DNS server to act on (discoverable via `dns_list_servers`), and `DomainParams.domain` is the domain to allow.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Prepare parameters and call the tool
    /// let params = DomainParams { server_id: "prod".into(), domain: "example.com".into() };
    /// let result = dns_server.dns_add_allowed_zone(Parameters(params)).await?;
    /// ```
    #[tool(
        description = "Whitelist a domain, allowing it even if it appears on a block list. \
    Use `server_id` from dns_list_servers."
    )]
    pub(crate) async fn dns_add_allowed_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_add_allowed_zone", server_id = %p.server_id, domain = %p.domain, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        access_lists::handle_add_allowed(&client, &policy, p).await
    }

    /// Removes a domain from a server's allow list (whitelist).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use crate::mcp::server::DnsServer;
    /// # use crate::mcp::params::DomainParams;
    /// # async fn example(srv: &DnsServer) {
    /// let params = DomainParams { server_id: "server1".into(), domain: "example.com".into() };
    /// // Call the tool and await the result
    /// let _ = srv.dns_delete_allowed_zone(crate::mcp::server::Parameters(params)).await;
    /// # }
    /// ```
    #[tool(description = "Remove a domain from the whitelist. \
    Use `server_id` from dns_list_servers.")]
    pub(crate) async fn dns_delete_allowed_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_delete_allowed_zone", server_id = %p.server_id, domain = %p.domain, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        access_lists::handle_delete_allowed(&client, &policy, p).await
    }
}
