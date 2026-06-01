//! MCP cache tool handlers.

use super::*;

#[tool_router(router = cache_router, vis = "pub(crate)")]
impl DnsServer {
    // ── Cache ─────────────────────────────────────────────────────────────

    /// List entries in the DNS cache for a specific configured server and domain.
    ///
    /// If the `domain` parameter is an empty string, the root cache is listed. Use a `server_id` obtained from `dns_list_servers`.
    ///
    /// # Parameters
    ///
    /// - `p`: Parameters containing `server_id` (the configured server to query) and `domain` (the domain to list).
    ///
    /// # Returns
    ///
    /// `CallToolResult` containing the cache entries for the specified server and domain, or an `McpError` on failure.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Async context required:
    /// // let params = Parameters(DomainParams { server_id: "primary".into(), domain: "".into() });
    /// // let result = dns_server.dns_list_cache(params).await?;
    /// ```
    #[tool(
        description = "Browse the DNS cache. Pass an empty string for domain to list the root. \
    Use `server_id` from dns_list_servers."
    )]
    pub(crate) async fn dns_list_cache(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_list_cache", server_id = %p.server_id, domain = %p.domain, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        cache_tools::handle_list_cache(&client, &policy, p).await
    }

    /// Evicts the DNS cache for a specific domain on the targeted server.
    ///
    /// The `server_id` field in the parameters selects which configured DNS backend to operate on;
    /// discover available IDs with `dns_list_servers`.
    ///
    /// # Returns
    ///
    /// `CallToolResult` on success, `McpError` on failure.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use crate::mcp::server::DnsServer;
    /// # use crate::mcp::params::DomainParams;
    /// # use crate::mcp::tools::Parameters;
    /// # async fn example(server: &DnsServer) {
    /// let params = DomainParams { server_id: "primary".into(), domain: "example.com".into() };
    /// let res = server.dns_delete_cache_zone(Parameters(params)).await;
    /// match res {
    ///     Ok(result) => println!("Evicted cache: {:?}", result),
    ///     Err(err) => eprintln!("Failed to evict cache: {:?}", err),
    /// }
    /// # }
    /// ```
    #[tool(description = "Evict a specific domain from the DNS cache. \
    Use `server_id` from dns_list_servers.")]
    pub(crate) async fn dns_delete_cache_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_delete_cache_zone", server_id = %p.server_id, domain = %p.domain, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        cache_tools::handle_delete_cache_zone(&client, &policy, p).await
    }

    /// Flushes the DNS cache for the configured server identified by `server_id`.
    ///
    /// Use a `server_id` returned by `dns_list_servers` to target the correct backend.
    ///
    /// Returns a `CallToolResult` on success, or an `McpError` if the server cannot be resolved or the flush fails.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # use crate::mcp::server::DnsServer;
    /// # use crate::mcp::params::ServerScopeParams;
    /// # async fn example(server: &DnsServer) -> Result<(), crate::core::error::McpError> {
    /// let params = ServerScopeParams { server_id: "main".to_string() };
    /// let result = server.dns_flush_cache(crate::mcp::tools::Parameters(params)).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tool(
        description = "Flush the entire DNS cache, forcing all records to be resolved fresh. \
    Use `server_id` from dns_list_servers."
    )]
    pub(crate) async fn dns_flush_cache(
        &self,
        Parameters(p): Parameters<ServerScopeParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_flush_cache", server_id = %p.server_id, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        cache_tools::handle_flush_cache(&client, &policy).await
    }
}
