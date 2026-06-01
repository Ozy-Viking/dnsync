//! MCP observe tool handlers.

use super::*;

#[tool_router(router = observe_router, vis = "pub(crate)")]
impl DnsServer {
    // ── Stats ─────────────────────────────────────────────────────────────

    /// Fetches dashboard statistics for a configured DNS server.
    ///
    /// Requests metrics for the server identified by `server_id`. The `stats_type` selects the
    /// time range and defaults to `"LastDay"` when unset. Valid `stats_type` values are
    /// `"LastHour"`, `"LastDay"`, `"LastWeek"`, `"LastMonth"`, and `"LastYear"`.
    ///
    /// # Parameters
    ///
    /// - `p.server_id` — Identifier of a configured DNS server (discoverable via `dns_list_servers`).
    /// - `p.stats_type` — Optional time range for the statistics; defaults to `"LastDay"`.
    ///
    /// # Returns
    ///
    /// `CallToolResult` containing the requested statistics payload.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # async fn example(dns_server: &crate::mcp::server::DnsServer) {
    /// use crate::mcp::params::{Parameters, StatsParams};
    ///
    /// let params = Parameters(StatsParams {
    ///     server_id: "primary".to_string(),
    ///     stats_type: None,
    /// });
    ///
    /// let result = dns_server.dns_get_stats(params).await;
    /// assert!(result.is_ok());
    /// # }
    /// ```
    #[tool(
        description = "Get dashboard statistics. stats_type: LastHour, LastDay, LastWeek, LastMonth, LastYear. \
    Use `server_id` from dns_list_servers."
    )]
    pub(crate) async fn dns_get_stats(
        &self,
        Parameters(p): Parameters<StatsParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_get_stats", server_id = %p.server_id, stats_type = p.stats_type.as_deref().unwrap_or("LastDay"), "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        stats_tools::handle_get_stats(&client, &policy, p).await
    }

    // ── Logs ──────────────────────────────────────────────────────────────

    /// Retrieve DNS server logs from the specified configured backend.
    #[tool(
        description = "Get DNS server logs. Use `server_id` from dns_list_servers. \
    Optional filters: lines, start, end, and level."
    )]
    pub(crate) async fn dns_logs(
        &self,
        Parameters(p): Parameters<LogsParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_logs", server_id = %p.server_id, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        logs_tools::handle_logs(&client, &policy, p).await
    }

    // ── Sync ──────────────────────────────────────────────────────────────

    /// Synchronize DNS records from one configured server to another.
    ///
    /// This tool requires both `from` and `to` server IDs to be provided in `SyncParams`;
    /// named sync profiles are not used. By default the operation is a dry-run; set
    /// `apply` in `SyncParams` to `true` to apply changes. If `from` or `to` is missing
    /// the call fails with a parse-style configuration error indicating the missing argument.
    ///
    /// # Parameters
    ///
    /// - `p.from` and `p.to`: server IDs identifying the source and destination servers.
    ///
    /// # Returns
    ///
    /// A `CallToolResult` describing the sync outcome on success, or an `McpError` on failure.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Construct sync parameters (dry-run)
    /// let params = crate::mcp::tools::sync::SyncParams {
    ///     from: Some("source-server".into()),
    ///     to: Some("dest-server".into()),
    ///     apply: Some(false),
    ///     ..Default::default()
    /// };
    /// // Call within an async context: `server.dns_sync(Parameters(params)).await?;`
    /// ```
    #[tool(description = "Sync records between two configured servers. \
    Dry-run by default; set `apply` to true to write changes.")]
    pub(crate) async fn dns_sync(
        &self,
        Parameters(p): Parameters<SyncParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_sync", from = ?p.from, to = ?p.to, apply = p.apply, "MCP tool invoked");
        // Named sync profiles have been superseded by [[jobs]]; `from` and `to`
        // must now be specified explicitly.
        let from_id = p.from.as_deref().ok_or_else(|| {
            mcp_err(crate::core::error::Error::parse(
                "sync requires a source server: pass from",
            ))
        })?;
        let to_id = p.to.as_deref().ok_or_else(|| {
            mcp_err(crate::core::error::Error::parse(
                "sync requires a destination server: pass to",
            ))
        })?;
        let (_, from_policy) = self.resolve_server(from_id).map_err(mcp_err)?;
        let (_, to_policy) = self.resolve_server(to_id).map_err(mcp_err)?;
        sync_tools::handle_sync(&self.config, &from_policy, &to_policy, p).await
    }

    // ── Direct DNS resolution (mirrors `dns query`) ───────────────────────

    /// Resolve a name directly via the system resolver, a configured
    /// `[[servers]]` entry, a public resolver shortcut, or any ad-hoc
    /// nameserver. Supports DNS, DoT, DoH, and DoQ.
    ///
    /// Mirrors the `dns query` CLI subcommand and returns the same
    /// stable JSON shape (`query`, `target`, `results` array — one
    /// entry per transport). When `all_transports = true` or
    /// `transports` lists multiple entries, the tool fans out across
    /// every requested block in precedence order dns → dot → doh →
    /// doq; the response's `results` length reflects the actual
    /// transports queried.
    #[tool(
        description = "Resolve a name directly against the system resolver, a configured \
    `[[servers]]` entry (via `server_id`), or any ad-hoc nameserver (via `at`). Supports DNS, \
    DoT, DoH, and (with the `doq` build feature) DoQ. When `server_id` is given, transport \
    selection follows `transports` / `all_transports`; otherwise the scheme on `at` chooses, \
    or the system resolver is used. Transport precedence matches the CLI: dns → dot → doh → doq. \
    Returns the same JSON shape as `dns query --json` — a \
    `results` array with one entry per transport queried."
    )]
    pub(crate) async fn dns_resolve(
        &self,
        Parameters(p): Parameters<ResolveParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_resolve", domain = %p.domain, at = ?p.at, server_id = ?p.server_id, "MCP tool invoked");
        resolve_tools::handle_resolve(&self.config, &self.cli_access, &self.cli_allow_zone, p).await
    }
}
