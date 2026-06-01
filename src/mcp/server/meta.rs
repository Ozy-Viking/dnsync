//! MCP server tool handlers.

use super::*;

#[tool_router(router = server_router, vis = "pub(crate)")]
impl DnsServer {
    // ── Server management ─────────────────────────────────────────────────

    /// List configured DNS servers with their `id`, `vendor`, and `base_url`.
    ///
    /// Returns a JSON object with a `servers` array where each element is an object containing:
    /// - `id`: the server identifier
    /// - `vendor`: the vendor name formatted with `Debug`
    /// - `base_url`: the server base URL, or the string `"(default)"` when no base URL is configured
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use serde_json::json;
    ///
    /// let expected_shape = json!({
    ///     "servers": [ { "id": "example", "vendor": "VendorA", "base_url": "(default)" } ]
    /// });
    ///
    /// assert!(expected_shape.get("servers").is_some());
    /// ```
    #[tool(description = "List all DNS servers defined in the config file. \
    Shows each server's ID, vendor, and base URL. \
    Call this first to discover server IDs — pass `server_id` to every other tool.")]
    pub(crate) async fn dns_list_servers(&self) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_list_servers", "MCP tool invoked");

        let servers: Vec<serde_json::Value> = self
            .config
            .servers
            .iter()
            .map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "vendor": format!("{:?}", s.vendor),
                    "base_url": s.base_url.as_deref().unwrap_or("(default)"),
                })
            })
            .collect();

        Ok(crate::mcp::helpers::json_result(serde_json::json!({
            "servers": servers,
        })))
    }

    #[tool(
        description = "Show the local application config (dnsync.toml) in TOML format. \
    This is the dnsync application config, not remote DNS server settings. \
    Token values are redacted; token_env references are preserved."
    )]
    pub(crate) async fn dns_get_config(&self) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_get_config", "MCP tool invoked");
        let redacted = self.config.redact();
        let toml = redacted.render_toml().map_err(mcp_err)?;
        Ok(crate::mcp::helpers::text_result(toml))
    }

    #[tool(description = "Return the dnsync binary version reported by this MCP server.")]
    pub(crate) async fn dns_version(&self) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_version", "MCP tool invoked");
        Ok(crate::mcp::helpers::json_result(serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
        })))
    }
}
