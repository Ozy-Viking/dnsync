//! MCP zones tool handlers.

use super::*;

#[tool_router(router = zones_router, vis = "pub(crate)")]
impl DnsServer {
    // ── Zones ─────────────────────────────────────────────────────────────

    /// List authoritative zones hosted on the specified DNS server.
    ///
    /// The `server_id` field of the provided parameters selects which configured backend to query.
    ///
    /// # Returns
    ///
    /// `CallToolResult` containing a JSON object with the zones list on success, or an `McpError` on failure.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # async fn example(server: &crate::mcp::DnsServer) -> Result<(), crate::core::error::McpError> {
    /// let params = crate::mcp::ListZonesParams { server_id: "primary".into(), ..Default::default() };
    /// let result = server.dns_list_zones(crate::mcp::Parameters(params)).await?;
    /// println!("{:?}", result);
    /// # Ok(())
    /// # }
    /// ```
    #[tool(
        description = "List all authoritative zones hosted on the DNS server. \
    Use `server_id` from dns_list_servers."
    )]
    pub(crate) async fn dns_list_zones(
        &self,
        Parameters(p): Parameters<ListZonesParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_list_zones", server_id = %p.server_id, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        zone_tools::handle_list_zones(&client, &policy, p).await
    }

    /// Create a new DNS zone on a configured server.
    ///
    /// Supports zone types: Primary, Secondary, Stub, and Forwarder. The `server_id` field in the parameters
    /// must reference one of the configured servers (discoverable via `dns_list_servers`).
    ///
    /// # Parameters
    ///
    /// - `p`: `CreateZoneParams` containing the zone definition and the target `server_id`.
    ///
    /// # Returns
    ///
    /// `CallToolResult` describing the outcome of the creation operation.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # async fn example(dns_server: &crate::mcp::server::DnsServer) -> Result<(), crate::core::error::McpError> {
    /// let params = crate::mcp::tools::zones::CreateZoneParams {
    ///     server_id: "primary-1".into(),
    ///     zone: "example.com".into(),
    ///     zone_type: Some("Primary".into()),
    ///     // ... other fields ...
    /// };
    /// let result = dns_server.dns_create_zone(crate::mcp::tools::Parameters(params)).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tool(
        description = "Create a new DNS zone. Types: Primary, Secondary, Stub, Forwarder. \
    Use `server_id` from dns_list_servers."
    )]
    pub(crate) async fn dns_create_zone(
        &self,
        Parameters(p): Parameters<CreateZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_create_zone", server_id = %p.server_id, zone = %p.zone, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        zone_tools::handle_create_zone(&client, &policy, p).await
    }

    /// Deletes the specified DNS zone on the configured backend server.
    ///
    /// The `p` parameter must include `server_id` to select a configured DNS backend and `zone` to
    /// identify the zone to remove. This operation is destructive and cannot be undone.
    ///
    /// # Parameters
    ///
    /// - `p`: `ZoneParams` containing `server_id` and the `zone` name to delete.
    ///
    /// # Returns
    ///
    /// `Ok(CallToolResult)` on success, `Err(McpError)` if the server cannot be resolved or deletion fails.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # async fn example(server: &crate::mcp::server::DnsServer) -> Result<(), crate::mcp::error::McpError> {
    /// use crate::mcp::params::ZoneParams;
    /// use crate::mcp::server::Parameters;
    ///
    /// let params = ZoneParams { server_id: "primary".into(), zone: "example.com".into() };
    /// let _result = server.dns_delete_zone(Parameters(params)).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tool(
        description = "Delete a DNS zone. This is destructive and cannot be undone. \
    Use `server_id` from dns_list_servers."
    )]
    pub(crate) async fn dns_delete_zone(
        &self,
        Parameters(p): Parameters<ZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_delete_zone", server_id = %p.server_id, zone = %p.zone, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        zone_tools::handle_delete_zone(&client, &policy, p).await
    }

    /// Enables a previously disabled DNS zone on the specified server.
    ///
    /// The `server_id` must match one of the IDs returned by `dns_list_servers`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Example usage (async context):
    /// // dns_enable_zone(&server, Parameters(ZoneParams { server_id: "prod-dns".into(), zone: "example.com".into() })).await?;
    /// ```
    #[tool(description = "Enable a previously disabled DNS zone. \
    Use `server_id` from dns_list_servers.")]
    pub(crate) async fn dns_enable_zone(
        &self,
        Parameters(p): Parameters<ZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_enable_zone", server_id = %p.server_id, zone = %p.zone, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        zone_tools::handle_enable_zone(&client, &policy, p).await
    }

    /// Disable a DNS zone so it stops responding to queries.
    ///
    /// The `server_id` field in `ZoneParams` selects which configured backend to operate on;
    /// discover valid IDs with `dns_list_servers`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Disable zone "example.com" on server "primary"
    /// let params = ZoneParams { server_id: "primary".into(), zone: "example.com".into() };
    /// let _res = dns_server.dns_disable_zone(Parameters(params)).await;
    /// ```
    ///
    /// Returns `Ok(CallToolResult)` on success, `Err(McpError)` on failure.
    #[tool(description = "Disable a DNS zone so it stops responding to queries. \
    Use `server_id` from dns_list_servers.")]
    pub(crate) async fn dns_disable_zone(
        &self,
        Parameters(p): Parameters<ZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_disable_zone", server_id = %p.server_id, zone = %p.zone, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        zone_tools::handle_disable_zone(&client, &policy, p).await
    }

    /// Imports an RFC 1035 zone file into an existing zone.
    ///
    /// This replaces or merges the zone's records according to the `overwrite_zone` flag:
    /// - If `overwrite_zone` is `true`, existing records for the zone are deleted before import.
    /// - If `overwrite_zone` is `false`, records from the zone file are added/updated alongside existing records.
    ///
    /// The `server_id` parameter selects which configured DNS backend to target (see `dns_list_servers`).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use crate::mcp::params::ImportZoneFileParams;
    /// // construct params with `zone`, `content`, `overwrite_zone`, and `server_id`
    /// let params = ImportZoneFileParams { zone: "example.com".into(), content: "$ORIGIN example.com.\n...".into(), overwrite_zone: true, server_id: "primary".into() };
    /// // `srv` is a `DnsServer` instance; call from an async context
    /// let _res = tokio::runtime::Runtime::new().unwrap().block_on(async { srv.dns_import_zone_file(Parameters(params)).await });
    /// ```
    #[tool(
        description = "Import a zone file (RFC 1035 format) into an existing zone. \
    Pass the full zone file text in `content`. Use `overwrite_zone: true` for a clean \
    replace that deletes all existing records first. \
    Use `server_id` from dns_list_servers."
    )]
    pub(crate) async fn dns_import_zone_file(
        &self,
        Parameters(p): Parameters<ImportZoneFileParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_import_zone_file", server_id = %p.server_id, zone = %p.zone, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        zone_tools::handle_import_zone_file(&client, &policy, p).await
    }

    /// Export a DNS zone in BIND (RFC 1035) zone file format.
    ///
    /// The specified `server_id` selects which configured DNS backend to query; use `dns_list_servers` to discover available IDs.
    /// The returned result contains the complete zone file text suitable for saving to disk or importing into another DNS provider.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// # async fn example(server: &crate::mcp::server::DnsServer) -> Result<(), crate::core::error::McpError> {
    /// use crate::mcp::tools::Parameters;
    /// use crate::mcp::params::ExportZoneFileParams;
    ///
    /// let params = ExportZoneFileParams { server_id: "primary".into(), zone: "example.com".into() };
    /// let res = server.dns_export_zone_file(Parameters(params)).await?;
    /// // `res` contains the exported zone file text (BIND format)
    /// # Ok(())
    /// # }
    /// ```
    #[tool(
        description = "Export a DNS zone as a BIND-format (RFC 1035) zone file. \
    Returns the full zone file text, which can be saved to disk or imported into another DNS provider. \
    Use `server_id` from dns_list_servers."
    )]
    pub(crate) async fn dns_export_zone_file(
        &self,
        Parameters(p): Parameters<ExportZoneFileParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_export_zone_file", server_id = %p.server_id, zone = %p.zone, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        zone_tools::handle_export_zone_file(&client, &policy, p).await
    }

    #[tool(description = "Copy a zone from one configured server to another. \
    Reads from `from`, writes to `to`, and respects each server's MCP permissions and allowed zones.")]
    pub(crate) async fn dns_transfer_zone(
        &self,
        Parameters(p): Parameters<TransferZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_transfer_zone", zone = %p.zone, from = %p.from, to = %p.to, "MCP tool invoked");
        let (_, from_policy) = self.resolve_server(&p.from).map_err(mcp_err)?;
        let (_, to_policy) = self.resolve_server(&p.to).map_err(mcp_err)?;
        let check = from_policy
            .check_read()
            .and(from_policy.check_zone(&p.zone))
            .and(to_policy.check_write())
            .and(to_policy.check_zone(&p.zone));
        Ok(
            crate::mcp::helpers::run_json("dns_transfer_zone", check, async move {
                let result = transfer::transfer_zone(
                    Some(&self.config),
                    &p.zone,
                    &p.from,
                    &p.to,
                    p.overwrite,
                    p.overwrite_zone,
                )
                .await?;
                serde_json::to_value(result).map_err(|e| {
                    crate::core::error::Error::parse(format!(
                        "could not serialise zone transfer result: {e}"
                    ))
                })
            })
            .await,
        )
    }

    #[tool(
        description = "Get zone-level options for a zone on the DNS server (Technitium only). \
    Returns transfer settings, zone type, and other per-zone configuration. \
    Use `server_id` from dns_list_servers."
    )]
    pub(crate) async fn dns_get_zone_options(
        &self,
        Parameters(p): Parameters<ZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_get_zone_options", server_id = %p.server_id, zone = %p.zone, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        zone_tools::handle_get_zone_options(&client, &policy, p).await
    }

    #[tool(
        description = "Set zone-level options for a zone on the DNS server (Technitium only). \
    Accepts a JSON object — only provided keys are changed. Requires write access. \
    Use `server_id` from dns_list_servers."
    )]
    pub(crate) async fn dns_set_zone_options(
        &self,
        Parameters(p): Parameters<SetZoneOptionsParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_set_zone_options", server_id = %p.server_id, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        zone_tools::handle_set_zone_options(&client, &policy, p).await
    }
}
