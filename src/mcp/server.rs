use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    tool, tool_handler, tool_router,
};

use crate::{
    control_plane::{
        config::AppConfig,
        policy::{Policy, PolicyRule},
        transfer,
    },
    mcp::{
        helpers::mcp_err,
        params::*,
        tools::{
            access_lists, cache as cache_tools, logs as logs_tools, records as record_tools,
            resolve as resolve_tools, settings as settings_tools, stats as stats_tools,
            sync as sync_tools, zones as zone_tools,
        },
    },
    vendors::runtime::VendorClient,
};

// ─── Server state ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct DnsServer {
    config: Arc<AppConfig>,
    cli_access: Arc<Vec<PolicyRule>>,
    cli_allow_zone: Arc<Vec<String>>,
    startup_info: String,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl DnsServer {
    /// Construct a `DnsServer` from the given application configuration and CLI-derived policy inputs.
    ///
    /// The created server stores the provided `config`, `cli_access`, and `cli_allow_zone` (each wrapped in `Arc`)
    /// and computes a human-readable `startup_info` message that either lists available server IDs or instructs
    /// how to add a server when none are configured.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Create a DnsServer from an AppConfig and CLI policy inputs.
    /// // (Fields shown here are illustrative; construct AppConfig/PolicyRule as appropriate in real code.)
    /// let config = AppConfig { servers: vec![] }; // or whatever constructor is available
    /// let cli_access = Vec::<PolicyRule>::new();
    /// let cli_allow_zone = Vec::<String>::new();
    /// let server = DnsServer::new(config, cli_access, cli_allow_zone);
    /// ```
    pub fn new(
        config: AppConfig,
        cli_access: Vec<PolicyRule>,
        cli_allow_zone: Vec<String>,
    ) -> Self {
        let startup_info = if config.servers.is_empty() {
            " No DNS servers configured. Run `dns config add` to add one, then restart the MCP server.".to_string()
        } else {
            let ids: Vec<&str> = config.servers.iter().map(|s| s.id.as_str()).collect();
            format!(
                " Available servers: {}. Pass `server_id` to every tool.",
                ids.join(", ")
            )
        };

        Self {
            config: Arc::new(config),
            cli_access: Arc::new(cli_access),
            cli_allow_zone: Arc::new(cli_allow_zone),
            startup_info,
            tool_router: Self::tool_router(),
        }
    }

    /// Resolve a configured DNS backend by its identifier and produce a client and policy for calling it.
    ///
    /// Looks up `server_id` case-insensitively in the server list, constructs a `VendorClient` for that
    /// server, and builds a `Policy` using the CLI-provided access and allow-zone rules. If the server
    /// cannot be found, returns a configuration error advising the caller to list available server IDs.
    ///
    /// # Parameters
    ///
    /// - `server_id`: Case-insensitive identifier of the configured server to resolve.
    ///
    /// # Returns
    ///
    /// A `(VendorClient, Policy)` pair for the matched server.
    ///
    /// # Errors
    ///
    /// Returns a configuration `Error` if no server with the given `server_id` exists.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use std::sync::Arc;
    /// # use crate::mcp::server::DnsServer;
    /// # use crate::config::AppConfig;
    /// // Given a DnsServer `srv` and a server id:
    /// // let srv = DnsServer::new(app_config, vec![], vec![]);
    /// // let (client, policy) = srv.resolve_server("primary")?;
    /// ```
    fn resolve_server(
        &self,
        server_id: &str,
    ) -> crate::core::error::Result<(VendorClient, Policy)> {
        let server = self
            .config
            .servers
            .iter()
            .find(|s| s.id.eq_ignore_ascii_case(server_id))
            .ok_or_else(|| {
                crate::core::error::Error::config(format!(
                    "no server named '{server_id}' — call dns_list_servers to see available IDs"
                ))
            })?;
        let client = VendorClient::from_server(server)?;
        let policy = Policy::for_server(server, &self.cli_access, &self.cli_allow_zone)?;
        Ok((client, policy))
    }

    fn show_settings_secrets(&self, server_id: &str) -> crate::core::error::Result<bool> {
        self.config
            .servers
            .iter()
            .find(|s| s.id.eq_ignore_ascii_case(server_id))
            .map(|server| server.mcp.show_settings_secrets)
            .ok_or_else(|| {
                crate::core::error::Error::config(format!(
                    "no server named '{server_id}' — call dns_list_servers to see available IDs"
                ))
            })
    }
}

// ─── Tools ───────────────────────────────────────────────────────────────────

#[tool_router]
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
    /// ```ignore
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
    async fn dns_list_servers(&self) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_list_servers", "MCP tool invoked");

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
    async fn dns_get_config(&self) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_get_config", "MCP tool invoked");
        let redacted = self.config.redact();
        let toml = redacted.render_toml().map_err(mcp_err)?;
        Ok(crate::mcp::helpers::text_result(toml))
    }

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
    /// ```ignore
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
    async fn dns_list_zones(
        &self,
        Parameters(p): Parameters<ListZonesParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_list_zones", "MCP tool invoked");
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
    /// ```ignore
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
    async fn dns_create_zone(
        &self,
        Parameters(p): Parameters<CreateZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_create_zone", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, "tool invoked");
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
    /// ```ignore
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
    async fn dns_delete_zone(
        &self,
        Parameters(p): Parameters<ZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_delete_zone", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, "tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        zone_tools::handle_delete_zone(&client, &policy, p).await
    }

    /// Enables a previously disabled DNS zone on the specified server.
    ///
    /// The `server_id` must match one of the IDs returned by `dns_list_servers`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Example usage (async context):
    /// // dns_enable_zone(&server, Parameters(ZoneParams { server_id: "prod-dns".into(), zone: "example.com".into() })).await?;
    /// ```
    #[tool(description = "Enable a previously disabled DNS zone. \
    Use `server_id` from dns_list_servers.")]
    async fn dns_enable_zone(
        &self,
        Parameters(p): Parameters<ZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_enable_zone", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, "tool invoked");
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
    /// ```ignore
    /// // Disable zone "example.com" on server "primary"
    /// let params = ZoneParams { server_id: "primary".into(), zone: "example.com".into() };
    /// let _res = dns_server.dns_disable_zone(Parameters(params)).await;
    /// ```
    ///
    /// Returns `Ok(CallToolResult)` on success, `Err(McpError)` on failure.
    #[tool(description = "Disable a DNS zone so it stops responding to queries. \
    Use `server_id` from dns_list_servers.")]
    async fn dns_disable_zone(
        &self,
        Parameters(p): Parameters<ZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_disable_zone", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, "tool invoked");
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
    /// ```ignore
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
    async fn dns_import_zone_file(
        &self,
        Parameters(p): Parameters<ImportZoneFileParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_import_zone_file", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, "tool invoked");
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
    /// ```ignore
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
    async fn dns_export_zone_file(
        &self,
        Parameters(p): Parameters<ExportZoneFileParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_export_zone_file", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, "tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        zone_tools::handle_export_zone_file(&client, &policy, p).await
    }

    #[tool(description = "Copy a zone from one configured server to another. \
    Reads from `from`, writes to `to`, and respects each server's MCP permissions and allowed zones.")]
    async fn dns_transfer_zone(
        &self,
        Parameters(p): Parameters<TransferZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_transfer_zone", "MCP tool invoked");
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

    // ── Records ───────────────────────────────────────────────────────────

    /// List DNS records for a domain, returning typed records including writable and DNSSEC types.
    ///
    /// Returns a JSON result containing the domain's DNS records suitable for display and editing.
    /// The returned set includes writable record types (for example: `A`, `AAAA`, `MX`, etc.)
    /// and read-only DNSSEC records (`DNSKEY`, `RRSIG`, `NSEC`, `NSEC3`).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Example (pseudo): call the tool with a server_id and domain.
    /// // let srv = DnsServer::new(...);
    /// // let params = ListRecordsParams { server_id: "primary".into(), domain: "example.com".into(), zone: None };
    /// // let result = srv.dns_list_records(Parameters(params)).await?;
    /// ```
    #[tool(
        description = "List all DNS records for a domain. Returns typed records including writable types (A, AAAA, MX, etc.) and read-only DNSSEC types (DNSKEY, RRSIG, NSEC, NSEC3). \
    Use `server_id` from dns_list_servers."
    )]
    async fn dns_list_records(
        &self,
        Parameters(p): Parameters<ListRecordsParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_list_records", "MCP tool invoked");
        tracing::debug!(domain = ?p.domain, zone = ?p.zone, "tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        record_tools::handle_list_records(&client, &policy, p).await
    }

    /// Adds a DNS record to a zone on the specified server.
    ///
    /// The operation applies the provided `record` (typed union: e.g. `A`, `MX`, `TXT`) to `zone`/`domain` on the server identified by `server_id`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # use crate::mcp::server::DnsServer;
    /// # use crate::mcp::params::{AddRecordParams, Record};
    /// # use crate::mcp::tools::Parameters;
    /// # async fn _example(server: &DnsServer) {
    /// let params = AddRecordParams {
    ///     server_id: "primary".to_string(),
    ///     zone: "example.com".to_string(),
    ///     domain: "www".to_string(),
    ///     record: Record::A { ip: "1.2.3.4".to_string() },
    /// };
    /// let result = server.dns_add_record(Parameters(params)).await;
    /// assert!(result.is_ok());
    /// # }
    /// ```
    #[tool(
        description = "Add a DNS record. The `record` field is a typed union: {\"type\":\"A\",\"ip\":\"1.2.3.4\"}, {\"type\":\"MX\",\"exchange\":\"mail.example.com\",\"preference\":10}, {\"type\":\"TXT\",\"text\":\"...\"}, etc. \
    Use `server_id` from dns_list_servers."
    )]
    async fn dns_add_record(
        &self,
        Parameters(p): Parameters<AddRecordParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_add_record", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, domain = %p.domain, "tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        record_tools::handle_add_record(&client, &policy, p).await
    }

    /// Delete one or more DNS records for a configured server.
    ///
    /// The `server_id` field in the parameters selects which configured backend to use (see `dns_list_servers`).
    /// If only `type` is provided, all records of that type for the specified domain are deleted; providing value fields
    /// (for example an IP address for an A record) narrows the deletion to matching records.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # async fn example(srv: &DnsServer) {
    /// let params = DeleteRecordParams {
    ///     server_id: "primary".into(),
    ///     zone: "example.com".into(),
    ///     domain: "www".into(),
    ///     r#type: "A".into(),
    ///     ip_address: Some("1.2.3.4".into()),
    ///     ..Default::default()
    /// };
    /// let res = srv.dns_delete_record(Parameters(params)).await;
    /// assert!(res.is_ok());
    /// # }
    /// ```
    #[tool(
        description = "Delete DNS record(s). Only `type` is required \u{2014} omitting value fields \
    deletes ALL records of that type for the domain. \
    e.g. {\"type\":\"A\"} deletes all A records; {\"type\":\"A\",\"ipAddress\":\"1.2.3.4\"} deletes one specific record. \
    Use `server_id` from dns_list_servers."
    )]
    async fn dns_delete_record(
        &self,
        Parameters(p): Parameters<DeleteRecordParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_delete_record", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, domain = %p.domain, "tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        record_tools::handle_delete_record(&client, &policy, p).await
    }

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
    /// ```ignore
    /// // Async context required:
    /// // let params = Parameters(DomainParams { server_id: "primary".into(), domain: "".into() });
    /// // let result = dns_server.dns_list_cache(params).await?;
    /// ```
    #[tool(
        description = "Browse the DNS cache. Pass an empty string for domain to list the root. \
    Use `server_id` from dns_list_servers."
    )]
    async fn dns_list_cache(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_list_cache", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
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
    /// ```ignore
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
    async fn dns_delete_cache_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_delete_cache_zone", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
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
    /// ```ignore
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
    async fn dns_flush_cache(
        &self,
        Parameters(p): Parameters<ServerScopeParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_flush_cache", "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        cache_tools::handle_flush_cache(&client, &policy).await
    }

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
    /// ```ignore
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
    async fn dns_get_stats(
        &self,
        Parameters(p): Parameters<StatsParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_get_stats", "MCP tool invoked");
        tracing::debug!(
            stats_type = p.stats_type.as_deref().unwrap_or("LastDay"),
            "tool invoked"
        );
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        stats_tools::handle_get_stats(&client, &policy, p).await
    }

    // ── Blocked ───────────────────────────────────────────────────────────

    /// List manually blocked domain names for a configured server.
    ///
    /// Resolves the target server by `server_id` and returns the blocked-domain list as a tool call result.
    ///
    /// # Examples
    ///
    /// ```ignore
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
    async fn dns_list_blocked_zones(
        &self,
        Parameters(p): Parameters<ServerScopeParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_list_blocked_zones", "MCP tool invoked");
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
    /// ```ignore
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
    async fn dns_add_blocked_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_add_blocked_zone", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
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
    /// ```ignore
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
    async fn dns_delete_blocked_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_delete_blocked_zone", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
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
    /// ```ignore
    /// // In an async context:
    /// let params = ServerScopeParams { server_id: "example-server".to_string() };
    /// let result = server.dns_list_allowed_zones(Parameters(params)).await;
    /// assert!(result.is_ok());
    /// ```
    #[tool(description = "List all whitelisted domains. \
    Use `server_id` from dns_list_servers.")]
    async fn dns_list_allowed_zones(
        &self,
        Parameters(p): Parameters<ServerScopeParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_list_allowed_zones", "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        access_lists::handle_list_allowed(&client, &policy).await
    }

    /// Adds a domain to a server's allow list so it will be permitted even if present on a block list.
    ///
    /// The `DomainParams.server_id` selects which configured DNS server to act on (discoverable via `dns_list_servers`), and `DomainParams.domain` is the domain to allow.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Prepare parameters and call the tool
    /// let params = DomainParams { server_id: "prod".into(), domain: "example.com".into() };
    /// let result = dns_server.dns_add_allowed_zone(Parameters(params)).await?;
    /// ```
    #[tool(
        description = "Whitelist a domain, allowing it even if it appears on a block list. \
    Use `server_id` from dns_list_servers."
    )]
    async fn dns_add_allowed_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_add_allowed_zone", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        access_lists::handle_add_allowed(&client, &policy, p).await
    }

    /// Removes a domain from a server's allow list (whitelist).
    ///
    /// # Examples
    ///
    /// ```ignore
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
    async fn dns_delete_allowed_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_delete_allowed_zone", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        access_lists::handle_delete_allowed(&client, &policy, p).await
    }

    // ── Settings ──────────────────────────────────────────────────────────

    /// Retrieve the active DNS configuration for the specified server.
    ///
    /// The `server_id` in `ServerScopeParams` must identify one of the configured servers (see `dns_list_servers`).
    ///
    /// On success returns a `CallToolResult` containing the server settings; on failure returns an `McpError`.
    ///
    /// # Examples
    ///
    /// ```ignore
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
    async fn dns_get_settings(
        &self,
        Parameters(p): Parameters<ServerScopeParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_get_settings", "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        let show_secrets = self.show_settings_secrets(&p.server_id).map_err(mcp_err)?;
        settings_tools::handle_get_settings(&client, &policy, show_secrets).await
    }

    // ── Logs ──────────────────────────────────────────────────────────────

    /// Retrieve DNS server logs from the specified configured backend.
    #[tool(
        description = "Get DNS server logs. Use `server_id` from dns_list_servers. \
    Optional filters: lines, start, end, and level."
    )]
    async fn dns_logs(
        &self,
        Parameters(p): Parameters<LogsParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_logs", "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        logs_tools::handle_logs(&client, &policy, p).await
    }

    // ── Sync ──────────────────────────────────────────────────────────────

    #[tool(description = "Sync records between two configured servers. \
    Dry-run by default; set `apply` to true to write changes.")]
    async fn dns_sync(
        &self,
        Parameters(p): Parameters<SyncParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_sync", "MCP tool invoked");
        let profile = p.profile.as_deref().and_then(|name| {
            self.config
                .sync
                .iter()
                .find(|profile| profile.name.eq_ignore_ascii_case(name))
        });
        let from_id = p
            .from
            .as_deref()
            .or_else(|| profile.map(|profile| profile.from.as_str()))
            .ok_or_else(|| {
                mcp_err(crate::core::error::Error::parse(
                    "sync requires a source server: name a profile or pass from",
                ))
            })?;
        let to_id =
            p.to.as_deref()
                .or_else(|| profile.map(|profile| profile.to.as_str()))
                .ok_or_else(|| {
                    mcp_err(crate::core::error::Error::parse(
                        "sync requires a destination server: name a profile or pass to",
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
    /// every requested block in precedence order doh → dot → dns →
    /// doq; the response's `results` length reflects the actual
    /// transports queried.
    #[tool(
        description = "Resolve a name directly against the system resolver, a configured \
    `[[servers]]` entry (via `server_id`), a public resolver (`public_resolver`: cf/google/quad9/adg), \
    or any ad-hoc nameserver (via `at`). Supports DNS, DoT, DoH, and DoQ. When `server_id` or \
    `public_resolver` is given, transport selection follows `transports` / `all_transports`; \
    otherwise the scheme on `at` chooses, or the system resolver is used. Returns the same JSON \
    shape as `dns query --json` — a `results` array with one entry per transport queried."
    )]
    async fn dns_resolve(
        &self,
        Parameters(p): Parameters<ResolveParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_resolve", "MCP tool invoked");
        resolve_tools::handle_resolve(&self.config, &self.cli_access, &self.cli_allow_zone, p).await
    }
}

// ─── ServerHandler ────────────────────────────────────────────────────────────

#[tool_handler]
impl ServerHandler for DnsServer {
    /// Builds the ServerInfo metadata describing this DNS MCP server.
    ///
    /// The returned `ServerInfo` contains the protocol version, enabled capabilities,
    /// human-facing instructions (including the server's startup info), and implementation
    /// metadata with the implementation name set to `"dns"`.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use std::sync::Arc;
    ///
    /// // Construct a server (example uses default/empty inputs for brevity).
    /// let config = AppConfig::default();
    /// let server = DnsServer::new(config, Vec::new(), Vec::new());
    /// let info = server.get_info();
    /// assert_eq!(info.server_info.name, "dns");
    /// ```
    fn get_info(&self) -> ServerInfo {
        let base = "MCP server for DNS management. Manages zones, records, cache, stats, \
                    and block/allow lists. Confirm before calling any destructive tool.";

        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::V_2024_11_05;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.instructions = Some(format!("{base}{}", self.startup_info));

        let mut impl_info = Implementation::from_build_env();
        impl_info.name = "dns".into();
        info.server_info = impl_info;

        info
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::config::AppConfig;

    fn make_server(config: AppConfig) -> DnsServer {
        DnsServer::new(config, vec![], vec![])
    }

    #[tokio::test]
    async fn dns_get_config_returns_toml() {
        let config: AppConfig = toml::from_str(
            r#"
            [[servers]]
            id = "primary"
            vendor = "technitium"
            token = "supersecret"
            "#,
        )
        .unwrap();
        let server = make_server(config);
        let result = server.dns_get_config().await.unwrap();
        assert!(!result.is_error.unwrap_or(false));
        let text = result.content[0]
            .as_text()
            .expect("expected text content")
            .text
            .clone();
        // Must be parseable TOML
        let parsed: toml::Value = toml::from_str(&text).expect("output should be valid TOML");
        // Token must be redacted
        let token = parsed["servers"][0]["token"].as_str().unwrap();
        assert_eq!(token, "[redacted]");
    }

    #[tokio::test]
    async fn dns_get_config_preserves_token_env() {
        let config: AppConfig = toml::from_str(
            r#"
            [[servers]]
            id = "primary"
            vendor = "technitium"
            token_env = "MY_DNS_TOKEN"
            "#,
        )
        .unwrap();
        let server = make_server(config);
        let result = server.dns_get_config().await.unwrap();
        assert!(!result.is_error.unwrap_or(false));
        let text = result.content[0]
            .as_text()
            .expect("expected text content")
            .text
            .clone();
        let parsed: toml::Value = toml::from_str(&text).expect("output should be valid TOML");
        // token_env should be preserved as-is
        let token_env = parsed["servers"][0]["token_env"].as_str().unwrap();
        assert_eq!(token_env, "MY_DNS_TOKEN");
        // token key should not appear (was None)
        assert!(parsed["servers"][0].get("token").is_none());
    }
}
