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
    },
    mcp::{
        helpers::mcp_err,
        params::*,
        tools::{
            access_lists, cache as cache_tools, records as record_tools,
            settings as settings_tools, stats as stats_tools, zones as zone_tools,
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
    pub fn new(config: AppConfig, cli_access: Vec<PolicyRule>, cli_allow_zone: Vec<String>) -> Self {
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

    fn resolve_server(&self, server_id: &str) -> crate::core::error::Result<(VendorClient, Policy)> {
        let server = self.config.selected_server(Some(server_id))?;
        let client = VendorClient::from_server(server)?;
        let policy = Policy::for_server(server, &self.cli_access, &self.cli_allow_zone)?;
        Ok((client, policy))
    }
}

// ─── Tools ───────────────────────────────────────────────────────────────────

#[tool_router]
impl DnsServer {
    // ── Server management ─────────────────────────────────────────────────

    #[tool(
        description = "List all DNS servers defined in the config file. \
        Shows each server's ID, vendor, and base URL. \
        Call this first to discover server IDs — pass `server_id` to every other tool."
    )]
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

    // ── Zones ─────────────────────────────────────────────────────────────

    #[tool(description = "List all authoritative zones hosted on the DNS server. \
        Use `server_id` from dns_list_servers.")]
    async fn dns_list_zones(
        &self,
        Parameters(p): Parameters<ListZonesParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_list_zones", "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        zone_tools::handle_list_zones(&client, &policy, p).await
    }

    #[tool(description = "Create a new DNS zone. Types: Primary, Secondary, Stub, Forwarder. \
        Use `server_id` from dns_list_servers.")]
    async fn dns_create_zone(
        &self,
        Parameters(p): Parameters<CreateZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_create_zone", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, "tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        zone_tools::handle_create_zone(&client, &policy, p).await
    }

    #[tool(description = "Delete a DNS zone. This is destructive and cannot be undone. \
        Use `server_id` from dns_list_servers.")]
    async fn dns_delete_zone(
        &self,
        Parameters(p): Parameters<ZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_delete_zone", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, "tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        zone_tools::handle_delete_zone(&client, &policy, p).await
    }

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

    // ── Records ───────────────────────────────────────────────────────────

    #[tool(
        description = "List all DNS records for a domain. Returns typed records including writable types (A, AAAA, MX, etc.) and read-only DNSSEC types (DNSKEY, RRSIG, NSEC, NSEC3). \
        Use `server_id` from dns_list_servers."
    )]
    async fn dns_list_records(
        &self,
        Parameters(p): Parameters<ListRecordsParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_list_records", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, zone = ?p.zone, "tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        record_tools::handle_list_records(&client, &policy, p).await
    }

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

    #[tool(description = "Browse the DNS cache. Pass an empty string for domain to list the root. \
        Use `server_id` from dns_list_servers.")]
    async fn dns_list_cache(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_list_cache", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        cache_tools::handle_list_cache(&client, &policy, p).await
    }

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

    #[tool(description = "Flush the entire DNS cache, forcing all records to be resolved fresh. \
        Use `server_id` from dns_list_servers.")]
    async fn dns_flush_cache(
        &self,
        Parameters(p): Parameters<ServerScopeParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_flush_cache", "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        cache_tools::handle_flush_cache(&client, &policy).await
    }

    // ── Stats ─────────────────────────────────────────────────────────────

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

    #[tool(description = "Block a domain, causing the DNS server to refuse to resolve it. \
        Use `server_id` from dns_list_servers.")]
    async fn dns_add_blocked_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_add_blocked_zone", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        access_lists::handle_add_blocked(&client, &policy, p).await
    }

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

    #[tool(description = "Whitelist a domain, allowing it even if it appears on a block list. \
        Use `server_id` from dns_list_servers.")]
    async fn dns_add_allowed_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_add_allowed_zone", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        access_lists::handle_add_allowed(&client, &policy, p).await
    }

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

    #[tool(description = "Get the current DNS server configuration. \
        Use `server_id` from dns_list_servers.")]
    async fn dns_get_settings(
        &self,
        Parameters(p): Parameters<ServerScopeParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_get_settings", "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        settings_tools::handle_get_settings(&client, &policy).await
    }
}

// ─── ServerHandler ────────────────────────────────────────────────────────────

#[tool_handler]
impl ServerHandler for DnsServer {
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
