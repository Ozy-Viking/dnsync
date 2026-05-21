use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    tool, tool_handler, tool_router,
};

use crate::{
    control_plane::policy::Policy,
    core::dns::service::DnsService,
    mcp::{
        params::*,
        tools::{access_lists, cache as cache_tools, records as record_tools, settings as settings_tools, stats as stats_tools, zones as zone_tools},
    },
};

// ─── Server state ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct DnsServer<C> {
    client: C,
    policy: Policy,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

// ─── Tools ───────────────────────────────────────────────────────────────────

#[tool_router]
impl<C: DnsService + Clone + Send + Sync + 'static> DnsServer<C> {
    pub fn new(client: C, policy: Policy) -> Self {
        Self {
            client,
            policy,
            tool_router: Self::tool_router(),
        }
    }

    // ── Zones ─────────────────────────────────────────────────────────────

    #[tool(description = "List all authoritative zones hosted on the Technitium DNS server.")]
    async fn dns_list_zones(
        &self,
        Parameters(p): Parameters<ListZonesParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_list_zones", "MCP tool invoked");
        zone_tools::handle_list_zones(&self.client, p).await
    }

    #[tool(description = "Create a new DNS zone. Types: Primary, Secondary, Stub, Forwarder.")]
    async fn dns_create_zone(
        &self,
        Parameters(p): Parameters<CreateZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_create_zone", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, "tool invoked");
        zone_tools::handle_create_zone(&self.client, &self.policy, p).await
    }

    #[tool(description = "Delete a DNS zone. This is destructive and cannot be undone.")]
    async fn dns_delete_zone(
        &self,
        Parameters(p): Parameters<ZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_delete_zone", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, "tool invoked");
        zone_tools::handle_delete_zone(&self.client, &self.policy, p).await
    }

    #[tool(description = "Enable a previously disabled DNS zone.")]
    async fn dns_enable_zone(
        &self,
        Parameters(p): Parameters<ZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_enable_zone", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, "tool invoked");
        zone_tools::handle_enable_zone(&self.client, &self.policy, p).await
    }

    #[tool(description = "Disable a DNS zone so it stops responding to queries.")]
    async fn dns_disable_zone(
        &self,
        Parameters(p): Parameters<ZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_disable_zone", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, "tool invoked");
        zone_tools::handle_disable_zone(&self.client, &self.policy, p).await
    }

    #[tool(
        description = "Import a zone file (RFC 1035 format) into an existing zone. \
        Pass the full zone file text in `content`. Use `overwrite_zone: true` for a clean \
        replace that deletes all existing records first."
    )]
    async fn dns_import_zone_file(
        &self,
        Parameters(p): Parameters<ImportZoneFileParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_import_zone_file", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, "tool invoked");
        zone_tools::handle_import_zone_file(&self.client, &self.policy, p).await
    }

    #[tool(
        description = "Export a DNS zone as a BIND-format (RFC 1035) zone file. \
        Returns the full zone file text, which can be saved to disk or imported into another DNS provider."
    )]
    async fn dns_export_zone_file(
        &self,
        Parameters(p): Parameters<ExportZoneFileParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_export_zone_file", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, "tool invoked");
        zone_tools::handle_export_zone_file(&self.client, &self.policy, p).await
    }

    // ── Records ───────────────────────────────────────────────────────────

    #[tool(
        description = "List all DNS records for a domain. Returns typed records including writable types (A, AAAA, MX, etc.) and read-only DNSSEC types (DNSKEY, RRSIG, NSEC, NSEC3)."
    )]
    async fn dns_list_records(
        &self,
        Parameters(p): Parameters<ListRecordsParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_list_records", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, zone = ?p.zone, "tool invoked");
        record_tools::handle_list_records(&self.client, &self.policy, p).await
    }

    #[tool(
        description = "Add a DNS record. The `record` field is a typed union: {\"type\":\"A\",\"ip\":\"1.2.3.4\"}, {\"type\":\"MX\",\"exchange\":\"mail.example.com\",\"preference\":10}, {\"type\":\"TXT\",\"text\":\"...\"}, etc."
    )]
    async fn dns_add_record(
        &self,
        Parameters(p): Parameters<AddRecordParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_add_record", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, domain = %p.domain, "tool invoked");
        record_tools::handle_add_record(&self.client, &self.policy, p).await
    }

    #[tool(
        description = "Delete DNS record(s). Only `type` is required \u{2014} omitting value fields \
        deletes ALL records of that type for the domain. \
        e.g. {\"type\":\"A\"} deletes all A records; {\"type\":\"A\",\"ipAddress\":\"1.2.3.4\"} deletes one specific record."
    )]
    async fn dns_delete_record(
        &self,
        Parameters(p): Parameters<DeleteRecordParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_delete_record", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, domain = %p.domain, "tool invoked");
        record_tools::handle_delete_record(&self.client, &self.policy, p).await
    }

    // ── Cache ─────────────────────────────────────────────────────────────

    #[tool(description = "Browse the DNS cache. Pass an empty string for domain to list the root.")]
    async fn dns_list_cache(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_list_cache", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
        cache_tools::handle_list_cache(&self.client, p).await
    }

    #[tool(description = "Evict a specific domain from the DNS cache.")]
    async fn dns_delete_cache_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_delete_cache_zone", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
        cache_tools::handle_delete_cache_zone(&self.client, &self.policy, p).await
    }

    #[tool(description = "Flush the entire DNS cache, forcing all records to be resolved fresh.")]
    async fn dns_flush_cache(&self) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_flush_cache", "MCP tool invoked");
        cache_tools::handle_flush_cache(&self.client, &self.policy).await
    }

    // ── Stats ─────────────────────────────────────────────────────────────

    #[tool(
        description = "Get dashboard statistics. stats_type: LastHour, LastDay, LastWeek, LastMonth, LastYear."
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
        stats_tools::handle_get_stats(&self.client, p).await
    }

    // ── Blocked ───────────────────────────────────────────────────────────

    #[tool(description = "List all manually blocked domains.")]
    async fn dns_list_blocked_zones(&self) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_list_blocked_zones", "MCP tool invoked");
        access_lists::handle_list_blocked(&self.client).await
    }

    #[tool(description = "Block a domain, causing the DNS server to refuse to resolve it.")]
    async fn dns_add_blocked_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_add_blocked_zone", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
        access_lists::handle_add_blocked(&self.client, &self.policy, p).await
    }

    #[tool(description = "Unblock a domain.")]
    async fn dns_delete_blocked_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_delete_blocked_zone", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
        access_lists::handle_delete_blocked(&self.client, &self.policy, p).await
    }

    // ── Allowed ───────────────────────────────────────────────────────────

    #[tool(description = "List all whitelisted domains.")]
    async fn dns_list_allowed_zones(&self) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_list_allowed_zones", "MCP tool invoked");
        access_lists::handle_list_allowed(&self.client).await
    }

    #[tool(description = "Whitelist a domain, allowing it even if it appears on a block list.")]
    async fn dns_add_allowed_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_add_allowed_zone", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
        access_lists::handle_add_allowed(&self.client, &self.policy, p).await
    }

    #[tool(description = "Remove a domain from the whitelist.")]
    async fn dns_delete_allowed_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_delete_allowed_zone", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
        access_lists::handle_delete_allowed(&self.client, &self.policy, p).await
    }

    // ── Settings ──────────────────────────────────────────────────────────

    #[tool(description = "Get the current Technitium DNS server configuration.")]
    async fn dns_get_settings(&self) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_get_settings", "MCP tool invoked");
        settings_tools::handle_get_settings(&self.client).await
    }
}

// ─── ServerHandler ────────────────────────────────────────────────────────────

#[tool_handler]
impl<C: DnsService + Clone + Send + Sync + 'static> ServerHandler for DnsServer<C> {
    fn get_info(&self) -> ServerInfo {
        let base = "MCP server for DNS management. Manages zones, records, cache, stats, \
                    and block/allow lists. Confirm before calling any destructive tool.";

        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::V_2024_11_05;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.instructions = Some(format!("{base}{}", self.policy.instructions_suffix()));

        // from_build_env() reads CARGO_PKG_NAME/VERSION; override name to "dns"
        let mut impl_info = Implementation::from_build_env();
        impl_info.name = "dns".into();
        info.server_info = impl_info;

        info
    }
}
