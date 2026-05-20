use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    tool, tool_handler, tool_router,
};

use crate::control_plane::policy::Policy;
use crate::core::dns::service::{DnsService, ListRecordsOptions};
use crate::core::error::Error;
use crate::mcp::helpers::{json_result, mcp_err, text_result};
use crate::mcp::params::{
    AddRecordParams, CreateZoneParams, DeleteRecordParams, DomainParams, ExportZoneFileParams,
    ImportZoneFileParams, ListRecordsParams, ListZonesParams, StatsParams, ZoneParams,
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
        self.client
            .list_zones(p.page_number.unwrap_or(1), p.zones_per_page.unwrap_or(50))
            .await
            .map(json_result)
            .map_err(mcp_err)
    }

    #[tool(description = "Create a new DNS zone. Types: Primary, Secondary, Stub, Forwarder.")]
    async fn dns_create_zone(
        &self,
        Parameters(p): Parameters<CreateZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_create_zone", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, "tool invoked");
        self.policy.check_write().map_err(mcp_err)?;
        self.policy.check_zone(&p.zone).map_err(mcp_err)?;
        self.client
            .create_zone(&p.zone, &p.zone_type)
            .await
            .map(json_result)
            .map_err(mcp_err)
    }

    #[tool(description = "Delete a DNS zone. This is destructive and cannot be undone.")]
    async fn dns_delete_zone(
        &self,
        Parameters(p): Parameters<ZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_delete_zone", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, "tool invoked");
        self.policy.check_write().map_err(mcp_err)?;
        self.policy.check_zone(&p.zone).map_err(mcp_err)?;
        self.client
            .delete_zone(&p.zone)
            .await
            .map(json_result)
            .map_err(mcp_err)
    }

    #[tool(description = "Enable a previously disabled DNS zone.")]
    async fn dns_enable_zone(
        &self,
        Parameters(p): Parameters<ZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_enable_zone", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, "tool invoked");
        self.policy.check_write().map_err(mcp_err)?;
        self.policy.check_zone(&p.zone).map_err(mcp_err)?;
        self.client
            .enable_zone(&p.zone)
            .await
            .map(json_result)
            .map_err(mcp_err)
    }

    #[tool(description = "Disable a DNS zone so it stops responding to queries.")]
    async fn dns_disable_zone(
        &self,
        Parameters(p): Parameters<ZoneParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_disable_zone", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, "tool invoked");
        self.policy.check_write().map_err(mcp_err)?;
        self.policy.check_zone(&p.zone).map_err(mcp_err)?;
        self.client
            .disable_zone(&p.zone)
            .await
            .map(json_result)
            .map_err(mcp_err)
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
        self.policy.check_write().map_err(mcp_err)?;
        self.policy.check_zone(&p.zone).map_err(mcp_err)?;
        let file_name = p.file_name.unwrap_or_else(|| format!("{}.txt", p.zone));
        self.client
            .import_zone_file(
                &p.zone,
                file_name,
                p.content.into_bytes(),
                p.overwrite.unwrap_or(true),
                p.overwrite_zone.unwrap_or(false),
                p.overwrite_soa_serial.unwrap_or(false),
            )
            .await
            .map(json_result)
            .map_err(mcp_err)
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
        self.policy.check_zone(&p.zone).map_err(mcp_err)?;
        self.client
            .export_zone_file(&p.zone)
            .await
            .map(text_result)
            .map_err(mcp_err)
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
        self.policy
            .check_zone(p.zone.as_deref().unwrap_or(&p.domain))
            .map_err(mcp_err)?;
        self.client
            .list_records(
                &p.domain,
                p.zone.as_deref(),
                ListRecordsOptions {
                    use_local_ip: p.use_local_ip.unwrap_or(false),
                    all_subdomains: false,
                },
            )
            .await
            .and_then(|r| serde_json::to_value(&r).map_err(|e| Error::parse(e.to_string())))
            .map(json_result)
            .map_err(mcp_err)
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
        self.policy.check_write().map_err(mcp_err)?;
        self.policy.check_zone(&p.zone).map_err(mcp_err)?;
        self.client
            .add_record(&p.zone, &p.domain, p.ttl.unwrap_or(3600), &p.record)
            .await
            .map(json_result)
            .map_err(mcp_err)
    }

    #[tool(
        description = "Delete DNS record(s). Only `type` is required — omitting value fields \
        deletes ALL records of that type for the domain. \
        e.g. {\"type\":\"A\"} deletes all A records; {\"type\":\"A\",\"ipAddress\":\"1.2.3.4\"} deletes one specific record."
    )]
    async fn dns_delete_record(
        &self,
        Parameters(p): Parameters<DeleteRecordParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_delete_record", "MCP tool invoked");
        tracing::debug!(zone = %p.zone, domain = %p.domain, "tool invoked");
        self.policy.check_write().map_err(mcp_err)?;
        self.policy.check_zone(&p.zone).map_err(mcp_err)?;
        let type_params = p.record.to_api_params();
        self.client
            .delete_record(&p.zone, &p.domain, &type_params)
            .await
            .map(json_result)
            .map_err(mcp_err)
    }

    // ── Cache ─────────────────────────────────────────────────────────────

    #[tool(description = "Browse the DNS cache. Pass an empty string for domain to list the root.")]
    async fn dns_list_cache(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_list_cache", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
        self.client
            .list_cache(&p.domain)
            .await
            .map(json_result)
            .map_err(mcp_err)
    }

    #[tool(description = "Evict a specific domain from the DNS cache.")]
    async fn dns_delete_cache_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_delete_cache_zone", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
        self.policy.check_write().map_err(mcp_err)?;
        self.client
            .delete_cache_zone(&p.domain)
            .await
            .map(json_result)
            .map_err(mcp_err)
    }

    #[tool(description = "Flush the entire DNS cache, forcing all records to be resolved fresh.")]
    async fn dns_flush_cache(&self) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_flush_cache", "MCP tool invoked");
        self.policy.check_write().map_err(mcp_err)?;
        self.client
            .flush_cache()
            .await
            .map(json_result)
            .map_err(mcp_err)
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
        self.client
            .get_stats(p.stats_type.as_deref().unwrap_or("LastDay"))
            .await
            .map(json_result)
            .map_err(mcp_err)
    }

    // ── Blocked ───────────────────────────────────────────────────────────

    #[tool(description = "List all manually blocked domains.")]
    async fn dns_list_blocked_zones(&self) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_list_blocked_zones", "MCP tool invoked");
        self.client
            .list_blocked()
            .await
            .map(json_result)
            .map_err(mcp_err)
    }

    #[tool(description = "Block a domain, causing the DNS server to refuse to resolve it.")]
    async fn dns_add_blocked_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_add_blocked_zone", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
        self.policy.check_write().map_err(mcp_err)?;
        self.client
            .add_blocked(&p.domain)
            .await
            .map(json_result)
            .map_err(mcp_err)
    }

    #[tool(description = "Unblock a domain.")]
    async fn dns_delete_blocked_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_delete_blocked_zone", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
        self.policy.check_write().map_err(mcp_err)?;
        self.client
            .delete_blocked(&p.domain)
            .await
            .map(json_result)
            .map_err(mcp_err)
    }

    // ── Allowed ───────────────────────────────────────────────────────────

    #[tool(description = "List all whitelisted domains.")]
    async fn dns_list_allowed_zones(&self) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_list_allowed_zones", "MCP tool invoked");
        self.client
            .list_allowed()
            .await
            .map(json_result)
            .map_err(mcp_err)
    }

    #[tool(description = "Whitelist a domain, allowing it even if it appears on a block list.")]
    async fn dns_add_allowed_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_add_allowed_zone", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
        self.policy.check_write().map_err(mcp_err)?;
        self.client
            .add_allowed(&p.domain)
            .await
            .map(json_result)
            .map_err(mcp_err)
    }

    #[tool(description = "Remove a domain from the whitelist.")]
    async fn dns_delete_allowed_zone(
        &self,
        Parameters(p): Parameters<DomainParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_delete_allowed_zone", "MCP tool invoked");
        tracing::debug!(domain = %p.domain, "tool invoked");
        self.policy.check_write().map_err(mcp_err)?;
        self.client
            .delete_allowed(&p.domain)
            .await
            .map(json_result)
            .map_err(mcp_err)
    }

    // ── Settings ──────────────────────────────────────────────────────────

    #[tool(description = "Get the current Technitium DNS server configuration.")]
    async fn dns_get_settings(&self) -> Result<CallToolResult, McpError> {
        tracing::info!(tool = "dns_get_settings", "MCP tool invoked");
        self.client
            .get_settings()
            .await
            .map(json_result)
            .map_err(mcp_err)
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
