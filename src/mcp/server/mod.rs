//! MCP stdio server.
//!
//! Defines `DnsServer` and its `ServerHandler`/tool surface. The ~30 tool
//! handlers are grouped by resource into submodules, each contributing a named
//! `ToolRouter` that is combined in [`DnsServer::tool_router`].

mod access;
mod cache;
mod observe;
mod records;
mod server;
mod settings;
mod zones;

// Shared imports, re-exported so the tool submodules can pull them in via `use super::*;`.
pub(crate) use std::sync::Arc;

pub(crate) use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    tool, tool_handler, tool_router,
};

pub(crate) use crate::{
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
    /// ```rust,ignore
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

        let result = Self {
            config: Arc::new(config),
            cli_access: Arc::new(cli_access),
            cli_allow_zone: Arc::new(cli_allow_zone),
            startup_info,
            tool_router: Self::tool_router(),
        };
        tracing::debug!(
            server_count = result.config.servers.len(),
            "MCP server initialised"
        );
        result
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
    /// ```rust,ignore
    /// # use std::sync::Arc;
    /// # use crate::mcp::server::DnsServer;
    /// # use crate::config::AppConfig;
    /// // Given a DnsServer `srv` and a server id:
    /// // let srv = DnsServer::new(app_config, vec![], vec![]);
    /// // let (client, policy) = srv.resolve_server("primary")?;
    /// ```
    #[tracing::instrument(level = "debug", skip(self), fields(server_id))]
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
        tracing::trace!(server_id, vendor = ?server.vendor, "server resolved");
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
/// Start the MCP server over stdio and block until the transport closes.
///
/// Owns the `rmcp` serving lifecycle so callers (e.g. the CLI dispatcher) never
/// need to depend on `rmcp` directly.
#[tracing::instrument(level = "debug", skip(config, access, allow_zone), fields(server_count = config.servers.len()))]
pub async fn serve_stdio(
    config: AppConfig,
    access: Vec<PolicyRule>,
    allow_zone: Vec<String>,
) -> crate::core::error::Result<()> {
    use crate::core::error::Error;

    tracing::info!("Starting MCP server (stdio)");
    let dns_server = DnsServer::new(config, access, allow_zone);
    let transport = (tokio::io::stdin(), tokio::io::stdout());
    let service = dns_server
        .serve(transport)
        .await
        .map_err(|e| Error::mcp(format!("failed to start MCP server: {e}")))?;
    service
        .waiting()
        .await
        .map_err(|e| Error::mcp(format!("MCP transport error: {e}")))?;
    Ok(())
}

impl DnsServer {
    /// Combine the per-resource tool routers into the full server router.
    pub(crate) fn tool_router() -> ToolRouter<Self> {
        Self::server_router()
            + Self::zones_router()
            + Self::records_router()
            + Self::cache_router()
            + Self::access_router()
            + Self::settings_router()
            + Self::observe_router()
    }
}
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
    /// ```rust,ignore
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
mod tests;
