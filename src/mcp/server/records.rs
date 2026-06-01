//! MCP records tool handlers.

use super::*;

#[tool_router(router = records_router, vis = "pub(crate)")]
impl DnsServer {
    // ── Records ───────────────────────────────────────────────────────────

    /// List DNS records for a domain, returning typed records including writable and DNSSEC types.
    ///
    /// Returns a JSON result containing the domain's DNS records suitable for display and editing.
    /// The returned set includes writable record types (for example: `A`, `AAAA`, `MX`, etc.)
    /// and read-only DNSSEC records (`DNSKEY`, `RRSIG`, `NSEC`, `NSEC3`).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// // Example (pseudo): call the tool with a server_id and domain.
    /// // let srv = DnsServer::new(...);
    /// // let params = ListRecordsParams { server_id: "primary".into(), domain: "example.com".into(), zone: None };
    /// // let result = srv.dns_list_records(Parameters(params)).await?;
    /// ```
    #[tool(
        description = "List all DNS records for a domain. Returns typed records including writable types (A, AAAA, MX, etc.) and read-only DNSSEC types (DNSKEY, RRSIG, NSEC, NSEC3). \
    Use `server_id` from dns_list_servers."
    )]
    pub(crate) async fn dns_list_records(
        &self,
        Parameters(p): Parameters<ListRecordsParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_list_records", server_id = %p.server_id, domain = ?p.domain, zone = ?p.zone, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        record_tools::handle_list_records(&client, &policy, p).await
    }

    /// Adds a DNS record to a zone on the specified server.
    ///
    /// The operation applies the provided `record` (typed union: e.g. `A`, `MX`, `TXT`) to `zone`/`domain` on the server identified by `server_id`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
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
    pub(crate) async fn dns_add_record(
        &self,
        Parameters(p): Parameters<AddRecordParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_add_record", server_id = %p.server_id, zone = %p.zone, domain = %p.domain, "MCP tool invoked");
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
    /// ```rust,ignore
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
    pub(crate) async fn dns_delete_record(
        &self,
        Parameters(p): Parameters<DeleteRecordParams>,
    ) -> Result<CallToolResult, McpError> {
        tracing::debug!(tool = "dns_delete_record", server_id = %p.server_id, zone = %p.zone, domain = %p.domain, "MCP tool invoked");
        let (client, policy) = self.resolve_server(&p.server_id).map_err(mcp_err)?;
        record_tools::handle_delete_record(&client, &policy, p).await
    }
}
