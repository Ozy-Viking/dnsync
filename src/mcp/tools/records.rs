use rmcp::{ErrorData as McpError, model::*};

use crate::{
    control_plane::policy::Policy,
    core::dns::records,
    core::{dns::service::DnsService, error::Error},
    mcp::{helpers::run_json, params::*},
};

pub async fn handle_list_records<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ListRecordsParams,
) -> Result<CallToolResult, McpError> {
    let zone_check = p
        .zone
        .as_deref()
        .or(p.domain.as_deref())
        .map_or(Ok(()), |zone| policy.check_zone(zone));
    Ok(run_json(
        "dns_list_records",
        policy.check_read().and(zone_check),
        async move {
            records::query::list_records_for_query(
                client,
                p.domain.as_deref(),
                p.zone.as_deref(),
                p.all_subdomains.unwrap_or(false),
                p.use_local_ip.unwrap_or(false),
            )
            .await
            .and_then(|r| serde_json::to_value(&r).map_err(|e| Error::parse(e.to_string())))
        },
    )
    .await)
}

pub async fn handle_add_record<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: AddRecordParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_add_record",
        policy.check_write().and(policy.check_zone(&p.zone)),
        records::create_record(client, &p.zone, &p.domain, p.ttl.unwrap_or(3600), &p.record),
    )
    .await)
}

/// Deletes a DNS record in the specified zone using the given DNS service and policy.
///
/// The operation enforces delete permission and zone authorization via the provided `Policy`.
///
/// # Returns
///
/// `CallToolResult` describing the outcome of the delete operation; `is_error == Some(true)` if the operation failed.
///
/// # Examples
///
/// ```ignore
/// # use crate::mcp::params::DeleteRecordParams;
/// # use crate::mcp::tools::records::handle_delete_record;
/// # async fn example<C: crate::dns::DnsService + Send + Sync>(client: &C, policy: &crate::Policy) {
/// let params = DeleteRecordParams {
///     server_id: "s".to_string(),
///     zone: "example.com".to_string(),
///     domain: "www.example.com".to_string(),
///     record: /* record descriptor */ Default::default(),
/// };
/// let result = handle_delete_record(client, policy, params).await.unwrap();
/// # }
/// ```
pub async fn handle_delete_record<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: DeleteRecordParams,
) -> Result<CallToolResult, McpError> {
    let type_params = p.record.to_api_params();
    Ok(run_json(
        "dns_delete_record",
        policy.check_delete().and(policy.check_zone(&p.zone)),
        records::delete_record(client, &p.zone, &p.domain, &type_params),
    )
    .await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::policy::{Policy, PolicyRule};
    use crate::mcp::tools::test_support::FakeService;
    use serde_json::json;

    /// Constructs a `ListRecordsParams` configured for tests using the
    /// `example.com` zone and `www.example.com` domain.
    ///
    /// # Returns
    ///
    /// A `ListRecordsParams` with `server_id` set to `"s"`, `domain` set to
    /// `Some("www.example.com")`, `zone` set to `Some("example.com")`, and
    /// `all_subdomains` and `use_local_ip` set to `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// let p = list_params();
    /// assert_eq!(p.server_id, "s");
    /// assert_eq!(p.domain.as_deref(), Some("www.example.com"));
    /// assert_eq!(p.zone.as_deref(), Some("example.com"));
    /// assert!(p.all_subdomains.is_none());
    /// assert!(p.use_local_ip.is_none());
    /// ```
    fn list_params() -> ListRecordsParams {
        ListRecordsParams {
            server_id: "s".into(),
            domain: Some("www.example.com".into()),
            zone: Some("example.com".into()),
            all_subdomains: None,
            use_local_ip: None,
        }
    }

    #[tokio::test]
    async fn list_records_requires_read() {
        let policy = Policy::new([PolicyRule::Write], None);
        let res = handle_list_records(&FakeService, &policy, list_params())
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(true));
        assert!(
            res.content[0]
                .as_text()
                .unwrap()
                .text
                .contains("does not permit read")
        );
    }

    #[tokio::test]
    async fn list_records_succeeds_with_read() {
        let policy = Policy::new([PolicyRule::Read], None);
        let res = handle_list_records(&FakeService, &policy, list_params())
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(false));
    }

    #[tokio::test]
    async fn add_record_requires_write() {
        let policy = Policy::new([PolicyRule::Read], None);
        let p: AddRecordParams = serde_json::from_value(json!({
            "server_id": "s", "zone": "example.com", "domain": "www.example.com",
            "record": {"type": "A", "ipAddress": "1.2.3.4"},
        }))
        .unwrap();
        let res = handle_add_record(&FakeService, &policy, p).await.unwrap();
        assert_eq!(res.is_error, Some(true));
        assert!(
            res.content[0]
                .as_text()
                .unwrap()
                .text
                .contains("does not permit write")
        );
    }

    #[tokio::test]
    async fn add_record_succeeds_with_write() {
        let policy = Policy::new([PolicyRule::Write], None);
        let p: AddRecordParams = serde_json::from_value(json!({
            "server_id": "s", "zone": "example.com", "domain": "www.example.com",
            "record": {"type": "A", "ipAddress": "1.2.3.4"},
        }))
        .unwrap();
        let res = handle_add_record(&FakeService, &policy, p).await.unwrap();
        assert_eq!(res.is_error, Some(false));
    }

    #[tokio::test]
    async fn add_record_rejected_for_disallowed_zone() {
        // Write is permitted, but the zone is outside the allow-list.
        let policy = Policy::new([PolicyRule::Write], Some(vec!["other.com".into()]));
        let p: AddRecordParams = serde_json::from_value(json!({
            "server_id": "s", "zone": "example.com", "domain": "www.example.com",
            "record": {"type": "A", "ipAddress": "1.2.3.4"},
        }))
        .unwrap();
        let res = handle_add_record(&FakeService, &policy, p).await.unwrap();
        assert_eq!(res.is_error, Some(true));
    }

    #[tokio::test]
    async fn delete_record_requires_delete() {
        let policy = Policy::new([PolicyRule::Write], None);
        let p: DeleteRecordParams = serde_json::from_value(json!({
            "server_id": "s", "zone": "example.com", "domain": "www.example.com",
            "record": {"type": "A"},
        }))
        .unwrap();
        let res = handle_delete_record(&FakeService, &policy, p)
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(true));
        assert!(
            res.content[0]
                .as_text()
                .unwrap()
                .text
                .contains("does not permit delete")
        );
    }

    #[tokio::test]
    async fn delete_record_succeeds_with_delete() {
        let policy = Policy::new([PolicyRule::Delete], None);
        let p: DeleteRecordParams = serde_json::from_value(json!({
            "server_id": "s", "zone": "example.com", "domain": "www.example.com",
            "record": {"type": "A"},
        }))
        .unwrap();
        let res = handle_delete_record(&FakeService, &policy, p)
            .await
            .unwrap();
        assert_eq!(res.is_error, Some(false));
    }
}
