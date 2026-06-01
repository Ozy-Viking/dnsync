//! Tests for `cli::query`, split by area.

pub(crate) use super::*;
pub(crate) use crate::cli::{Cli, Command};
pub(crate) use clap::Parser;
pub(crate) use hickory_resolver::proto::rr::{Name, RData, Record};
pub(crate) use rstest::rstest;
pub(crate) use std::str::FromStr;

mod output;
mod parsing;
mod planning;

fn parse(args: &[&str]) -> Result<QueryArgs> {
    let mut argv = vec!["dns", "query"];
    argv.extend_from_slice(args);
    let cli = Cli::try_parse_from(argv).map_err(|e| Error::parse(e.to_string()))?;
    match cli.command {
        Command::Query(q) => Ok(q),
        _ => Err(Error::parse("expected Command::Query")),
    }
}

fn server_with_dns_and_doq() -> DnsServerConfig {
    use crate::control_plane::config::{
        DnsTransportConfig, DoqTransportConfig, McpPermissions, VendorKind,
    };
    DnsServerConfig {
        id: "dns1".to_string(),
        vendor: VendorKind::Technitium,
        location: None,
        base_url: None,
        base_url_env: None,
        token: None,
        token_env: None,
        org_id: None,
        cluster: None,
        dns: Some(DnsTransportConfig {
            enabled: true,
            addr: Some("10.5.0.53:53".to_string()),
            timeout_ms: None,
        }),
        dot: None,
        doh: None,
        doq: Some(DoqTransportConfig {
            enabled: true,
            addr: Some("10.5.0.53:853".to_string()),
            server_name: Some("dns1.hankin.io".to_string()),
            timeout_ms: None,
        }),
        mcp: McpPermissions::default(),
        validation_endpoints: Vec::new(),
    }
}

fn result_block(server_id: &str) -> QueryResultBlock {
    QueryResultBlock {
        target_label: format!("{server_id}-addr"),
        server_id: Some(server_id.to_string()),
        server_vendor: Some(VendorKind::Technitium),
        transport: ValidationTransport::Dns,
        extras: Vec::new(),
        url: None,
        host_for_json: Some("10.5.0.53".to_string()),
        port_for_json: Some(53),
        elapsed: Duration::ZERO,
        status: QueryStatus::NoError,
        records: vec![ObservedRecord {
            name: "huly.hankin.io.".to_string(),
            record_type: "A".to_string(),
            ttl: Some(300),
            values: vec!["10.5.0.42".to_string()],
        }],
        asked_types: vec!["A".to_string()],
        queried_name: "huly.hankin.io".to_string(),
    }
}

fn test_record(name: &str, ttl: u32, rr_type: RecordType, rdata_text: &str) -> Record {
    Record::from_rdata(
        Name::from_str(name).unwrap(),
        ttl,
        RData::try_from_str(rr_type, rdata_text).unwrap(),
    )
}
