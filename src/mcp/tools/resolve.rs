//! `dns_resolve` MCP tool — the MCP-side of the `dns query` subcommand.
//!
//! Maintains CLI/MCP parity (agents.md §"CLI and MCP capability must
//! stay in parity"): both surfaces share the same `execute_query`
//! engine and return identical JSON shapes.

use rmcp::{ErrorData as McpError, model::*};

use crate::{
    cli::query::{QueryArgs, execute_query},
    control_plane::{
        app::select_query_servers,
        config::AppConfig,
        policy::{Policy, PolicyRule},
    },
    core::error::Error,
    mcp::{helpers::mcp_err, params::ResolveParams},
};

pub async fn handle_resolve(
    config: &AppConfig,
    cli_access: &[PolicyRule],
    cli_allow_zone: &[String],
    p: ResolveParams,
) -> Result<CallToolResult, McpError> {
    tracing::info!(tool = "dns_resolve", "MCP tool invoked");

    // When the request targets configured `[[servers]]` entries (or a
    // cluster), gate each resolved server on its MCP read permission.
    // Ad-hoc and system resolver paths are not vendor-API operations and
    // aren't covered by per-server access controls; they pass through.
    let requested_servers = effective_server_ids(&p);
    if !requested_servers.is_empty() {
        let servers =
            select_query_servers(config, &requested_servers, false).map_err(mcp_err)?;
        for server in servers {
            let policy = Policy::for_server(server, cli_access, cli_allow_zone).map_err(mcp_err)?;
            policy.check_read().map_err(mcp_err)?;
        }
    }

    let args = params_to_args(p).map_err(mcp_err)?;
    let outcome = execute_query(Some(config.clone()), args)
        .await
        .map_err(mcp_err)?;

    Ok(crate::mcp::helpers::json_result(outcome.to_json()))
}

/// The effective list of server/cluster identifiers a request targets:
/// `server_ids` when provided, otherwise the single `server_id`.
fn effective_server_ids(p: &ResolveParams) -> Vec<String> {
    if let Some(ids) = &p.server_ids {
        ids.clone()
    } else {
        p.server_id.clone().into_iter().collect()
    }
}

fn params_to_args(p: ResolveParams) -> Result<QueryArgs, Error> {
    let server = effective_server_ids(&p);
    let transports = p.transports.unwrap_or_default();
    let mut args = QueryArgs {
        targets: vec![p.domain],
        r#type: p.types.unwrap_or_default(),
        server,
        at: p.at,
        port: p.port,
        tls_server_name: p.tls_server_name,
        timeout: p.timeout_ms,
        all_transports: p.all_transports.unwrap_or(false),
        chase: p.chase.unwrap_or(false),
        json: true,
        ..Default::default()
    };
    for transport in transports {
        match transport.to_ascii_lowercase().as_str() {
            "dns" => args.dns = true,
            "dot" => args.dot = true,
            "doh" => args.doh = true,
            "doq" => args.doq = true,
            other => {
                return Err(Error::parse(format!(
                    "unknown transport '{other}' in `transports`; expected one of dns/dot/doh/doq",
                )));
            }
        }
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_to_args_maps_transport_strings() {
        let p = ResolveParams {
            domain: "example.com".into(),
            types: Some(vec!["A".into(), "AAAA".into()]),
            server_id: Some("dns1".into()),
            server_ids: None,
            at: None,
            transports: Some(vec!["dot".into(), "doh".into()]),
            all_transports: None,
            port: None,
            tls_server_name: None,
            timeout_ms: Some(1500),
            chase: None,
        };
        let args = params_to_args(p).unwrap();
        assert_eq!(args.targets, vec!["example.com".to_string()]);
        assert_eq!(args.r#type, vec!["A".to_string(), "AAAA".to_string()]);
        assert_eq!(args.server, vec!["dns1".to_string()]);
        assert!(args.dot);
        assert!(args.doh);
        assert!(!args.dns);
        assert!(!args.doq);
        assert!(!args.all_transports);
        assert_eq!(args.timeout, Some(1500));
        // MCP always emits JSON
        assert!(args.json);
    }

    #[test]
    fn params_to_args_server_ids_take_precedence_over_server_id() {
        let p = ResolveParams {
            domain: "example.com".into(),
            types: None,
            server_id: Some("ignored".into()),
            server_ids: Some(vec!["a".into(), "b".into()]),
            at: None,
            transports: None,
            all_transports: None,
            port: None,
            tls_server_name: None,
            timeout_ms: None,
            chase: None,
        };
        let args = params_to_args(p).unwrap();
        assert_eq!(args.server, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn params_to_args_falls_back_to_single_server_id() {
        let p = ResolveParams {
            domain: "example.com".into(),
            types: None,
            server_id: Some("only".into()),
            server_ids: None,
            at: None,
            transports: None,
            all_transports: None,
            port: None,
            tls_server_name: None,
            timeout_ms: None,
            chase: None,
        };
        let args = params_to_args(p).unwrap();
        assert_eq!(args.server, vec!["only".to_string()]);
    }

    #[test]
    fn params_to_args_all_transports() {
        let p = ResolveParams {
            domain: "example.com".into(),
            types: None,
            server_id: Some("dns1".into()),
            server_ids: None,
            at: None,
            transports: None,
            all_transports: Some(true),
            port: None,
            tls_server_name: None,
            timeout_ms: None,
            chase: None,
        };
        let args = params_to_args(p).unwrap();
        assert!(args.all_transports);
    }

    #[test]
    fn params_to_args_rejects_unknown_transport() {
        let p = ResolveParams {
            domain: "example.com".into(),
            types: None,
            server_id: None,
            server_ids: None,
            at: Some("1.1.1.1".into()),
            transports: Some(vec!["smtp".into()]),
            all_transports: None,
            port: None,
            tls_server_name: None,
            timeout_ms: None,
            chase: None,
        };
        assert!(params_to_args(p).is_err());
    }
}
