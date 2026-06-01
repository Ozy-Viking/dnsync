//! stable JSON output shape.

use super::*;

#[derive(Serialize)]
pub(crate) struct JsonOutput<'a> {
    query: JsonQuery<'a>,
    target: JsonTarget<'a>,
    /// Flat results for the single-server, system, and ad-hoc cases
    /// (back-compatible shape). Mutually exclusive with `servers`.
    #[serde(skip_serializing_if = "Option::is_none")]
    results: Option<Vec<JsonResult<'a>>>,
    /// Per-server grouped results, emitted only when more than one
    /// server is queried. Mutually exclusive with `results`.
    #[serde(skip_serializing_if = "Option::is_none")]
    servers: Option<Vec<JsonServerGroup<'a>>>,
}

#[derive(Serialize)]
pub(crate) struct JsonServerGroup<'a> {
    server: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster: Option<&'a str>,
    results: Vec<JsonResult<'a>>,
}

#[derive(Serialize)]
pub(crate) struct JsonQuery<'a> {
    name: &'a str,
    types: &'a [String],
}

#[derive(Serialize)]
pub(crate) struct JsonTarget<'a> {
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_resolver: Option<&'a str>,
}

#[derive(Serialize)]
pub(crate) struct JsonResult<'a> {
    resolver: JsonResolver<'a>,
    elapsed_ms: u128,
    status: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    skip_reason: Option<&'a str>,
    answers: Vec<JsonAnswer>,
}

#[derive(Serialize)]
pub(crate) struct JsonResolver<'a> {
    transport: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_name: Option<&'a str>,
}

#[derive(Serialize)]
pub(crate) struct JsonAnswer {
    name: String,
    #[serde(rename = "type")]
    rr_type: String,
    data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
}

pub(crate) fn print_json(
    domain: &str,
    record_types: &[String],
    kind: &TargetKind,
    blocks: &[QueryResultBlock],
) {
    let value = build_json_value(domain, record_types, kind, blocks);
    println!(
        "{}",
        serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
    );
}

/// Produce the stable JSON shape `dns query --json` emits, without
/// printing. Reused by the MCP `dns_resolve` tool so CLI and MCP
/// return identical structured payloads.
pub(crate) fn build_json_value(
    domain: &str,
    record_types: &[String],
    kind: &TargetKind,
    blocks: &[QueryResultBlock],
) -> serde_json::Value {
    let target = match kind {
        TargetKind::System { display } => JsonTarget {
            kind: "system",
            server: None,
            cluster: None,
            system_resolver: Some(display.as_str()),
        },
        TargetKind::Named { servers } => {
            // Top-level `server`/`cluster` stay populated for the common
            // single-server case (back-compat); for a multi-server fan-
            // out they are null and each result carries its own `server`.
            let (server, cluster) = match servers.as_slice() {
                [only] => (Some(only.server_id.as_str()), only.cluster.as_deref()),
                _ => (None, None),
            };
            JsonTarget {
                kind: "named",
                server,
                cluster,
                system_resolver: None,
            }
        }
        TargetKind::AdHoc => JsonTarget {
            kind: "ad_hoc",
            server: None,
            cluster: None,
            system_resolver: None,
        },
    };

    // Multi-server runs emit grouped `servers: [...]`; everything else
    // keeps the flat `results: [...]` back-compatible shape.
    let multi_server = matches!(kind, TargetKind::Named { servers } if servers.len() > 1);

    let (results, servers) = if multi_server {
        let TargetKind::Named { servers } = kind else {
            unreachable!("multi_server is only set for TargetKind::Named");
        };
        let groups = servers
            .iter()
            .map(|named| JsonServerGroup {
                server: named.server_id.as_str(),
                cluster: named.cluster.as_deref(),
                results: blocks
                    .iter()
                    .filter(|b| b.server_id.as_deref() == Some(named.server_id.as_str()))
                    .map(json_result_for_block)
                    .collect(),
            })
            .collect();
        (None, Some(groups))
    } else {
        (
            Some(blocks.iter().map(json_result_for_block).collect()),
            None,
        )
    };

    let out = JsonOutput {
        query: JsonQuery {
            name: domain,
            types: record_types,
        },
        target,
        results,
        servers,
    };
    json!(out)
}

/// Build the JSON view of a single result block (resolver coordinates,
/// status, and answers), shared by the flat and grouped shapes.
pub(crate) fn json_result_for_block(b: &QueryResultBlock) -> JsonResult<'_> {
    JsonResult {
        resolver: JsonResolver {
            transport: transport_word(b.transport),
            address: b.host_for_json.as_deref(),
            port: b.port_for_json,
            url: b.url.as_deref(),
            server_name: b
                .extras
                .iter()
                .find(|(k, _)| k == "sni")
                .map(|(_, v)| v.as_str()),
        },
        elapsed_ms: b.elapsed.as_millis(),
        status: b.status.json_tag(),
        skip_reason: match &b.status {
            QueryStatus::Skipped { reason } => Some(reason.as_str()),
            _ => None,
        },
        answers: b
            .records
            .iter()
            .flat_map(|r| {
                r.values.iter().map(move |v| JsonAnswer {
                    name: trim_trailing_dot(&r.name).to_string(),
                    rr_type: r.record_type.clone(),
                    data: v.clone(),
                    ttl: r.ttl,
                })
            })
            .collect(),
    }
}
