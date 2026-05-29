//! Integration tests for the MCP `dns_resolve` response shape.

use std::{net::SocketAddr, str::FromStr};

use dnslib::{
    control_plane::config::AppConfig,
    mcp::{params::ResolveParams, tools::resolve::handle_resolve},
};
use hickory_resolver::proto::{
    op::Message,
    rr::{Name, RData, Record, RecordType},
};
use serde_json::{Value, json};
use tokio::{net::UdpSocket, task::JoinHandle};

#[tokio::test]
async fn dns_resolve_preserves_cname_and_aaaa_answer_shape() {
    let (server_addr, server_handle) = spawn_dns_server().await;

    let body = resolve_body(
        server_addr,
        "alias-v6.example.test",
        Some(vec!["AAAA".to_string()]),
    )
    .await;

    let answers = body["results"][0]["answers"]
        .as_array()
        .expect("answers is an array");

    assert_eq!(
        answers,
        &vec![
            json!({
                "name": "alias-v6.example.test",
                "type": "CNAME",
                "data": "target-v6.example.test.",
                "ttl": 300,
            }),
            json!({
                "name": "target-v6.example.test",
                "type": "AAAA",
                "data": "2001:db8::10",
                "ttl": 300,
            }),
        ]
    );

    server_handle.abort();
}

#[tokio::test]
async fn dns_resolve_default_types_returns_all_supported_shapes() {
    let (server_addr, server_handle) = spawn_dns_server().await;

    let body = resolve_body(server_addr, "all.example.test", None).await;

    assert_eq!(
        body["query"]["types"],
        json!([
            "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA", "PTR", "SOA"
        ])
    );
    assert_eq!(
        body["results"][0]["answers"],
        json!([
            {
                "name": "all.example.test",
                "type": "A",
                "data": "192.0.2.10",
                "ttl": 300,
            },
            {
                "name": "all.example.test",
                "type": "AAAA",
                "data": "2001:db8::10",
                "ttl": 300,
            },
            {
                "name": "all.example.test",
                "type": "CNAME",
                "data": "canonical.example.test.",
                "ttl": 300,
            },
            {
                "name": "all.example.test",
                "type": "MX",
                "data": "10 mail.example.test.",
                "ttl": 300,
            },
            {
                "name": "all.example.test",
                "type": "TXT",
                "data": "v=spf1 -all",
                "ttl": 300,
            },
            {
                "name": "all.example.test",
                "type": "NS",
                "data": "ns1.example.test.",
                "ttl": 300,
            },
            {
                "name": "all.example.test",
                "type": "SRV",
                "data": "10 20 5060 sip.example.test.",
                "ttl": 300,
            },
            {
                "name": "all.example.test",
                "type": "CAA",
                "data": "0 issue \"letsencrypt.org\"",
                "ttl": 300,
            },
            {
                "name": "all.example.test",
                "type": "PTR",
                "data": "ptr.example.test.",
                "ttl": 300,
            },
            {
                "name": "all.example.test",
                "type": "SOA",
                "data": "ns1.example.test. hostmaster.example.test. 2026052901 3600 900 604800 300",
                "ttl": 300,
            },
        ])
    );

    server_handle.abort();
}

#[tokio::test]
async fn dns_resolve_default_types_handles_cname_to_aaaa_and_a_targets() {
    let (server_addr, server_handle) = spawn_dns_server().await;

    let v6 = resolve_body(server_addr, "alias-v6.example.test", None).await;
    assert_eq!(
        v6["results"][0]["answers"],
        json!([
            {
                "name": "alias-v6.example.test",
                "type": "CNAME",
                "data": "target-v6.example.test.",
                "ttl": 300,
            },
            {
                "name": "target-v6.example.test",
                "type": "AAAA",
                "data": "2001:db8::10",
                "ttl": 300,
            },
        ])
    );

    let v4 = resolve_body(server_addr, "alias-v4.example.test", None).await;
    assert_eq!(
        v4["results"][0]["answers"],
        json!([
            {
                "name": "alias-v4.example.test",
                "type": "CNAME",
                "data": "target-v4.example.test.",
                "ttl": 300,
            },
            {
                "name": "target-v4.example.test",
                "type": "A",
                "data": "192.0.2.20",
                "ttl": 300,
            },
        ])
    );

    server_handle.abort();
}

#[tokio::test]
async fn cname_only_query_without_chase_shows_just_the_cname() {
    let (server_addr, server_handle) = spawn_dns_server().await;

    let body = resolve_body(
        server_addr,
        "alias-v6.example.test",
        Some(vec!["CNAME".to_string()]),
    )
    .await;

    assert_eq!(
        body["results"][0]["answers"],
        json!([
            {
                "name": "alias-v6.example.test",
                "type": "CNAME",
                "data": "target-v6.example.test.",
                "ttl": 300,
            },
        ])
    );

    server_handle.abort();
}

#[tokio::test]
async fn chase_follows_cname_to_terminal_address_on_typed_query() {
    let (server_addr, server_handle) = spawn_dns_server().await;

    // Asking only for CNAME would normally stop at the hop; --chase walks
    // on to the terminal AAAA even though AAAA was never requested.
    let body = resolve_body_chase(
        server_addr,
        "alias-v6.example.test",
        Some(vec!["CNAME".to_string()]),
        true,
    )
    .await;

    assert_eq!(
        body["results"][0]["answers"],
        json!([
            {
                "name": "alias-v6.example.test",
                "type": "CNAME",
                "data": "target-v6.example.test.",
                "ttl": 300,
            },
            {
                "name": "target-v6.example.test",
                "type": "AAAA",
                "data": "2001:db8::10",
                "ttl": 300,
            },
        ])
    );

    server_handle.abort();
}

async fn resolve_body(server_addr: SocketAddr, domain: &str, types: Option<Vec<String>>) -> Value {
    resolve_body_chase(server_addr, domain, types, false).await
}

async fn resolve_body_chase(
    server_addr: SocketAddr,
    domain: &str,
    types: Option<Vec<String>>,
    chase: bool,
) -> Value {
    let result = handle_resolve(
        &AppConfig::default(),
        &[],
        &[],
        ResolveParams {
            domain: domain.to_string(),
            types,
            server_id: None,
            at: Some(server_addr.to_string()),
            transports: Some(vec!["dns".to_string()]),
            all_transports: None,
            port: None,
            tls_server_name: None,
            timeout_ms: Some(1_000),
            chase: Some(chase),
        },
    )
    .await
    .expect("MCP resolve succeeds");

    mcp_json_body(&result)
}

fn mcp_json_body(result: &rmcp::model::CallToolResult) -> Value {
    let content = result.content.first().expect("MCP result has content");
    let Some(text) = content.raw.as_text() else {
        panic!("MCP result content is text");
    };
    serde_json::from_str(&text.text).expect("MCP text content is JSON")
}

async fn spawn_dns_server() -> (SocketAddr, JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind test DNS server");
    let addr = socket.local_addr().expect("test DNS server addr");

    let handle = tokio::spawn(async move {
        let mut buf = [0_u8; 512];
        loop {
            let Ok((len, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let Ok(request) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let response = dns_response_for(request);
            let Ok(bytes) = response.to_vec() else {
                continue;
            };
            let _ = socket.send_to(&bytes, peer).await;
        }
    });

    (addr, handle)
}

fn dns_response_for(request: Message) -> Message {
    let query = request.queries.first().cloned();
    let mut response = request.into_response();

    let Some(query) = query else {
        return response;
    };

    match (query.name.to_string().as_str(), query.query_type) {
        ("all.example.test.", RecordType::A) => {
            response.add_answer(record(
                "all.example.test.",
                300,
                RecordType::A,
                "192.0.2.10",
            ));
        }
        ("all.example.test.", RecordType::AAAA) => {
            response.add_answer(record(
                "all.example.test.",
                300,
                RecordType::AAAA,
                "2001:db8::10",
            ));
        }
        ("all.example.test.", RecordType::CNAME) => {
            response.add_answer(record(
                "all.example.test.",
                300,
                RecordType::CNAME,
                "canonical.example.test.",
            ));
        }
        ("all.example.test.", RecordType::MX) => {
            response.add_answer(record(
                "all.example.test.",
                300,
                RecordType::MX,
                "10 mail.example.test.",
            ));
        }
        ("all.example.test.", RecordType::TXT) => {
            response.add_answer(record(
                "all.example.test.",
                300,
                RecordType::TXT,
                "\"v=spf1 -all\"",
            ));
        }
        ("all.example.test.", RecordType::NS) => {
            response.add_answer(record(
                "all.example.test.",
                300,
                RecordType::NS,
                "ns1.example.test.",
            ));
        }
        ("all.example.test.", RecordType::SRV) => {
            response.add_answer(record(
                "all.example.test.",
                300,
                RecordType::SRV,
                "10 20 5060 sip.example.test.",
            ));
        }
        ("all.example.test.", RecordType::CAA) => {
            response.add_answer(record(
                "all.example.test.",
                300,
                RecordType::CAA,
                "0 issue \"letsencrypt.org\"",
            ));
        }
        ("all.example.test.", RecordType::PTR) => {
            response.add_answer(record(
                "all.example.test.",
                300,
                RecordType::PTR,
                "ptr.example.test.",
            ));
        }
        ("all.example.test.", RecordType::SOA) => {
            response.add_answer(record(
                "all.example.test.",
                300,
                RecordType::SOA,
                "ns1.example.test. hostmaster.example.test. 2026052901 3600 900 604800 300",
            ));
        }
        ("alias-v6.example.test.", RecordType::AAAA)
        | ("alias-v6.example.test.", RecordType::CNAME) => {
            response.add_answer(record(
                "alias-v6.example.test.",
                300,
                RecordType::CNAME,
                "target-v6.example.test.",
            ));
            if query.query_type == RecordType::AAAA {
                response.add_answer(record(
                    "target-v6.example.test.",
                    300,
                    RecordType::AAAA,
                    "2001:db8::10",
                ));
            }
        }
        ("alias-v4.example.test.", RecordType::A)
        | ("alias-v4.example.test.", RecordType::CNAME) => {
            response.add_answer(record(
                "alias-v4.example.test.",
                300,
                RecordType::CNAME,
                "target-v4.example.test.",
            ));
            if query.query_type == RecordType::A {
                response.add_answer(record(
                    "target-v4.example.test.",
                    300,
                    RecordType::A,
                    "192.0.2.20",
                ));
            }
        }
        // Terminal records for the chain targets, answered directly so a
        // `--chase` walk can reach them from a CNAME-only initial query.
        ("target-v6.example.test.", RecordType::AAAA) => {
            response.add_answer(record(
                "target-v6.example.test.",
                300,
                RecordType::AAAA,
                "2001:db8::10",
            ));
        }
        ("target-v4.example.test.", RecordType::A) => {
            response.add_answer(record(
                "target-v4.example.test.",
                300,
                RecordType::A,
                "192.0.2.20",
            ));
        }
        _ => {}
    }

    response
}

fn record(name: &str, ttl: u32, rr_type: RecordType, rdata: &str) -> Record {
    Record::from_rdata(
        self::name(name),
        ttl,
        RData::try_from_str(rr_type, rdata).expect("test rdata parses"),
    )
}

fn name(value: &str) -> Name {
    Name::from_str(value).expect("test name parses")
}
