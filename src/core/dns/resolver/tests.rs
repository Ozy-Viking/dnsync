
use super::*;
use crate::control_plane::config::{
    DnsTransportConfig, DohTransportConfig, DoqTransportConfig, DotTransportConfig, McpPermissions,
    VendorKind,
};
use rstest::rstest;

fn server_with_blocks() -> DnsServerConfig {
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
            timeout_ms: Some(1500),
        }),
        dot: Some(DotTransportConfig {
            enabled: true,
            addr: Some("10.5.0.53:853".to_string()),
            server_name: Some("dns1.hankin.io".to_string()),
            timeout_ms: None,
        }),
        doh: Some(DohTransportConfig {
            enabled: false,
            url: Some("https://dns1.hankin.io/dns-query".to_string()),
            addr: None,
            server_name: None,
            timeout_ms: None,
        }),
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

#[rstest]
#[case::no_port("10.5.0.53", Some("10.5.0.53"), None)]
#[case::with_port("10.5.0.53:853", Some("10.5.0.53"), Some(853))]
#[case::host_no_port("dns.example", Some("dns.example"), None)]
#[case::host_port("dns.example:53", Some("dns.example"), Some(53))]
#[case::empty("", None, None)]
#[case::ipv6_no_port("[2001:db8::1]", Some("2001:db8::1"), None)]
#[case::ipv6_port("[2001:db8::1]:853", Some("2001:db8::1"), Some(853))]
fn split_host_port_cases(
    #[case] input: &str,
    #[case] expected_host: Option<&str>,
    #[case] expected_port: Option<u16>,
) {
    let parsed = split_host_port(Some(input));
    assert_eq!(parsed.0.as_deref(), expected_host);
    assert_eq!(parsed.1, expected_port);
}

#[test]
fn split_host_port_none_for_none_input() {
    assert_eq!(split_host_port(None), (None, None));
}

#[test]
fn from_server_block_dns_parses_addr() {
    let server = server_with_blocks();
    let target = ResolverTarget::from_server_block(&server, ValidationTransport::Dns).unwrap();
    assert_eq!(target.transport, ValidationTransport::Dns);
    assert_eq!(target.host.as_deref(), Some("10.5.0.53"));
    assert_eq!(target.port, Some(53));
    assert_eq!(target.timeout, Duration::from_millis(1500));
    assert!(matches!(target.kind, ResolverKind::Named { ref server_id } if server_id == "dns1"));
}

#[test]
fn from_server_block_dot_picks_up_server_name() {
    let server = server_with_blocks();
    let target = ResolverTarget::from_server_block(&server, ValidationTransport::Dot).unwrap();
    assert_eq!(target.transport, ValidationTransport::Dot);
    assert_eq!(target.host.as_deref(), Some("10.5.0.53"));
    assert_eq!(target.port, Some(853));
    assert_eq!(target.server_name.as_deref(), Some("dns1.hankin.io"));
}

#[test]
fn from_server_block_doh_carries_url() {
    let server = server_with_blocks();
    let target = ResolverTarget::from_server_block(&server, ValidationTransport::Doh).unwrap();
    assert_eq!(
        target.url.as_deref(),
        Some("https://dns1.hankin.io/dns-query"),
    );
}

#[test]
fn from_server_block_returns_none_when_block_absent() {
    let mut server = server_with_blocks();
    server.dns = None;
    assert!(ResolverTarget::from_server_block(&server, ValidationTransport::Dns).is_none());
}

#[test]
fn is_enabled_on_reflects_block_state() {
    let server = server_with_blocks();
    assert!(ResolverTarget::is_enabled_on(
        &server,
        ValidationTransport::Dns
    ));
    assert!(ResolverTarget::is_enabled_on(
        &server,
        ValidationTransport::Dot
    ));
    assert!(!ResolverTarget::is_enabled_on(
        &server,
        ValidationTransport::Doh
    ));
    assert!(ResolverTarget::is_enabled_on(
        &server,
        ValidationTransport::Doq
    ));

    let mut without_doq = server_with_blocks();
    without_doq.doq = None;
    assert!(!ResolverTarget::is_enabled_on(
        &without_doq,
        ValidationTransport::Doq
    ));
}

#[cfg(not(feature = "doq"))]
#[test]
fn doq_resolver_unsupported_without_feature() {
    let server = server_with_blocks();
    let target = ResolverTarget::from_server_block(&server, ValidationTransport::Doq).unwrap();
    let err = resolver_config(&target).expect_err("doq should fail without feature");
    assert!(matches!(err, ValidationFailureKind::UnsupportedTransport));
}

#[cfg(feature = "doq")]
#[test]
fn doq_resolver_builds_with_feature() {
    let server = server_with_blocks();
    let target = ResolverTarget::from_server_block(&server, ValidationTransport::Doq).unwrap();
    resolver_config(&target).expect("doq resolver should build with feature enabled");
}

#[test]
fn from_endpoint_preserves_validation_shape() {
    let endpoint = ValidationEndpointConfig {
        name: "cloudflare-doh".to_string(),
        transport: ValidationTransport::Doh,
        address: String::new(),
        port: None,
        url: Some("https://cloudflare-dns.com/dns-query".to_string()),
        tls_server_name: None,
        enabled: true,
        timeout_ms: Some(2000),
    };

    let target = ResolverTarget::from_endpoint(&endpoint);

    assert_eq!(target.transport, ValidationTransport::Doh);
    assert_eq!(target.host, None);
    assert_eq!(
        target.url.as_deref(),
        Some("https://cloudflare-dns.com/dns-query"),
    );
    assert_eq!(target.timeout, Duration::from_millis(2000));
    assert!(matches!(
        target.kind,
        ResolverKind::ValidationEndpoint { ref name } if name == "cloudflare-doh"
    ));
}
