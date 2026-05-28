//! Transport-aware DNS resolver construction.
//!
//! Both the validation pipeline and the `dns query` subcommand build
//! Hickory resolvers from configured DNS endpoints. The resolver setup
//! is identical for both surfaces; only the source of the configuration
//! differs (legacy `ValidationEndpointConfig` for validation, the
//! per-server `[servers.dns|dot|doh|doq]` blocks for query). This module
//! provides:
//!
//! - [`ResolverTarget`]: a small neutral struct holding everything a
//!   resolver build needs (transport, host, port, URL, SNI, timeout).
//! - Converters from legacy and new config shapes into a `ResolverTarget`.
//! - [`resolver_config`] / [`build_resolver`]: produce
//!   `ResolverConfig` / `Resolver<TokioRuntimeProvider>` from a target.
//! - [`classify_hickory_error`]: map Hickory error strings to stable
//!   [`ValidationFailureKind`] variants for downstream reporting.
//!
//! DoQ support is gated behind the `doq` Cargo feature. On default
//! builds, a target with `ValidationTransport::Doq` returns
//! [`ValidationFailureKind::UnsupportedTransport`].

use std::{net::IpAddr, sync::Arc, time::Duration};

use hickory_resolver::{
    Resolver,
    config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts},
    net::runtime::TokioRuntimeProvider,
};

use crate::{
    control_plane::config::{
        DnsServerConfig, DnsTransportConfig, DohTransportConfig, DoqTransportConfig,
        DotTransportConfig, ValidationEndpointConfig, ValidationTransport,
    },
    core::dns::validation::{DnsEndpointResolverResult, ValidationFailureKind},
};

/// Default per-attempt timeout when no override is supplied.
pub const DEFAULT_TIMEOUT_MS: u64 = 5_000;

/// Where a `ResolverTarget` was sourced from.
///
/// Used by the query subcommand to render the resolver header line and
/// to populate the `resolver.kind` field in JSON output. Not consulted
/// by the resolver build itself — purely descriptive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverKind {
    /// Built from the host OS resolver (no config). Not produced by
    /// this module; the system path skips `ResolverTarget` entirely.
    System,
    /// Built from a configured `[[servers]]` entry's transport block.
    Named { server_id: String },
    /// Built from a CLI ad-hoc target (`--at` / `@addr`).
    AdHoc,
    /// Built from a legacy `[[servers.validation_endpoints]]` entry.
    ValidationEndpoint { name: String },
}

/// Minimal data a resolver build needs, transport-tagged.
#[derive(Debug, Clone)]
pub struct ResolverTarget {
    pub kind: ResolverKind,
    pub transport: ValidationTransport,
    /// Host portion: IP literal for DNS/DoT/DoQ; optional IP override
    /// for DoH (when present, used in place of the URL host for
    /// connection).
    pub host: Option<String>,
    /// Port. `None` means transport default (53/853/443/853).
    pub port: Option<u16>,
    /// DoH URL. Required for DoH; ignored otherwise.
    pub url: Option<String>,
    /// SNI / certificate name override for DoT/DoH/DoQ.
    pub server_name: Option<String>,
    /// Plain DNS should use TCP only. Ignored for encrypted transports.
    pub tcp_only: bool,
    pub timeout: Duration,
}

impl ResolverTarget {
    /// Build a target from a legacy `[[servers.validation_endpoints]]`
    /// entry. Preserves today's validation behaviour exactly.
    #[must_use]
    pub fn from_endpoint(endpoint: &ValidationEndpointConfig) -> Self {
        Self {
            kind: ResolverKind::ValidationEndpoint {
                name: endpoint.name.clone(),
            },
            transport: endpoint.transport,
            host: (!endpoint.address.trim().is_empty()).then(|| endpoint.address.clone()),
            port: endpoint.port,
            url: endpoint.url.clone(),
            server_name: endpoint.tls_server_name.clone(),
            tcp_only: false,
            timeout: Duration::from_millis(endpoint.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
        }
    }

    /// Build a target from a server's transport block. Returns `None`
    /// when the requested block is absent on this server. (The caller —
    /// the query subcommand — decides whether that's a `skipped` row
    /// or a silent skip for `--all`.)
    #[must_use]
    pub fn from_server_block(
        server: &DnsServerConfig,
        transport: ValidationTransport,
    ) -> Option<Self> {
        let kind = ResolverKind::Named {
            server_id: server.id.clone(),
        };
        match transport {
            ValidationTransport::Dns => server.dns.as_ref().map(|block| {
                let (host, port) = split_host_port(block.addr.as_deref());
                Self {
                    kind,
                    transport,
                    host,
                    port,
                    url: None,
                    server_name: None,
                    tcp_only: false,
                    timeout: Duration::from_millis(block.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
                }
            }),
            ValidationTransport::Dot => server.dot.as_ref().map(|block| {
                let (host, port) = split_host_port(block.addr.as_deref());
                Self {
                    kind,
                    transport,
                    host,
                    port,
                    url: None,
                    server_name: block.server_name.clone(),
                    tcp_only: false,
                    timeout: Duration::from_millis(block.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
                }
            }),
            ValidationTransport::Doh => server.doh.as_ref().map(|block| {
                let (host, port) = split_host_port(block.addr.as_deref());
                Self {
                    kind,
                    transport,
                    host,
                    port,
                    url: block.url.clone(),
                    server_name: block.server_name.clone(),
                    tcp_only: false,
                    timeout: Duration::from_millis(block.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
                }
            }),
            ValidationTransport::Doq => server.doq.as_ref().map(|block| {
                let (host, port) = split_host_port(block.addr.as_deref());
                Self {
                    kind,
                    transport,
                    host,
                    port,
                    url: None,
                    server_name: block.server_name.clone(),
                    tcp_only: false,
                    timeout: Duration::from_millis(block.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
                }
            }),
        }
    }

    /// Returns true when the server's block for `transport` exists and
    /// is `enabled = true`. Used by the query subcommand's transport
    /// precedence and `--all` enumeration.
    #[must_use]
    pub fn is_enabled_on(server: &DnsServerConfig, transport: ValidationTransport) -> bool {
        match transport {
            ValidationTransport::Dns => server
                .dns
                .as_ref()
                .map(|b: &DnsTransportConfig| b.enabled)
                .unwrap_or(false),
            ValidationTransport::Dot => server
                .dot
                .as_ref()
                .map(|b: &DotTransportConfig| b.enabled)
                .unwrap_or(false),
            ValidationTransport::Doh => server
                .doh
                .as_ref()
                .map(|b: &DohTransportConfig| b.enabled)
                .unwrap_or(false),
            ValidationTransport::Doq => server
                .doq
                .as_ref()
                .map(|b: &DoqTransportConfig| b.enabled)
                .unwrap_or(false),
        }
    }
}

/// Build a `ResolverConfig` for a target.
///
/// Returns `UnsupportedTransport` when DoQ is requested on a build
/// without the `doq` feature enabled.
pub fn resolver_config(target: &ResolverTarget) -> DnsEndpointResolverResult<ResolverConfig> {
    let name_server = match target.transport {
        ValidationTransport::Dns => plain_dns_name_server(target)?,
        ValidationTransport::Dot => dot_name_server(target)?,
        ValidationTransport::Doh => doh_name_server(target)?,
        ValidationTransport::Doq => doq_name_server(target)?,
    };
    Ok(ResolverConfig::from_parts(
        None,
        Vec::new(),
        vec![name_server],
    ))
}

/// Build a Hickory `Resolver` for a target with the target's timeout.
pub fn build_resolver(
    target: &ResolverTarget,
) -> DnsEndpointResolverResult<Resolver<TokioRuntimeProvider>> {
    let mut opts = ResolverOpts::default();
    opts.timeout = target.timeout;
    opts.attempts = 1;

    Resolver::builder_with_config(resolver_config(target)?, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .map_err(|err| classify_hickory_error(target.transport, &err.to_string()))
}

fn plain_dns_name_server(target: &ResolverTarget) -> DnsEndpointResolverResult<NameServerConfig> {
    let ip = target_ip(target)?;
    let port = target.port.unwrap_or(53);
    let mut udp = ConnectionConfig::udp();
    udp.port = port;
    let mut tcp = ConnectionConfig::tcp();
    tcp.port = port;

    let connections = if target.tcp_only {
        vec![tcp]
    } else {
        vec![udp, tcp]
    };
    Ok(NameServerConfig::new(ip, true, connections))
}

fn dot_name_server(target: &ResolverTarget) -> DnsEndpointResolverResult<NameServerConfig> {
    let ip = target_ip(target)?;
    let server_name = tls_server_name(target)?.into();
    let mut tls = ConnectionConfig::tls(server_name);
    tls.port = target.port.unwrap_or(853);

    Ok(NameServerConfig::new(ip, true, vec![tls]))
}

fn doh_name_server(target: &ResolverTarget) -> DnsEndpointResolverResult<NameServerConfig> {
    let (host, path) = doh_url_parts(target)?;
    let ip = match target.host.as_deref() {
        Some(h) if !h.trim().is_empty() => h
            .parse::<IpAddr>()
            .map_err(|_| ValidationFailureKind::MalformedResponse)?,
        _ => host
            .parse::<IpAddr>()
            .map_err(|_| ValidationFailureKind::MalformedResponse)?,
    };
    let server_name = target
        .server_name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(host)
        .to_string();
    let mut https = ConnectionConfig::https(Arc::from(server_name), Some(Arc::from(path)));
    https.port = target.port.unwrap_or(443);

    Ok(NameServerConfig::new(ip, true, vec![https]))
}

#[cfg(feature = "doq")]
fn doq_name_server(target: &ResolverTarget) -> DnsEndpointResolverResult<NameServerConfig> {
    let ip = target_ip(target)?;
    let server_name = tls_server_name(target)?.into();
    let mut quic = ConnectionConfig::quic(server_name);
    quic.port = target.port.unwrap_or(853);

    Ok(NameServerConfig::new(ip, true, vec![quic]))
}

#[cfg(not(feature = "doq"))]
fn doq_name_server(_target: &ResolverTarget) -> DnsEndpointResolverResult<NameServerConfig> {
    tracing::warn!(
        "DoQ transport is not enabled in this build of dns. \
         Rebuild with `--features doq` to enable DNS-over-QUIC."
    );
    Err(ValidationFailureKind::UnsupportedTransport)
}

fn target_ip(target: &ResolverTarget) -> DnsEndpointResolverResult<IpAddr> {
    target
        .host
        .as_deref()
        .ok_or(ValidationFailureKind::MalformedResponse)?
        .parse::<IpAddr>()
        .map_err(|_| ValidationFailureKind::MalformedResponse)
}

fn tls_server_name(target: &ResolverTarget) -> DnsEndpointResolverResult<String> {
    target
        .server_name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .map(str::to_string)
        .or_else(|| {
            target
                .host
                .as_deref()
                .filter(|h| !h.trim().is_empty())
                .map(str::to_string)
        })
        .ok_or(ValidationFailureKind::MalformedResponse)
}

fn doh_url_parts(target: &ResolverTarget) -> DnsEndpointResolverResult<(&str, &str)> {
    let url = target
        .url
        .as_deref()
        .ok_or(ValidationFailureKind::MalformedResponse)?;
    let without_scheme = url
        .strip_prefix("https://")
        .ok_or(ValidationFailureKind::DohHttpFailure)?;
    let (authority, path) = without_scheme
        .split_once('/')
        .unwrap_or((without_scheme, "dns-query"));
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host_port)| host_port);
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split_once(']').map_or(authority, |(host, _)| host)
    } else {
        authority
            .split_once(':')
            .map_or(authority, |(host, _)| host)
    };

    if host.trim().is_empty() {
        return Err(ValidationFailureKind::MalformedResponse);
    }

    Ok((
        host,
        if path.is_empty() {
            "/dns-query"
        } else {
            &url[url.len() - path.len() - 1..]
        },
    ))
}

/// Map a Hickory error string into a stable [`ValidationFailureKind`].
///
/// Used by both the validation pipeline and (in due course) the query
/// subcommand, so the categories stay aligned across surfaces.
pub fn classify_hickory_error(
    transport: ValidationTransport,
    error: &str,
) -> ValidationFailureKind {
    let error = error.to_ascii_lowercase();

    if error.contains("timed out") || error.contains("timeout") {
        ValidationFailureKind::Timeout
    } else if error.contains("nxdomain") || error.contains("no records found") {
        ValidationFailureKind::Nxdomain
    } else if error.contains("servfail") || error.contains("server failure") {
        ValidationFailureKind::Servfail
    } else if error.contains("refused") {
        ValidationFailureKind::Refused
    } else if matches!(transport, ValidationTransport::Dot) || error.contains("tls") {
        ValidationFailureKind::TlsFailure
    } else if matches!(transport, ValidationTransport::Doh) || error.contains("http") {
        ValidationFailureKind::DohHttpFailure
    } else {
        ValidationFailureKind::MalformedResponse
    }
}

/// Split an `addr` of the shape `"host[:port]"` (with IPv6 brackets
/// optionally allowed) into `(host, port)`. Returns `(Some(addr),
/// None)` when there's no port, `(None, None)` for `None`/empty input.
fn split_host_port(addr: Option<&str>) -> (Option<String>, Option<u16>) {
    let raw = match addr {
        Some(s) if !s.trim().is_empty() => s.trim(),
        _ => return (None, None),
    };

    if let Some(stripped) = raw.strip_prefix('[') {
        if let Some((host, rest)) = stripped.split_once(']') {
            let port = rest.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            return (Some(host.to_string()), port);
        }
        return (Some(raw.to_string()), None);
    }

    if let Some((host, port_s)) = raw.rsplit_once(':')
        && let Ok(port) = port_s.parse::<u16>()
        && !host.is_empty()
        && !host.contains(':')
    {
        return (Some(host.to_string()), Some(port));
    }

    (Some(raw.to_string()), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::config::{
        DnsTransportConfig, DohTransportConfig, DoqTransportConfig, DotTransportConfig,
        McpPermissions, VendorKind,
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
        assert!(
            matches!(target.kind, ResolverKind::Named { ref server_id } if server_id == "dns1")
        );
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
}
