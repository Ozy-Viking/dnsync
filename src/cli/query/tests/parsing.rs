use super::*;

#[test]
fn split_targets_domain_only() {
    let (domain, at) = split_targets(&["huly.hankin.io".to_string()]).unwrap();
    assert_eq!(domain, "huly.hankin.io");
    assert_eq!(at, None);
}

#[test]
fn split_targets_with_at_sugar() {
    let (domain, at) =
        split_targets(&["huly.hankin.io".to_string(), "@1.1.1.1".to_string()]).unwrap();
    assert_eq!(domain, "huly.hankin.io");
    assert_eq!(at.as_deref(), Some("1.1.1.1"));
}

#[test]
fn split_targets_at_before_domain() {
    let (domain, at) =
        split_targets(&["@1.1.1.1".to_string(), "huly.hankin.io".to_string()]).unwrap();
    assert_eq!(domain, "huly.hankin.io");
    assert_eq!(at.as_deref(), Some("1.1.1.1"));
}

#[test]
fn split_targets_rejects_multiple_at() {
    assert!(
        split_targets(&[
            "huly.hankin.io".to_string(),
            "@1.1.1.1".to_string(),
            "@8.8.8.8".to_string(),
        ])
        .is_err()
    );
}

#[test]
fn split_targets_rejects_extra_positional() {
    assert!(split_targets(&["huly.hankin.io".to_string(), "extra.example".to_string(),]).is_err());
}

#[test]
fn split_targets_requires_domain() {
    assert!(split_targets(&[]).is_err());
    assert!(split_targets(&["@1.1.1.1".to_string()]).is_err());
}

#[test]
fn parse_record_types_default_to_supported_standard_types() {
    let types = parse_record_types(&[], false).unwrap();
    assert_eq!(
        types,
        DEFAULT_RECORD_TYPES
            .iter()
            .map(|rr_type| (*rr_type).to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn parse_record_types_all_types_overrides_explicit() {
    let types = parse_record_types(&["A".to_string()], true).unwrap();
    assert_eq!(
        types,
        DEFAULT_RECORD_TYPES
            .iter()
            .map(|rr_type| (*rr_type).to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn parse_record_types_uppercases_and_dedups() {
    let types = parse_record_types(
        &["a".to_string(), "AAAA".to_string(), "A".to_string()],
        false,
    )
    .unwrap();
    assert_eq!(types, vec!["A".to_string(), "AAAA".to_string()]);
}

#[test]
fn parse_record_types_rejects_unknown() {
    assert!(parse_record_types(&["BOGUS".to_string()], false).is_err());
}

#[test]
fn validate_rejects_server_and_at() {
    let mut args = QueryArgs::default();
    args.server = vec!["dns1".to_string()];
    args.at = Some("1.1.1.1".to_string());
    assert!(validate_cli_rules(&args).is_err());
}

#[test]
fn validate_rejects_all_servers_with_explicit_server() {
    let mut args = QueryArgs::default();
    args.all_servers = true;
    args.server = vec!["dns1".to_string()];
    assert!(validate_cli_rules(&args).is_err());
}

#[test]
fn validate_rejects_all_servers_with_at() {
    let mut args = QueryArgs::default();
    args.all_servers = true;
    args.at = Some("1.1.1.1".to_string());
    assert!(validate_cli_rules(&args).is_err());
}

#[test]
fn validate_rejects_all_transports_with_explicit_transport() {
    let mut args = QueryArgs::default();
    args.server = vec!["dns1".to_string()];
    args.all_transports = true;
    args.dot = true;
    assert!(validate_cli_rules(&args).is_err());
}

#[test]
fn validate_rejects_all_transports_without_server() {
    let mut args = QueryArgs::default();
    args.all_transports = true;
    args.at = Some("1.1.1.1".to_string());
    assert!(validate_cli_rules(&args).is_err());
}

#[test]
fn validate_rejects_transport_flags_with_no_target() {
    let mut args = QueryArgs::default();
    args.dot = true;
    assert!(validate_cli_rules(&args).is_err());
}

#[test]
fn validate_rejects_multiple_transport_flags_with_at() {
    let mut args = QueryArgs::default();
    args.at = Some("1.1.1.1".to_string());
    args.dns = true;
    args.dot = true;
    assert!(validate_cli_rules(&args).is_err());
}

#[test]
fn validate_rejects_port_with_named_server() {
    let mut args = QueryArgs::default();
    args.server = vec!["dns1".to_string()];
    args.port = Some(53);
    assert!(validate_cli_rules(&args).is_err());
}

#[test]
fn validate_accepts_single_target_with_no_transport_flags() {
    let mut args = QueryArgs::default();
    args.server = vec!["dns1".to_string()];
    validate_cli_rules(&args).unwrap();

    let mut args = QueryArgs::default();
    args.at = Some("1.1.1.1".to_string());
    validate_cli_rules(&args).unwrap();
}

#[test]
fn validate_accepts_multiple_servers() {
    let mut args = QueryArgs::default();
    args.server = vec!["dns1".to_string(), "dns2".to_string()];
    validate_cli_rules(&args).unwrap();
}

// ── split_addr ──────────────────────────────────────────────────────────────

#[test]
fn split_addr_host_only() {
    let (host, port) = split_addr("dns.example").unwrap();
    assert_eq!(host, "dns.example");
    assert_eq!(port, None);
}

#[test]
fn split_addr_host_with_port() {
    let (host, port) = split_addr("dns.example:8053").unwrap();
    assert_eq!(host, "dns.example");
    assert_eq!(port, Some(8053));
}

#[test]
fn split_addr_ipv4_with_port() {
    let (host, port) = split_addr("1.1.1.1:53").unwrap();
    assert_eq!(host, "1.1.1.1");
    assert_eq!(port, Some(53));
}

#[test]
fn split_addr_bare_ipv6_has_no_port() {
    // A bare IPv6 literal contains colons but must not be split on them.
    let (host, port) = split_addr("2606:4700:4700::1111").unwrap();
    assert_eq!(host, "2606:4700:4700::1111");
    assert_eq!(port, None);
}

#[test]
fn split_addr_bracketed_ipv6_with_port() {
    let (host, port) = split_addr("[2606:4700:4700::1111]:853").unwrap();
    assert_eq!(host, "2606:4700:4700::1111");
    assert_eq!(port, Some(853));
}

#[test]
fn split_addr_bracketed_ipv6_without_port() {
    let (host, port) = split_addr("[::1]").unwrap();
    assert_eq!(host, "::1");
    assert_eq!(port, None);
}

#[test]
fn split_addr_rejects_empty() {
    assert!(split_addr("   ").is_err());
}

#[test]
fn split_addr_rejects_non_numeric_port() {
    assert!(split_addr("host:notaport").is_err());
    assert!(split_addr("[::1]:bad").is_err());
}

// ── strip_https_scheme_for_display ──────────────────────────────────────────

#[test]
fn strip_https_scheme_removes_only_https_prefix() {
    assert_eq!(
        strip_https_scheme_for_display("https://dns.example/dns-query"),
        "dns.example/dns-query"
    );
    // No scheme — returned unchanged.
    assert_eq!(
        strip_https_scheme_for_display("dns.example/dns-query"),
        "dns.example/dns-query"
    );
    // http:// is left intact (only https:// is stripped).
    assert_eq!(
        strip_https_scheme_for_display("http://dns.example"),
        "http://dns.example"
    );
}

// ── extract_doh_host ────────────────────────────────────────────────────────

#[test]
fn extract_doh_host_pulls_authority_from_url() {
    assert_eq!(
        extract_doh_host("https://cloudflare-dns.com/dns-query"),
        Some("cloudflare-dns.com")
    );
}

#[test]
fn extract_doh_host_strips_port_and_userinfo() {
    assert_eq!(
        extract_doh_host("https://user@dns.example:443/dns-query"),
        Some("dns.example")
    );
}

#[test]
fn extract_doh_host_handles_bracketed_ipv6() {
    assert_eq!(
        extract_doh_host("https://[2606:4700:4700::1111]:443/dns-query"),
        Some("2606:4700:4700::1111")
    );
}

#[test]
fn extract_doh_host_without_scheme() {
    assert_eq!(
        extract_doh_host("dns.example/dns-query"),
        Some("dns.example")
    );
}

#[test]
fn extract_doh_host_empty_authority_is_none() {
    assert_eq!(extract_doh_host("https:///dns-query"), None);
}

// ── describe_target ─────────────────────────────────────────────────────────

use crate::core::dns::resolver::{ResolverKind, ResolverTarget};

fn target(transport: ValidationTransport) -> ResolverTarget {
    ResolverTarget {
        kind: ResolverKind::AdHoc,
        transport,
        host: Some("dns.example".to_string()),
        port: None,
        url: None,
        server_name: None,
        tcp_only: false,
        timeout: Duration::from_millis(5000),
    }
}

#[test]
fn describe_target_dns_default_port_label_omits_port() {
    let (label, extras, url, host, port) = describe_target(&target(ValidationTransport::Dns));
    assert_eq!(label, "dns.example");
    assert!(extras.is_empty());
    assert_eq!(url, None);
    assert_eq!(host.as_deref(), Some("dns.example"));
    assert_eq!(port, Some(53));
}

#[test]
fn describe_target_dns_non_default_port_in_label() {
    let mut t = target(ValidationTransport::Dns);
    t.port = Some(5353);
    let (label, _, _, _, port) = describe_target(&t);
    assert_eq!(label, "dns.example:5353");
    assert_eq!(port, Some(5353));
}

#[test]
fn describe_target_dot_adds_sni_extra_and_default_port() {
    let mut t = target(ValidationTransport::Dot);
    t.server_name = Some("sni.example".to_string());
    let (label, extras, _, _, port) = describe_target(&t);
    assert_eq!(label, "dns.example:853");
    assert_eq!(port, Some(853));
    assert!(extras.iter().any(|(k, v)| k == "sni" && v == "sni.example"));
}

#[test]
fn describe_target_doh_label_strips_scheme() {
    let mut t = target(ValidationTransport::Doh);
    t.url = Some("https://dns.example/dns-query".to_string());
    let (label, _, url, _, _) = describe_target(&t);
    assert_eq!(label, "dns.example/dns-query");
    assert_eq!(url.as_deref(), Some("https://dns.example/dns-query"));
}
