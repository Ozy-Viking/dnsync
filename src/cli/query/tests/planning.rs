use super::*;

#[test]
fn transport_compiled_in_gates_only_doq() {
    assert!(transport_compiled_in(ValidationTransport::Dns));
    assert!(transport_compiled_in(ValidationTransport::Dot));
    assert!(transport_compiled_in(ValidationTransport::Doh));
    assert_eq!(
        transport_compiled_in(ValidationTransport::Doq),
        cfg!(feature = "doq")
    );
}

#[test]
fn all_transports_skips_doq_unless_compiled_in() {
    let server = server_with_dns_and_doq();
    let mut args = QueryArgs::default();
    args.all_transports = true;
    let targets = plan_targets_for_server(&server, &args, Duration::from_millis(1000));
    // DNS is always planned; DoQ only when the feature is enabled.
    assert!(
        targets
            .iter()
            .any(|t| t.transport == ValidationTransport::Dns)
    );
    assert_eq!(
        targets
            .iter()
            .any(|t| t.transport == ValidationTransport::Doq),
        cfg!(feature = "doq")
    );
}

#[test]
fn explicit_doq_is_always_planned() {
    let server = server_with_dns_and_doq();
    let mut args = QueryArgs::default();
    args.doq = true;
    let targets = plan_targets_for_server(&server, &args, Duration::from_millis(1000));
    // An explicit `--doq` is honoured regardless of build, so the
    // UNSUPPORTED status still surfaces when the feature is off.
    assert!(
        targets
            .iter()
            .any(|t| t.transport == ValidationTransport::Doq)
    );
}

#[test]
fn parse_ad_hoc_plain_ip_no_scheme() {
    let p = parse_ad_hoc("1.1.1.1").unwrap();
    assert_eq!(p.transport, None);
    assert_eq!(p.host.as_deref(), Some("1.1.1.1"));
    assert_eq!(p.port, None);
}

#[test]
fn parse_ad_hoc_ip_with_port() {
    let p = parse_ad_hoc("9.9.9.9:53").unwrap();
    assert_eq!(p.host.as_deref(), Some("9.9.9.9"));
    assert_eq!(p.port, Some(53));
}

#[test]
fn parse_ad_hoc_tls_scheme_maps_to_dot() {
    let p = parse_ad_hoc("tls://9.9.9.9").unwrap();
    assert_eq!(p.transport, Some(ValidationTransport::Dot));
    assert_eq!(p.host.as_deref(), Some("9.9.9.9"));
}

#[test]
fn parse_ad_hoc_https_scheme_carries_url() {
    let p = parse_ad_hoc("https://cloudflare-dns.com/dns-query").unwrap();
    assert_eq!(p.transport, Some(ValidationTransport::Doh));
    assert_eq!(
        p.url.as_deref(),
        Some("https://cloudflare-dns.com/dns-query")
    );
}

#[test]
fn parse_ad_hoc_doq_scheme() {
    let p = parse_ad_hoc("doq://dns.adguard.com:853").unwrap();
    assert_eq!(p.transport, Some(ValidationTransport::Doq));
    assert_eq!(p.host.as_deref(), Some("dns.adguard.com"));
    assert_eq!(p.port, Some(853));
}

#[test]
fn parse_ad_hoc_rejects_unknown_scheme() {
    assert!(parse_ad_hoc("ftp://1.1.1.1").is_err());
}

#[test]
fn parse_ad_hoc_ipv6_literal_no_port() {
    let p = parse_ad_hoc("[2001:db8::1]").unwrap();
    assert_eq!(p.host.as_deref(), Some("2001:db8::1"));
    assert_eq!(p.port, None);
}

#[test]
fn parse_ad_hoc_ipv6_literal_with_port() {
    let p = parse_ad_hoc("[2001:db8::1]:53").unwrap();
    assert_eq!(p.host.as_deref(), Some("2001:db8::1"));
    assert_eq!(p.port, Some(53));
}

#[test]
fn clap_parses_query_alias_q() {
    let args = parse(&["huly.hankin.io"]).unwrap();
    assert_eq!(args.targets, vec!["huly.hankin.io".to_string()]);
}

#[test]
fn clap_parses_at_sugar_as_positional() {
    let args = parse(&["huly.hankin.io", "@1.1.1.1"]).unwrap();
    assert_eq!(args.targets.len(), 2);
    assert!(args.targets.contains(&"@1.1.1.1".to_string()));
}

#[test]
fn clap_parses_multiple_transport_flags() {
    let args = parse(&["huly.hankin.io", "--server", "dns1", "--dot", "--doh"]).unwrap();
    assert!(args.dot);
    assert!(args.doh);
    assert!(!args.dns);
    assert!(!args.all);
    assert!(!args.all_transports);
    assert_eq!(args.server, vec!["dns1".to_string()]);
}

#[test]
fn clap_parses_repeated_server() {
    let args = parse(&["huly.hankin.io", "--server", "dns1", "--server", "dns2"]).unwrap();
    assert_eq!(args.server, vec!["dns1".to_string(), "dns2".to_string()]);
}

#[test]
fn clap_parses_all_flags() {
    let args = parse(&["huly.hankin.io", "--all-servers", "--all-types"]).unwrap();
    assert!(args.all_servers);
    assert!(args.all_types);
    assert!(!args.all_transports);
}

#[test]
fn clap_parses_chase_and_chain_alias() {
    assert!(parse(&["huly.hankin.io", "--chase"]).unwrap().chase);
    assert!(parse(&["huly.hankin.io", "--chain"]).unwrap().chase);
    assert!(!parse(&["huly.hankin.io"]).unwrap().chase);
}

#[test]
fn chain_key_normalises_trailing_dot_and_case() {
    assert_eq!(chain_key("Target.Example."), "target.example");
    assert_eq!(chain_key("target.example"), "target.example");
    assert_eq!(chain_key("HULY.Hankin.IO."), "huly.hankin.io");
}

#[test]
fn is_chain_record_matches_only_cname_and_dname() {
    assert!(is_chain_record("CNAME"));
    assert!(is_chain_record("DNAME"));
    assert!(!is_chain_record("A"));
    assert!(!is_chain_record("AAAA"));
    assert!(!is_chain_record("MX"));
}

#[test]
fn clap_q_alias_works() {
    let cli = Cli::try_parse_from(["dns", "q", "huly.hankin.io"]).unwrap();
    match cli.command {
        Command::Query(q) => assert_eq!(q.targets, vec!["huly.hankin.io".to_string()]),
        _ => panic!("expected Command::Query"),
    }
}

#[test]
fn forced_transport_picks_in_precedence_order() {
    let mut args = QueryArgs::default();
    args.doh = true;
    assert_eq!(
        forced_transport_from_flags(&args),
        Some(ValidationTransport::Doh)
    );
    let mut args = QueryArgs::default();
    args.doq = true;
    assert_eq!(
        forced_transport_from_flags(&args),
        Some(ValidationTransport::Doq)
    );
    let args = QueryArgs::default();
    assert_eq!(forced_transport_from_flags(&args), None);
}

#[test]
fn worst_status_picks_higher_severity() {
    assert_eq!(
        worst(QueryStatus::NoError, QueryStatus::NxDomain),
        QueryStatus::NxDomain
    );
    assert_eq!(
        worst(QueryStatus::NxDomain, QueryStatus::NoError),
        QueryStatus::NxDomain
    );
    assert_eq!(
        worst(QueryStatus::Timeout, QueryStatus::NxDomain),
        QueryStatus::Timeout
    );
}

#[test]
fn exit_code_worst_across_blocks() {
    fn block(status: QueryStatus) -> QueryResultBlock {
        QueryResultBlock {
            target_label: String::new(),
            server_id: None,
            server_vendor: None,
            transport: ValidationTransport::Dns,
            extras: Vec::new(),
            url: None,
            host_for_json: None,
            port_for_json: None,
            elapsed: Duration::ZERO,
            status,
            records: Vec::new(),
            asked_types: vec!["A".to_string()],
            queried_name: "example.com".to_string(),
        }
    }
    assert_eq!(exit_code_for(&[block(QueryStatus::NoError)]), 0);
    assert_eq!(
        exit_code_for(&[block(QueryStatus::NoError), block(QueryStatus::NxDomain)]),
        1
    );
    assert_eq!(
        exit_code_for(&[block(QueryStatus::NoError), block(QueryStatus::Timeout)]),
        2
    );
    // Implicit skip doesn't change the exit code
    assert_eq!(
        exit_code_for(&[
            block(QueryStatus::NoError),
            block(QueryStatus::Skipped {
                reason: "block not configured or disabled".to_string()
            })
        ]),
        0
    );
}
