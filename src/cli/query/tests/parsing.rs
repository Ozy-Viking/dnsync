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
