use super::*;

#[test]
fn parses_per_server_mcp_permissions() {
    let config = config();
    let home = config.selected_server(Some("home")).unwrap();

    assert_eq!(home.id, "home");
    assert_eq!(home.vendor, VendorKind::Technitium);
    assert_eq!(home.base_url.as_deref(), Some("http://home.local:5380"));
    assert_eq!(home.mcp.access, vec![PolicyRule::Read]);
    assert_eq!(home.mcp.allowed_zones, ["example.com", "internal.lan"]);
    assert!(home.mcp.show_settings_secrets);

    let lab = config.selected_server(Some("lab")).unwrap();
    assert!(!lab.mcp.show_settings_secrets);
}

#[test]
fn requires_server_selection_when_multiple_servers_exist() {
    let err = config().selected_server(None).unwrap_err();

    assert!(err.to_string().contains("multiple DNS servers"));
}

#[test]
fn rejects_duplicate_server_ids_case_insensitively() {
    let config: AppConfig = toml::from_str(
        r#"
                [[servers]]
                id = "home"

                [[servers]]
                id = "HOME"
            "#,
    )
    .expect("config should parse before validation");

    let err = config.validate().unwrap_err();

    assert!(err.to_string().contains("duplicate DNS server id"));
}

#[test]
fn rejects_unknown_mcp_permission_fields() {
    let err = toml::from_str::<AppConfig>(
        r#"
                [[servers]]
                id = "home"

                [servers.mcp]
                read_only = true
            "#,
    )
    .unwrap_err();

    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn selected_server_matches_case_insensitively() {
    let config = config();

    assert_eq!(config.selected_server(Some("HOME")).unwrap().id, "home");
}

#[test]
fn load_creates_missing_config_with_defaults() {
    let path = temp_config_path("missing-default");

    let config = AppConfig::load(Some(path.clone()))
        .expect("missing config should be created and loaded")
        .expect("created config should load");

    let server = config.selected_server(None).unwrap();
    assert_eq!(server.id, "default");
    assert_eq!(server.vendor, VendorKind::Technitium);
    assert_eq!(server.base_url.as_deref(), Some("http://localhost:5380"));
    assert_eq!(
        server.token_env.as_deref(),
        Some("DNSYNC_TECHNITIUM_API_TOKEN")
    );
    assert!(server.token.is_none());
    {
        use std::collections::HashSet;
        let full: HashSet<PolicyRule> = [PolicyRule::Read, PolicyRule::Write, PolicyRule::Delete]
            .into_iter()
            .collect();
        let actual: HashSet<PolicyRule> = server.mcp.access.iter().cloned().collect();
        assert_eq!(actual, full);
    }
    assert!(server.mcp.allowed_zones.is_empty());

    // Verify the written file round-trips and uses token_env, not token
    let written = std::fs::read_to_string(&path).unwrap();
    let reparsed: AppConfig =
        toml::from_str(&written).expect("written config should be valid TOML");
    let reparsed_server = reparsed.selected_server(None).unwrap();
    assert_eq!(
        reparsed_server.token_env.as_deref(),
        Some("DNSYNC_TECHNITIUM_API_TOKEN")
    );
    assert!(reparsed_server.token.is_none());

    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn load_does_not_overwrite_existing_config() {
    let path = temp_config_path("existing-config");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        r#"
                [[servers]]
                id = "custom"
                token = "custom-token"
            "#,
    )
    .unwrap();
    // match the permissions the production code sets so the load check passes
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let config = AppConfig::load(Some(path.clone()))
        .expect("existing config should load")
        .expect("config should be present");

    assert_eq!(config.selected_server(None).unwrap().id, "custom");
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("custom-token")
    );

    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn init_config_refuses_to_overwrite_existing_config() {
    let path = temp_config_path("init-existing-config");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "existing = true\n").unwrap();

    let err = init_config(Some(path.clone()), false).unwrap_err();

    assert!(err.to_string().contains("already exists"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "existing = true\n");

    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn init_config_force_overwrites_existing_config() {
    let path = temp_config_path("init-force-config");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "existing = true\n").unwrap();

    let written_path = init_config(Some(path.clone()), true).unwrap();

    assert_eq!(written_path, path);

    let written = std::fs::read_to_string(&written_path).unwrap();
    let config: AppConfig = toml::from_str(&written).expect("written config should be valid TOML");
    let server = config.selected_server(None).unwrap();
    assert_eq!(server.id, "default");
    assert_eq!(
        server.token_env.as_deref(),
        Some("DNSYNC_TECHNITIUM_API_TOKEN")
    );
    assert!(server.token.is_none());

    std::fs::remove_dir_all(written_path.parent().unwrap()).unwrap();
}

#[test]
fn cli_base_url_override_wins_over_config() {
    let server = config().selected_server(Some("home")).unwrap().clone();

    assert_eq!(
        server.resolved_base_url(Some("http://override.local:5380")),
        "http://override.local:5380"
    );
}

#[test]
fn technitium_base_url_defaults_to_localhost() {
    let server = DnsServerConfig {
        id: "home".to_string(),
        vendor: VendorKind::Technitium,
        location: None,
        base_url: None,
        base_url_env: None,
        token: None,
        token_env: None,
        org_id: None,
        cluster: None,
        dns: None,
        dot: None,
        doh: None,
        doq: None,
        mcp: McpPermissions::default(),
        validation_endpoints: Vec::new(),
    };

    assert_eq!(server.resolved_base_url(None), TECHNITIUM_DEFAULT_BASE_URL);
}

#[test]
fn pangolin_base_url_defaults_to_cloud_api() {
    let server = DnsServerConfig {
        id: "cloud".to_string(),
        vendor: VendorKind::Pangolin,
        location: None,
        base_url: None,
        base_url_env: None,
        token: None,
        token_env: None,
        org_id: None,
        cluster: None,
        dns: None,
        dot: None,
        doh: None,
        doq: None,
        mcp: McpPermissions::default(),
        validation_endpoints: Vec::new(),
    };

    assert_eq!(server.resolved_base_url(None), PANGOLIN_DEFAULT_BASE_URL);
}

#[test]
fn cli_token_override_wins_over_config() {
    let server = config().selected_server(Some("home")).unwrap().clone();

    assert_eq!(
        server
            .resolved_token(Some("override-token"))
            .unwrap()
            .expose_for_auth(),
        "override-token"
    );
}

#[test]
fn debug_default_config_path_uses_repo_root() {
    let path = default_config_path().expect("debug builds should have a default config path");

    assert_eq!(
        path,
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(".config")
            .join("dnsync")
            .join("config.toml")
    );
}

#[test]
fn starter_config_contains_token_env() {
    let toml = AppConfig::render_starter_toml().unwrap();
    assert!(
        toml.contains(r#"token_env = "DNSYNC_TECHNITIUM_API_TOKEN""#),
        "starter TOML should contain token_env assignment"
    );
}

#[test]
fn starter_config_does_not_contain_literal_token() {
    let toml = AppConfig::render_starter_toml().unwrap();
    assert!(
        !toml.lines().any(|l| l.trim_start().starts_with("token =")),
        "starter TOML must not contain a bare `token = ...` key"
    );
}

#[test]
fn starter_config_round_trips() {
    let toml = AppConfig::render_starter_toml().unwrap();
    let reparsed: AppConfig = toml::from_str(&toml).expect("starter TOML should parse back");
    let server = reparsed.selected_server(None).unwrap();
    assert_eq!(server.id, "default");
    assert_eq!(server.vendor, VendorKind::Technitium);
    assert_eq!(server.base_url.as_deref(), Some("http://localhost:5380"));
    assert_eq!(
        server.token_env.as_deref(),
        Some("DNSYNC_TECHNITIUM_API_TOKEN")
    );
    assert!(server.token.is_none());
    {
        use std::collections::HashSet;
        let full: HashSet<PolicyRule> = [PolicyRule::Read, PolicyRule::Write, PolicyRule::Delete]
            .into_iter()
            .collect();
        let actual: HashSet<PolicyRule> = server.mcp.access.iter().cloned().collect();
        assert_eq!(actual, full);
    }
    assert!(server.mcp.allowed_zones.is_empty());
}

#[test]
fn starter_config_validates() {
    AppConfig::starter()
        .validate()
        .expect("starter config should pass validation");
}

#[cfg(unix)]
#[test]
fn written_config_file_has_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let path = temp_config_path("perms-file");

    init_config(Some(path.clone()), false).unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "config file should be owner read/write only (0600)"
    );

    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn written_config_dir_has_owner_only_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let path = temp_config_path("perms-dir");

    init_config(Some(path.clone()), false).unwrap();

    let dir = path.parent().unwrap();
    let mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "config directory should be owner-only (0700)");

    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn redact_replaces_token_but_preserves_token_env() {
    let cfg: AppConfig = toml::from_str(
        r#"
                [[servers]]
                id = "home"
                token = "secret"
                token_env = "MY_TOKEN_VAR"
            "#,
    )
    .unwrap();

    let redacted = cfg.redact();
    let server = redacted.selected_server(None).unwrap();
    assert_eq!(
        server.token.as_ref().map(ApiToken::expose_for_auth),
        Some("[redacted]")
    );
    assert_eq!(server.token_env.as_deref(), Some("MY_TOKEN_VAR"));
}

#[test]
fn redact_leaves_none_token_as_none() {
    let cfg: AppConfig = toml::from_str(
        r#"
                [[servers]]
                id = "home"
                token_env = "MY_TOKEN_VAR"
            "#,
    )
    .unwrap();

    let redacted = cfg.redact();
    assert!(redacted.selected_server(None).unwrap().token.is_none());
}
