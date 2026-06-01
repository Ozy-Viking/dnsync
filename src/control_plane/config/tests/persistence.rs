use super::*;

#[test]
fn config_rejects_invalid_validation_endpoint() {
    let cfg: AppConfig = toml::from_str(
        r#"
                [[servers]]
                id = "home"
                token_env = "MY_TOKEN_VAR"

                [[servers.validation_endpoints]]
                name = ""
                transport = "dns"
                address = "192.168.1.1"
            "#,
    )
    .unwrap();

    let err = cfg.validate().unwrap_err();
    assert!(err.to_string().contains("empty name"));

    let cfg: AppConfig = toml::from_str(
        r#"
                [[servers]]
                id = "home"
                token_env = "MY_TOKEN_VAR"

                [[servers.validation_endpoints]]
                name = "missing-url"
                transport = "doh"
            "#,
    )
    .unwrap();

    let err = cfg.validate().unwrap_err();
    assert!(err.to_string().contains("requires url"));
}

#[test]
fn config_print_redacts_tokens_but_keeps_validation_endpoints() {
    let cfg: AppConfig = toml::from_str(
        r#"
                [[servers]]
                id = "home"
                token = "secret"

                [[servers.validation_endpoints]]
                name = "router"
                transport = "dns"
                address = "192.168.1.1"
            "#,
    )
    .unwrap();

    let redacted = cfg.redact();
    let server = redacted.selected_server(None).unwrap();

    assert_eq!(
        server.token.as_ref().map(ApiToken::expose_for_auth),
        Some("[redacted]")
    );
    assert_eq!(
        server.validation_endpoints,
        cfg.servers[0].validation_endpoints
    );
}

#[test]
fn load_if_exists_returns_none_when_no_file() {
    let path = temp_config_path("load-if-exists-missing");
    assert!(!path.exists());

    let result = AppConfig::load_if_exists(Some(path)).unwrap();
    assert!(result.is_none());
}

#[test]
fn load_if_exists_returns_config_when_file_present() {
    let path = temp_config_path("load-if-exists-present");
    // Use init_config so the file is created with correct permissions
    init_config(Some(path.clone()), false).unwrap();

    let config = AppConfig::load_if_exists(Some(path.clone()))
        .expect("should load")
        .expect("should be Some");
    assert_eq!(config.selected_server(None).unwrap().id, "default");

    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

/// Regression guard for the token leak via instrumentation: a populated
/// config must never reveal the token through `Debug` (used by `?value`
/// tracing fields / `#[instrument]`) or through serde serialisation, while
/// the real value is still reachable for authentication.
#[test]
fn config_never_leaks_token_via_debug_or_serialize() {
    const SECRET: &str = "super-secret-token-value";
    let config = AppConfig {
        servers: vec![DnsServerConfig {
            id: "leaky".to_string(),
            vendor: VendorKind::Technitium,
            location: None,
            base_url: Some("http://192.168.1.10:5380".to_string()),
            base_url_env: None,
            token: Some(ApiToken::new(SECRET)),
            token_env: None,
            org_id: None,
            cluster: None,
            dns: None,
            dot: None,
            doh: None,
            doq: None,
            mcp: McpPermissions::default(),
            validation_endpoints: Vec::new(),
        }],
        ..AppConfig::default()
    };

    let debug = format!("{config:?}");
    assert!(!debug.contains(SECRET), "Debug leaked token: {debug}");
    assert!(debug.contains("ApiToken([REDACTED])"));

    let json = serde_json::to_string(&config).unwrap();
    assert!(!json.contains(SECRET), "Serialize leaked token: {json}");

    // The real value is still available at the auth boundary.
    let token = config.servers[0].token.as_ref().unwrap();
    assert_eq!(token.expose_for_auth(), SECRET);
}

#[test]
fn add_server_creates_config_with_single_server() {
    let path = temp_config_path("add-server-new");
    let server = DnsServerConfig {
        id: "myserver".to_string(),
        vendor: VendorKind::Technitium,
        location: None,
        base_url: Some("http://192.168.1.10:5380".to_string()),
        base_url_env: None,
        token: None,
        token_env: Some("MY_API_TOKEN".to_string()),
        org_id: None,
        cluster: None,
        dns: None,
        dot: None,
        doh: None,
        doq: None,
        mcp: McpPermissions::default(),
        validation_endpoints: Vec::new(),
    };

    let written = add_server(Some(path.clone()), server).unwrap();
    assert_eq!(written, path);

    let config = AppConfig::load(Some(path.clone())).unwrap().unwrap();
    let s = config.selected_server(None).unwrap();
    assert_eq!(s.id, "myserver");
    assert_eq!(s.token_env.as_deref(), Some("MY_API_TOKEN"));

    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn add_server_appends_to_existing_config() {
    let path = temp_config_path("add-server-existing");
    init_config(Some(path.clone()), false).unwrap();

    let server = DnsServerConfig {
        id: "lab".to_string(),
        vendor: VendorKind::Technitium,
        location: None,
        base_url: Some("http://192.168.1.20:5380".to_string()),
        base_url_env: None,
        token: None,
        token_env: Some("LAB_TOKEN".to_string()),
        org_id: None,
        cluster: None,
        dns: None,
        dot: None,
        doh: None,
        doq: None,
        mcp: McpPermissions::default(),
        validation_endpoints: Vec::new(),
    };

    add_server(Some(path.clone()), server).unwrap();

    let config = AppConfig::load(Some(path.clone())).unwrap().unwrap();
    assert_eq!(config.servers.len(), 2);
    assert!(config.selected_server(Some("default")).is_ok());
    assert!(config.selected_server(Some("lab")).is_ok());

    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn add_server_preserves_comments_in_existing_config() {
    let path = temp_config_path("add-server-comments");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let original = concat!(
        "# My DNS servers\n",
        "[[servers]]\n",
        "id = \"home\"\n",
        "# Home server uses its own env var\n",
        "token_env = \"HOME_TOKEN\"\n",
    );
    std::fs::write(&path, original).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let server = DnsServerConfig {
        id: "lab".to_string(),
        vendor: VendorKind::Technitium,
        location: None,
        base_url: None,
        base_url_env: None,
        token: None,
        token_env: Some("LAB_TOKEN".to_string()),
        org_id: None,
        cluster: None,
        dns: None,
        dot: None,
        doh: None,
        doq: None,
        mcp: McpPermissions::default(),
        validation_endpoints: Vec::new(),
    };
    add_server(Some(path.clone()), server).unwrap();

    let written = std::fs::read_to_string(&path).unwrap();
    assert!(
        written.contains("# My DNS servers"),
        "top-level comment should be preserved"
    );
    assert!(
        written.contains("# Home server uses its own env var"),
        "inline comment should be preserved"
    );
    assert!(
        written.contains("id = \"lab\""),
        "new server should be appended"
    );

    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn update_defaults_adds_missing_values_without_overwriting_existing_ones() {
    let path = temp_config_path("update-defaults");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let original = concat!(
        "# Existing config\n",
        "[[servers]]\n",
        "id = \"cf\"\n",
        "vendor = \"cloudflare\"\n",
        "token_env = \"CF_TOKEN\"\n",
        "\n",
        "[servers.dns]\n",
        "enabled = false\n",
        "\n",
        "[[servers]]\n",
        "id = \"home\"\n",
        "base_url_env = \"HOME_URL\"\n",
        "token_env = \"HOME_TOKEN\"\n",
    );
    write_private_file(&path, original).unwrap();

    let report = update_defaults(Some(path.clone())).unwrap();

    assert_eq!(report.updated_servers, 2);
    assert!(report.added_values >= 1);

    let updated = std::fs::read_to_string(&path).unwrap();
    assert!(updated.contains("# Existing config"));
    assert!(updated.contains("base_url = \"https://api.cloudflare.com/client/v4\""));
    assert!(updated.contains("[servers.dot]"));
    assert!(updated.contains("server_name = \"cloudflare-dns.com\""));
    assert!(updated.contains("[servers.doh]"));
    assert!(updated.contains("[servers.doq]"));
    assert!(updated.contains("base_url_env = \"HOME_URL\""));
    assert!(!updated.contains("base_url = \"http://localhost:5380\""));

    let parsed = AppConfig::load(Some(path.clone())).unwrap().unwrap();
    let cf = parsed.selected_server(Some("cf")).unwrap();
    assert_eq!(cf.dns.as_ref().unwrap().enabled, false);
    assert_eq!(cf.dns.as_ref().unwrap().addr, None);

    let second = update_defaults(Some(path.clone())).unwrap();
    assert_eq!(second.updated_servers, 0);
    assert_eq!(second.added_values, 0);

    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn add_server_rejects_duplicate_id() {
    let path = temp_config_path("add-server-duplicate");
    init_config(Some(path.clone()), false).unwrap();

    let server = DnsServerConfig {
        id: "default".to_string(), // already exists
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

    let err = add_server(Some(path.clone()), server).unwrap_err();
    assert!(err.to_string().contains("duplicate DNS server id"));

    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn load_errors_if_config_is_world_readable() {
    use std::os::unix::fs::PermissionsExt;
    let path = temp_config_path("world-readable");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, AppConfig::render_starter_toml().unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let err = AppConfig::load(Some(path.clone())).unwrap_err();

    assert!(
        err.to_string().contains("chmod 600"),
        "error should include remediation command"
    );

    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
