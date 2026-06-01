use super::*;

#[test]
fn config_validation_endpoint_roundtrip() {
    let cfg: AppConfig = toml::from_str(
        r#"
                [[servers]]
                id = "home"
                token_env = "MY_TOKEN_VAR"

                [[servers.validation_endpoints]]
                name = "router"
                transport = "dns"
                address = "192.168.1.1"
                port = 53
                enabled = true
                timeout_ms = 1500

                [[servers.validation_endpoints]]
                name = "cloudflare-doh"
                transport = "doh"
                url = "https://cloudflare-dns.com/dns-query"
                enabled = true

                [[servers.validation_endpoints]]
                name = "quad9-dot"
                transport = "dot"
                address = "9.9.9.9"
                port = 853
                tls_server_name = "dns.quad9.net"
            "#,
    )
    .unwrap();

    cfg.validate().unwrap();
    let rendered = cfg.render_toml().unwrap();
    let reparsed: AppConfig = toml::from_str(&rendered).unwrap();
    let endpoints = &reparsed.selected_server(None).unwrap().validation_endpoints;

    assert_eq!(endpoints.len(), 3);
    assert_eq!(endpoints[0].name, "router");
    assert_eq!(endpoints[0].transport, ValidationTransport::Dns);
    assert_eq!(
        endpoints[1].url.as_deref(),
        Some("https://cloudflare-dns.com/dns-query")
    );
    assert_eq!(
        endpoints[2].tls_server_name.as_deref(),
        Some("dns.quad9.net")
    );
    assert!(rendered.contains("[[servers.validation_endpoints]]"));
}

#[test]
fn server_transport_blocks_roundtrip() {
    let cfg: AppConfig = toml::from_str(
        r#"
                [[servers]]
                id = "dns1"
                vendor = "technitium"
                cluster = "home-dns"

                [servers.dns]
                enabled = true
                addr = "10.5.0.53:53"
                timeout_ms = 1500

                [servers.dot]
                enabled = true
                addr = "10.5.0.53:853"
                server_name = "dns1.hankin.io"

                [servers.doh]
                enabled = true
                url = "https://dns1.hankin.io/dns-query"
                addr = "10.5.0.53:443"
                server_name = "dns1.hankin.io"

                [servers.doq]
                enabled = true
                addr = "10.5.0.53:853"
                server_name = "dns1.hankin.io"
                timeout_ms = 2000

                [clusters.home-dns]
                members = ["dns1"]
            "#,
    )
    .unwrap();

    cfg.validate().unwrap();
    let rendered = cfg.render_toml().unwrap();
    let reparsed: AppConfig = toml::from_str(&rendered).unwrap();
    let server = reparsed.selected_server(None).unwrap();

    assert_eq!(server.cluster.as_deref(), Some("home-dns"));
    assert_eq!(
        server.dns.as_ref().unwrap().addr.as_deref(),
        Some("10.5.0.53:53")
    );
    assert_eq!(
        server.dot.as_ref().unwrap().server_name.as_deref(),
        Some("dns1.hankin.io")
    );
    assert_eq!(
        server.doh.as_ref().unwrap().url.as_deref(),
        Some("https://dns1.hankin.io/dns-query")
    );
    let doq = server.doq.as_ref().unwrap();
    assert!(doq.enabled);
    assert_eq!(doq.addr.as_deref(), Some("10.5.0.53:853"));
    assert_eq!(doq.server_name.as_deref(), Some("dns1.hankin.io"));
    assert_eq!(doq.timeout_ms, Some(2000));
    assert!(rendered.contains("[servers.dns]"));
    assert!(rendered.contains("[servers.dot]"));
    assert!(rendered.contains("[servers.doh]"));
    assert!(rendered.contains("[servers.doq]"));
}

#[test]
fn cloudflare_external_server_gets_provider_transport_defaults() {
    let cfg: AppConfig = toml::from_str(
        r#"
                [[servers]]
                id = "cf"
                vendor = "cloudflare"
                token_env = "DNSYNC_CLOUDFLARE_API_TOKEN"
            "#,
    )
    .unwrap();

    cfg.validate().unwrap();
    let server = cfg.selected_server(None).unwrap();

    assert_eq!(
        server.dns.as_ref().unwrap().addr.as_deref(),
        Some("1.1.1.1:53")
    );
    assert_eq!(
        server.dot.as_ref().unwrap().server_name.as_deref(),
        Some("cloudflare-dns.com")
    );
    let doh = server.doh.as_ref().unwrap();
    assert_eq!(
        doh.url.as_deref(),
        Some("https://cloudflare-dns.com/dns-query")
    );
    assert_eq!(doh.addr.as_deref(), Some("1.1.1.1:443"));
    assert_eq!(
        server.doq.as_ref().unwrap().server_name.as_deref(),
        Some("cloudflare-dns.com")
    );
}

#[test]
fn cloudflare_transport_blocks_override_provider_defaults() {
    let cfg: AppConfig = toml::from_str(
        r#"
                [[servers]]
                id = "cf"
                vendor = "cloudflare"
                token_env = "DNSYNC_CLOUDFLARE_API_TOKEN"

                [servers.dns]
                enabled = false

                [servers.doh]
                enabled = true
                url = "https://security.cloudflare-dns.com/dns-query"
                addr = "1.1.1.2:443"
                server_name = "security.cloudflare-dns.com"
                timeout_ms = 2500
            "#,
    )
    .unwrap();

    cfg.validate().unwrap();
    let server = cfg.selected_server(None).unwrap();

    let dns = server.dns.as_ref().unwrap();
    assert!(!dns.enabled);
    assert_eq!(dns.addr, None);

    let doh = server.doh.as_ref().unwrap();
    assert_eq!(
        doh.url.as_deref(),
        Some("https://security.cloudflare-dns.com/dns-query")
    );
    assert_eq!(doh.addr.as_deref(), Some("1.1.1.2:443"));
    assert_eq!(
        doh.server_name.as_deref(),
        Some("security.cloudflare-dns.com")
    );
    assert_eq!(doh.timeout_ms, Some(2500));

    assert_eq!(
        server.dot.as_ref().unwrap().addr.as_deref(),
        Some("1.1.1.1:853")
    );
    assert_eq!(
        server.doq.as_ref().unwrap().addr.as_deref(),
        Some("1.1.1.1:853")
    );
}

#[test]
fn cloudflare_local_server_does_not_get_provider_transport_defaults() {
    let cfg: AppConfig = toml::from_str(
        r#"
                [[servers]]
                id = "cf-local"
                vendor = "cloudflare"
                location = "local"
                token_env = "DNSYNC_CLOUDFLARE_API_TOKEN"
            "#,
    )
    .unwrap();

    cfg.validate().unwrap();
    let server = cfg.selected_server(None).unwrap();

    assert!(server.dns.is_none());
    assert!(server.dot.is_none());
    assert!(server.doh.is_none());
    assert!(server.doq.is_none());
}

#[test]
fn validate_rejects_doq_without_addr() {
    let cfg: AppConfig = toml::from_str(
        r#"
                [[servers]]
                id = "dns1"

                [servers.doq]
                enabled = true
            "#,
    )
    .unwrap();

    let err = cfg.validate().unwrap_err();
    assert!(
        err.to_string()
            .contains("enabled doq transport without addr"),
        "unexpected error: {err}",
    );
}

#[test]
fn disabled_doq_block_does_not_require_addr() {
    let cfg: AppConfig = toml::from_str(
        r#"
                [[servers]]
                id = "dns1"

                [servers.doq]
                enabled = false
            "#,
    )
    .unwrap();

    cfg.validate().unwrap();
}

#[test]
fn disabled_transport_blocks_can_omit_endpoints() {
    let cfg: AppConfig = toml::from_str(
        r#"
                [[servers]]
                id = "dns1"

                [servers.dns]
                enabled = false

                [servers.dot]
                enabled = false

                [servers.doh]
                enabled = false
            "#,
    )
    .unwrap();

    cfg.validate().unwrap();
    let rendered = cfg.render_toml().unwrap();

    assert!(rendered.contains("[servers.dns]"));
    assert!(rendered.contains("enabled = false"));
    assert!(!rendered.contains("addr = \"\""));
    assert!(!rendered.contains("url = \"\""));
}

#[test]
fn cluster_config_roundtrip() {
    let cfg: AppConfig = toml::from_str(
        r#"
                [[servers]]
                id = "dns1"
                vendor = "technitium"
                cluster = "home-dns"

                [[servers]]
                id = "dns2"
                vendor = "technitium"
                cluster = "home-dns"

                [clusters.home-dns]
                vendor = "technitium"
                members = ["dns1", "dns2"]
                write_policy = "primary_only"
                primary = "auto"
                catalog_zone = "auto"
                preferred_writer = "dns1"
            "#,
    )
    .unwrap();

    cfg.validate().unwrap();
    let rendered = cfg.render_toml().unwrap();
    let reparsed: AppConfig = toml::from_str(&rendered).unwrap();
    let cluster = reparsed.clusters.get("home-dns").unwrap();

    assert_eq!(cluster.members, ["dns1", "dns2"]);
    assert_eq!(cluster.write_policy, ClusterWritePolicy::PrimaryOnly);
    assert_eq!(cluster.primary.as_deref(), Some("auto"));
    assert_eq!(cluster.catalog_zone.as_deref(), Some("auto"));
    assert_eq!(cluster.preferred_writer.as_deref(), Some("dns1"));
    assert!(rendered.contains("[clusters.home-dns]"));
}

#[test]
fn cluster_rejects_unknown_members() {
    let cfg: AppConfig = toml::from_str(
        r#"
                [[servers]]
                id = "dns1"

                [clusters.home-dns]
                members = ["dns1", "dns2"]
            "#,
    )
    .unwrap();

    let err = cfg.validate().unwrap_err();
    assert!(err.to_string().contains("unknown DNS server 'dns2'"));
}

#[test]
fn server_rejects_unknown_cluster_reference() {
    let cfg: AppConfig = toml::from_str(
        r#"
                [[servers]]
                id = "dns1"
                cluster = "missing"
            "#,
    )
    .unwrap();

    let err = cfg.validate().unwrap_err();
    assert!(
        err.to_string()
            .contains("DNS server 'dns1' references unknown cluster 'missing'")
    );
}
