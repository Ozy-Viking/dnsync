#[cfg(not(any(feature = "technitium", feature = "pangolin", feature = "cloudflare")))]
compile_error!(
    "No DNS vendor feature is enabled. Enable at least one vendor feature, such as `technitium`, `pangolin`, or `cloudflare`."
);

#[cfg(not(any(feature = "technitium", feature = "pangolin", feature = "cloudflare")))]
fn main() {}

#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
use dnslib::{
    cli::{self, RecordCmd, ZoneCmd},
    control_plane::{config, policy},
    core::{dns::service::DnsService, error},
    mcp::server,
    vendors::runtime::{ClientOverrides, VendorClient},
};

use std::process;

use clap::Parser;
use miette::Report;
use rmcp::ServiceExt;
use tracing_subscriber::{EnvFilter, fmt};

use cli::{Cli, Command, ConfigCmd};
use error::Error;
use policy::Policy;
#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
use server::DnsServer;

#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    process::exit(run(cli).await);
}

#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
async fn run(cli: Cli) -> i32 {
    if let Command::Completions { shell } = cli.command {
        cli::completions::generate_completions(shell);
        return 0;
    }

    if let Command::ServerIds = cli.command {
        let config = config::AppConfig::load_if_exists(cli.config).ok().flatten();
        if let Some(cfg) = config {
            for server in &cfg.servers {
                println!("{}", server.id);
            }
        }
        return 0;
    }

    if let Command::Config(config_cmd) = cli.command {
        return match config_cmd {
            ConfigCmd::Init { force } => match config::init_config(cli.config, force) {
                Ok(path) => {
                    println!("Wrote config file: {}", path.display());
                    0
                }
                Err(e) => render_error(e),
            },

            ConfigCmd::Print => {
                let toml = match config::AppConfig::load_if_exists(cli.config.clone()) {
                    Ok(Some(cfg)) => cfg.redact().render_toml(),
                    Ok(None) => config::AppConfig::render_starter_toml(),
                    Err(e) => return render_error(e),
                };
                match toml {
                    Ok(s) => {
                        print!("{s}");
                        0
                    }
                    Err(e) => render_error(e),
                }
            }

            ConfigCmd::Add {
                id,
                vendor,
                location,
                base_url,
                token_env,
                token,
                org_id,
                access,
                allow_zone,
            } => {
                let server = if id.is_none() {
                    match cli::interactive::run_add_wizard() {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("Error: {e:?}");
                            return 1;
                        }
                    }
                } else {
                    config::DnsServerConfig {
                        id: id.unwrap(),
                        vendor,
                        location,
                        base_url,
                        token,
                        token_env,
                        org_id,
                        mcp: config::McpPermissions {
                            access,
                            allowed_zones: allow_zone,
                        },
                    }
                };
                match config::add_server(cli.config, server) {
                    Ok(path) => {
                        println!("Updated config file: {}", path.display());
                        0
                    }
                    Err(e) => render_error(e),
                }
            }
        };
    }

    let app_config = match config::AppConfig::load(cli.config.clone()) {
        Ok(config) => config,
        Err(e) => return render_error(e),
    };

    if let Command::Record(RecordCmd::List {
        domain,
        zone,
        all_subdomains,
        servers: subcmd_servers,
        use_local_ip,
        json,
    }) = &cli.command
    {
        // Accept --server before or after the subcommand, preferring the more
        // specific (subcommand-level) flag when both are given.
        let effective_servers: &[String] = if !subcmd_servers.is_empty() {
            subcmd_servers
        } else {
            &cli.servers
        };
        let bare_label_without_zone = zone.is_none()
            && domain
                .as_deref()
                .is_some_and(|domain| !domain.contains('.'));
        let default_all_servers = (domain.is_none() || bare_label_without_zone)
            && effective_servers.is_empty()
            && app_config.as_ref().is_some_and(|c| c.servers.len() > 1);
        if cli.all || !effective_servers.is_empty() || default_all_servers {
            return run_record_list_across_servers(
                &cli,
                app_config.as_ref(),
                domain.as_deref(),
                zone.as_deref(),
                *all_subdomains,
                effective_servers,
                *use_local_ip,
                *json,
            )
            .await;
        }
    }

    if let Command::Zone(ZoneCmd::Transfer {
        zone,
        from,
        to,
        overwrite,
        overwrite_zone,
    }) = &cli.command
    {
        if cli.token.is_some() || cli.base_url.is_some() {
            return render_error(Error::parse(
                "zone transfer does not accept --token/--base-url; \
                 configure credentials per server via config file or environment variables",
            ));
        }
        return run_zone_transfer(
            app_config.as_ref(),
            zone,
            from,
            to,
            *overwrite,
            *overwrite_zone,
        )
        .await;
    }

    if cli.servers.len() > 1 {
        return render_error(Error::parse(
            "multiple --server flags are only valid with `record list`; \
             use a single --server for all other commands",
        ));
    }

    let policy = match cli_policy(&cli, app_config.as_ref()) {
        Ok(p) => p,
        Err(e) => return render_error(e),
    };

    let client = match VendorClient::from_cli_options(
        app_config.as_ref(),
        ClientOverrides {
            selected_server: cli.servers.first().map(|s| s.as_str()),
            base_url: cli.base_url.as_deref(),
            token: cli.token.as_deref(),
        },
    ) {
        Ok(client) => client,
        Err(e) => return render_error(e),
    };

    run_with_client(cli, client, policy).await
}

#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
async fn run_record_list_across_servers(
    cli: &Cli,
    app_config: Option<&config::AppConfig>,
    domain: Option<&str>,
    zone: Option<&str>,
    all_subdomains: bool,
    servers: &[String],
    use_local_ip: bool,
    json: bool,
) -> i32 {
    use dnslib::cli::runner::{
        filter_records_by_domain, infer_zone, list_records_for_all_zones, resolve_fqdn,
        search_bare_label_in_zones,
    };
    use dnslib::core::dns::service::{ListRecordsOptions, ZoneRead};

    if cli.token.is_some() || cli.base_url.is_some() {
        return render_error(Error::parse(
            "cross-server record list does not accept --token/--base-url; configure credentials per server via config file or environment variables",
        ));
    }

    let Some(cfg) = app_config else {
        return render_error(Error::parse(
            "--all/--server for record list requires a config file with server entries",
        ));
    };

    let bare_label_without_zone =
        zone.is_none() && domain.is_some_and(|domain| !domain.contains('.'));
    let query_all_servers =
        cli.all || (servers.is_empty() && (domain.is_none() || bare_label_without_zone));
    let selected: Vec<&config::DnsServerConfig> = if query_all_servers {
        cfg.servers.iter().collect()
    } else {
        let mut picked = Vec::with_capacity(servers.len());
        for server_id in servers {
            match cfg.selected_server(Some(server_id.as_str())) {
                Ok(s) => picked.push(s),
                Err(e) => return render_error(e),
            }
        }
        picked
    };

    if selected.is_empty() {
        return render_error(Error::parse(
            "--all requested, but no servers are configured; add at least one server in the config file",
        ));
    }

    let domain_query = domain.map(|domain| {
        let effective_fqdn = resolve_fqdn(domain, zone);
        let is_bare_label = zone.is_none() && !effective_fqdn.contains('.');
        let (query_domain, query_zone) = if !is_bare_label && all_subdomains {
            let zone_name = zone
                .map(str::to_string)
                .or_else(|| infer_zone(&effective_fqdn).filter(|z| z.contains('.')))
                .unwrap_or_else(|| effective_fqdn.clone());
            (zone_name.clone(), Some(zone_name))
        } else {
            (effective_fqdn.clone(), zone.map(str::to_string))
        };
        (effective_fqdn, is_bare_label, query_domain, query_zone)
    });
    let options = ListRecordsOptions {
        use_local_ip,
        all_subdomains,
    };
    let mut json_zones = Vec::new();
    let mut printed_servers = 0usize;

    for server in &selected {
        let client = match VendorClient::from_server(server) {
            Ok(client) => client,
            Err(e) => return render_error(e),
        };
        let result = match &domain_query {
            None => list_records_for_all_zones(&client, options).await,
            Some((effective_fqdn, true, _, _)) => {
                search_bare_label_in_zones(&client, effective_fqdn, all_subdomains, options).await
            }
            Some((_, false, query_domain, query_zone)) => {
                client
                    .list_records(query_domain, query_zone.as_deref(), options)
                    .await
            }
        };

        match result {
            Ok(mut response) => {
                // search_bare_label_in_zones already filters internally; only
                // apply the outer filter for non-bare-label --all-subdomains queries.
                if let Some((effective_fqdn, false, _, _)) = &domain_query
                    && all_subdomains
                {
                    filter_records_by_domain(&mut response, effective_fqdn, true);
                }
                if json {
                    for mut zone_records in response.zones {
                        if zone_records.zone.id.is_none() {
                            zone_records.zone.id = Some(zone_records.zone.name.clone());
                        }
                        json_zones.push(serde_json::json!({
                            "serverName": server.id,
                            "serverId": server.id,
                            "vendor": format!("{:?}", server.vendor),
                            "zone": zone_records.zone,
                            "records": zone_records.records,
                        }));
                    }
                } else if !response.zones.is_empty() {
                    if printed_servers > 0 {
                        println!();
                    }
                    println!("=== Server: {} ({:?}) ===", server.id, server.vendor);
                    cli::records::print_records_table(&response);
                    printed_servers += 1;
                }
            }
            Err(e) => return render_error(e),
        }
    }

    if json {
        match serde_json::to_string_pretty(&json_zones) {
            Ok(pretty) => println!("{pretty}"),
            Err(e) => {
                return render_error(Error::parse(format!(
                    "could not serialise record list response: {e}"
                )));
            }
        }
    }

    0
}

#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
async fn run_with_client<C: DnsService + Clone + Send + Sync + 'static>(
    cli: Cli,
    client: C,
    policy: Policy,
) -> i32 {
    match cli.command {
        Command::Mcp => {
            match policy.access {
                policy::PolicyRule::Read => {
                    tracing::info!("MCP server starting in read-only mode")
                }
                policy::PolicyRule::Write => {
                    tracing::info!("MCP server starting in write mode (deletes disabled)")
                }
                policy::PolicyRule::Delete => {}
            }
            if let Some(ref zones) = policy.allowed_zones {
                tracing::info!("MCP server zone restriction: {}", zones.join(", "));
            }
            tracing::info!("Starting MCP server (stdio)");

            let dns_server = DnsServer::new(client, policy);
            let transport = (tokio::io::stdin(), tokio::io::stdout());
            match dns_server.serve(transport).await {
                Ok(service) => match service.waiting().await {
                    Ok(_) => 0,
                    Err(e) => {
                        eprintln!("error: MCP transport error: {e}");
                        1
                    }
                },
                Err(e) => {
                    eprintln!("error: failed to start MCP server: {e}");
                    1
                }
            }
        }
        other => match cli::runner::run(&client, other).await {
            Ok(_) => 0,
            Err(e) => render_error(e),
        },
    }
}

#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
fn render_error(e: Error) -> i32 {
    let code = e.exit_code();
    eprintln!("{:?}", Report::from(e));
    code
}

#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
async fn run_zone_transfer(
    app_config: Option<&config::AppConfig>,
    zone: &str,
    from_id: &str,
    to_id: &str,
    overwrite: bool,
    overwrite_zone: bool,
) -> i32 {
    let Some(cfg) = app_config else {
        return render_error(Error::parse(
            "zone transfer requires a config file with --from and --to server entries",
        ));
    };

    let from_server = match cfg.selected_server(Some(from_id)) {
        Ok(s) => s,
        Err(e) => return render_error(e),
    };
    let to_server = match cfg.selected_server(Some(to_id)) {
        Ok(s) => s,
        Err(e) => return render_error(e),
    };

    eprintln!(
        "Exporting '{zone}' from '{from_id}' ({:?})…",
        from_server.vendor
    );
    let zone_file = match server_export_zone(from_server, zone).await {
        Ok(text) => text,
        Err(e) => return render_error(e),
    };

    eprintln!(
        "Importing {} bytes into '{to_id}' ({:?})…",
        zone_file.len(),
        to_server.vendor
    );
    let file_name = format!("{zone}.txt");
    match server_import_zone(
        to_server,
        zone,
        file_name,
        zone_file.into_bytes(),
        overwrite,
        overwrite_zone,
    )
    .await
    {
        Ok(result) => {
            if !result.is_null() {
                match serde_json::to_string_pretty(&result) {
                    Ok(pretty) => println!("{pretty}"),
                    Err(e) => return render_error(Error::parse(format!("serialise error: {e}"))),
                }
            }
            0
        }
        Err(e) => render_error(e),
    }
}

#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
async fn server_export_zone(server: &config::DnsServerConfig, zone: &str) -> Result<String, Error> {
    VendorClient::export_zone_for_server(server, zone).await
}

#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
async fn server_import_zone(
    server: &config::DnsServerConfig,
    zone: &str,
    file_name: String,
    file_bytes: Vec<u8>,
    overwrite: bool,
    overwrite_zone: bool,
) -> Result<serde_json::Value, Error> {
    VendorClient::import_zone_for_server(
        server,
        zone,
        file_name,
        file_bytes,
        overwrite,
        overwrite_zone,
    )
    .await
}

#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
fn cli_policy(cli: &Cli, config: Option<&config::AppConfig>) -> Result<Policy, Error> {
    let mcp = config
        .and_then(|c| {
            c.selected_server(cli.servers.first().map(|s| s.as_str()))
                .ok()
        })
        .map(|s| &s.mcp);

    // Take the most restrictive of CLI flag and server config; default to full access.
    let config_access = mcp
        .map(|p| p.access)
        .unwrap_or(policy::PolicyRule::Delete);
    let access = match cli.access {
        Some(a) => a.min(config_access),
        None => config_access,
    };
    let allowed_zones = allowed_zones(cli, mcp)?;
    Ok(Policy::new(access, allowed_zones))
}

#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
fn allowed_zones(
    cli: &Cli,
    mcp: Option<&config::McpPermissions>,
) -> Result<Option<Vec<String>>, Error> {
    let configured = mcp.and_then(|permissions| {
        (!permissions.allowed_zones.is_empty()).then_some(&permissions.allowed_zones)
    });

    if cli.allow_zone.is_empty() {
        return Ok(configured.cloned());
    }

    let Some(configured) = configured else {
        return Ok(Some(cli.allow_zone.clone()));
    };

    let configured_policy = Policy::new(policy::PolicyRule::Delete, Some(configured.clone()));
    for zone in &cli.allow_zone {
        configured_policy.check_zone(zone).map_err(|_| {
            Error::policy_violation(
                format!(
                    "--allow-zone '{zone}' is outside this server's configured MCP allowed zones"
                ),
                "Remove the override or choose a zone already permitted by this server's config.",
            )
        })?;
    }

    Ok(Some(cli.allow_zone.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn cli(allow_zone: Vec<String>) -> Cli {
        Cli {
            config: None,
            servers: vec![],
            all: false,
            base_url: None,
            token: Some("token".to_string()),
            access: None,
            allow_zone,
            command: Command::Mcp,
        }
    }

    fn temp_config_path(name: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();

        env!("CARGO_MANIFEST_DIR")
            .parse::<std::path::PathBuf>()
            .unwrap()
            .join("target")
            .join("dnsync-main-tests")
            .join(format!("{name}-{}-{nonce}", std::process::id()))
            .join("config.toml")
    }

    fn config_cli(path: std::path::PathBuf, force: bool) -> Cli {
        Cli {
            config: Some(path),
            servers: vec![],
            all: false,
            base_url: None,
            token: None,
            access: None,
            allow_zone: Vec::new(),
            command: Command::Config(ConfigCmd::Init { force }),
        }
    }

    #[test]
    fn cli_allow_zone_can_narrow_configured_zones() {
        let policy = cli_policy(&cli(vec!["sub.example.com".to_string()]), None).unwrap();

        assert!(policy.check_zone("sub.example.com").is_ok());
        assert!(policy.check_zone("other.example.com").is_err());
    }

    #[test]
    fn cli_allow_zone_cannot_broaden_configured_zones() {
        let config: config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "home"
                vendor = "technitium"
                token = "tok"

                [servers.mcp]
                allowed_zones = ["example.com"]
            "#,
        )
        .unwrap();

        let err = cli_policy(&cli(vec!["other.net".to_string()]), Some(&config)).unwrap_err();

        assert!(err.to_string().contains("outside this server's configured"));
    }

    #[tokio::test]
    async fn config_init_exits_before_token_resolution() {
        let path = temp_config_path("config-init");
        let status = run(config_cli(path.clone(), false)).await;

        assert_eq!(status, 0);
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
