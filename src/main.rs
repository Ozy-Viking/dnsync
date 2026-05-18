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
    core::{dns::service::DnsService, error, secret::ApiToken},
    mcp::server,
};

#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
use std::process;

#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
use clap::Parser;
#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
use miette::Report;
#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
use rmcp::ServiceExt;
#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
use tracing_subscriber::{EnvFilter, fmt};

#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
use cli::{Cli, Command, ConfigCmd};
#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
use error::Error;
#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
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
fn generate_completions(shell: clap_complete::Shell) {
    use clap::CommandFactory;
    use clap_complete::generate;
    use std::io::{self, Write};

    let mut cmd = Cli::command();
    let bin_name = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| cmd.get_name().to_string());
    let fn_name = bin_name.replace('-', "_");

    let mut out = io::stdout();
    generate(shell, &mut cmd, &bin_name, &mut out);

    let dynamic = match shell {
        clap_complete::Shell::Fish => format!(
            "\n# Dynamic --server completion from config\n\
             complete -e -c {bin_name} -l server\n\
             complete -c {bin_name} -l server -r -a '({bin_name} _servers 2>/dev/null)'\n"
        ),
        clap_complete::Shell::Bash => format!(
            "\n# Dynamic --server completion from config\n\
             __{fn_name}_complete() {{\n\
             \tlocal cur prev\n\
             \tcur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n\
             \tprev=\"${{COMP_WORDS[COMP_CWORD-1]}}\"\n\
             \tif [[ \"$prev\" == \"--server\" ]]; then\n\
             \t\tmapfile -t COMPREPLY < <(compgen -W \"$({bin_name} _servers 2>/dev/null)\" -- \"$cur\")\n\
             \t\treturn\n\
             \tfi\n\
             \t_{fn_name} \"$@\"\n\
             }}\n\
             complete -F __{fn_name}_complete {bin_name}\n"
        ),
        clap_complete::Shell::Zsh => format!(
            "\n# Dynamic --server completion from config\n\
             _{fn_name}_server_ids() {{\n\
             \tlocal -a ids=(\"${{(@f)$({bin_name} _servers 2>/dev/null)}}\")\n\
             \t_describe 'server ID' ids\n\
             }}\n"
        ),
        _ => String::new(),
    };

    if !dynamic.is_empty() {
        out.write_all(dynamic.as_bytes()).ok();
    }
}

#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
async fn run(cli: Cli) -> i32 {
    if let Command::Completions { shell } = cli.command {
        generate_completions(shell);
        return 0;
    }

    if let Command::ServerIds = cli.command {
        let config = config::AppConfig::load(cli.config).ok().flatten();
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
                readonly,
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
                            readonly,
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
        servers,
        use_local_ip,
        json,
    }) = &cli.command
    {
        if cli.all || !cli.servers.is_empty() {
            return run_record_list_across_servers(
                &cli,
                app_config.as_ref(),
                domain,
                zone.as_deref(),
                *all_subdomains,
                servers,
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

    let policy = match cli_policy(&cli, app_config.as_ref()) {
        Ok(p) => p,
        Err(e) => return render_error(e),
    };

    let server_config = app_config
        .as_ref()
        .and_then(|c| c.selected_server(cli.servers.first().map(|s| s.as_str())).ok());

    let vendor = server_config
        .map(|s| s.vendor)
        .unwrap_or(config::VendorKind::Technitium);

    match vendor {
        #[cfg(feature = "technitium")]
        config::VendorKind::Technitium => {
            use dnslib::vendors::technitium::client::TechnitiumClient;

            let (base_url, token) = match resolve_technitium_credentials(&cli, app_config.as_ref())
            {
                Ok(v) => v,
                Err(e) => return render_error(e),
            };

            let client = match TechnitiumClient::new(base_url.clone(), token) {
                Ok(c) => c,
                Err(e) => return render_error(e),
            };

            run_with_client(cli, client, policy).await
        }

        #[cfg(feature = "pangolin")]
        config::VendorKind::Pangolin => {
            use dnslib::vendors::pangolin::client::PangolinClient;

            let (base_url, token, org_id) =
                match resolve_pangolin_credentials(&cli, app_config.as_ref()) {
                    Ok(v) => v,
                    Err(e) => return render_error(e),
                };

            let client = match PangolinClient::new(base_url.clone(), token, org_id) {
                Ok(c) => c,
                Err(e) => return render_error(e),
            };

            run_with_client(cli, client, policy).await
        }

        #[cfg(feature = "cloudflare")]
        config::VendorKind::Cloudflare => {
            use dnslib::vendors::cloudflare::client::CloudflareClient;

            let (base_url, token) = match resolve_cloudflare_credentials(&cli, app_config.as_ref())
            {
                Ok(v) => v,
                Err(e) => return render_error(e),
            };

            let client = match CloudflareClient::new(base_url, token) {
                Ok(c) => c,
                Err(e) => return render_error(e),
            };

            run_with_client(cli, client, policy).await
        }

        #[allow(unreachable_patterns)]
        _ => {
            eprintln!("error: vendor not supported in this build");
            1
        }
    }
}

#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
async fn run_record_list_across_servers(
    cli: &Cli,
    app_config: Option<&config::AppConfig>,
    domain: &str,
    zone: Option<&str>,
    all_subdomains: bool,
    servers: &[String],
    use_local_ip: bool,
    json: bool,
) -> i32 {
    use dnslib::cli::runner::{filter_records_by_domain, infer_zone, resolve_fqdn, search_bare_label_in_zones};
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

    let selected: Vec<&config::DnsServerConfig> = if cli.all {
        cfg.servers.iter().collect()
    } else {
        let mut picked = Vec::with_capacity(cli.servers.len());
        for server_id in &cli.servers {
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
    let options = ListRecordsOptions { use_local_ip, all_subdomains };

    for (idx, server) in selected.iter().enumerate() {
        if idx > 0 {
            println!();
        }
        println!("=== Server: {} ({:?}) ===", server.id, server.vendor);
        let result = match server.vendor {
            #[cfg(feature = "technitium")]
            config::VendorKind::Technitium => {
                use dnslib::vendors::technitium::client::TechnitiumClient;
                let base_url = server.resolved_base_url(None);
                let token = match server.resolved_token(None) {
                    Ok(t) => t,
                    Err(e) => return render_error(e),
                };
                let client = match TechnitiumClient::new(base_url, token) {
                    Ok(c) => c,
                    Err(e) => return render_error(e),
                };
                if is_bare_label {
                    search_bare_label_in_zones(&client, &effective_fqdn, all_subdomains, options).await
                } else {
                    client.list_records(&query_domain, query_zone.as_deref(), options).await
                }
            }
            #[cfg(feature = "pangolin")]
            config::VendorKind::Pangolin => {
                use dnslib::vendors::pangolin::client::PangolinClient;
                let base_url = server
                    .base_url
                    .clone()
                    .unwrap_or_else(|| config::PANGOLIN_DEFAULT_BASE_URL.to_string());
                let token = match server.resolved_token(None) {
                    Ok(t) => t,
                    Err(e) => return render_error(e),
                };
                let Some(org_id) = server.org_id.clone() else {
                    return render_error(Error::parse(format!(
                        "Pangolin server '{}' is missing org_id",
                        server.id
                    )));
                };
                let client = match PangolinClient::new(base_url, token, org_id) {
                    Ok(c) => c,
                    Err(e) => return render_error(e),
                };
                if is_bare_label {
                    search_bare_label_in_zones(&client, &effective_fqdn, all_subdomains, options).await
                } else {
                    client.list_records(&query_domain, query_zone.as_deref(), options).await
                }
            }
            #[cfg(feature = "cloudflare")]
            config::VendorKind::Cloudflare => {
                use dnslib::vendors::cloudflare::client::CloudflareClient;
                let base_url = server
                    .base_url
                    .clone()
                    .unwrap_or_else(|| config::CLOUDFLARE_DEFAULT_BASE_URL.to_string());
                let token = match server.resolved_token(None) {
                    Ok(t) => t,
                    Err(e) => return render_error(e),
                };
                let client = match CloudflareClient::new(base_url, token) {
                    Ok(c) => c,
                    Err(e) => return render_error(e),
                };
                if is_bare_label {
                    search_bare_label_in_zones(&client, &effective_fqdn, all_subdomains, options).await
                } else {
                    client.list_records(&query_domain, query_zone.as_deref(), options).await
                }
            }
            #[allow(unreachable_patterns)]
            _ => Err(Error::parse(format!(
                "server '{}' has unsupported vendor in this build",
                server.id
            ))),
        };

        match result {
            Ok(mut response) => {
                // search_bare_label_in_zones already filters internally; only
                // apply the outer filter for non-bare-label --all-subdomains queries.
                if all_subdomains && !is_bare_label {
                    filter_records_by_domain(&mut response, &effective_fqdn, true);
                }
                if json {
                    match serde_json::to_string_pretty(&response) {
                        Ok(pretty) => println!("{pretty}"),
                        Err(e) => {
                            return render_error(Error::parse(format!(
                                "could not serialise record list response: {e}"
                            )));
                        }
                    }
                } else {
                    cli::records::print_records_table(&response);
                }
            }
            Err(e) => return render_error(e),
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
            if policy.readonly {
                tracing::info!("MCP server starting in read-only mode");
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

#[cfg(feature = "technitium")]
fn resolve_technitium_credentials(
    cli: &Cli,
    config: Option<&config::AppConfig>,
) -> Result<(String, ApiToken), Error> {
    let Some(config) = config else {
        let base_url = cli
            .base_url
            .clone()
            .unwrap_or_else(|| config::TECHNITIUM_DEFAULT_BASE_URL.to_string());
        let token = cli
            .token
            .clone()
            .ok_or_else(|| {
                Error::parse("API token is required from --token, TECHNITIUM_API_TOKEN, or config")
            })
            .map(ApiToken::new)?;
        return Ok((base_url, token));
    };

    let server = config.selected_server(cli.servers.first().map(|s| s.as_str()))?;
    let base_url = server.resolved_base_url(cli.base_url.as_deref());
    let token = server.resolved_token(cli.token.as_deref())?;
    Ok((base_url, token))
}

#[cfg(feature = "pangolin")]
fn resolve_pangolin_credentials(
    cli: &Cli,
    config: Option<&config::AppConfig>,
) -> Result<(String, ApiToken, String), Error> {
    use std::env;

    let (base_url, token, org_id_opt) = if let Some(config) = config {
        let server = config.selected_server(cli.servers.first().map(|s| s.as_str()))?;
        let base_url = cli
            .base_url
            .clone()
            .or_else(|| env::var("DNSYNC_PANGOLIN_BASE_URL").ok())
            .or_else(|| server.base_url.clone())
            .unwrap_or_else(|| config::PANGOLIN_DEFAULT_BASE_URL.to_string());

        let token = cli
            .token
            .clone()
            .or_else(|| env::var("DNSYNC_PANGOLIN_API_TOKEN").ok())
            .or_else(|| server.token_env.as_ref().and_then(|k| env::var(k).ok()))
            .or_else(|| server.token.clone())
            .ok_or_else(|| {
                Error::parse(
                    "Pangolin API token is required from --token, DNSYNC_PANGOLIN_API_TOKEN, token_env, or config token",
                )
            })
            .map(ApiToken::new)?;

        let org_id = env::var("DNSYNC_PANGOLIN_ORG_ID")
            .ok()
            .or_else(|| server.org_id.clone());

        (base_url, token, org_id)
    } else {
        let base_url = cli
            .base_url
            .clone()
            .or_else(|| env::var("DNSYNC_PANGOLIN_BASE_URL").ok())
            .unwrap_or_else(|| config::PANGOLIN_DEFAULT_BASE_URL.to_string());
        let token = cli
            .token
            .clone()
            .or_else(|| env::var("DNSYNC_PANGOLIN_API_TOKEN").ok())
            .ok_or_else(|| {
                Error::parse(
                    "Pangolin API token is required from --token or DNSYNC_PANGOLIN_API_TOKEN",
                )
            })
            .map(ApiToken::new)?;
        let org_id = env::var("DNSYNC_PANGOLIN_ORG_ID").ok();
        (base_url, token, org_id)
    };

    let org_id = org_id_opt.ok_or_else(|| {
        Error::parse("Pangolin org ID is required from DNSYNC_PANGOLIN_ORG_ID or config org_id")
    })?;

    Ok((base_url, token, org_id))
}

#[cfg(feature = "cloudflare")]
fn resolve_cloudflare_credentials(
    cli: &Cli,
    config: Option<&config::AppConfig>,
) -> Result<(String, ApiToken), Error> {
    use std::env;

    let Some(config) = config else {
        let base_url = cli
            .base_url
            .clone()
            .or_else(|| env::var("DNSYNC_CLOUDFLARE_BASE_URL").ok())
            .unwrap_or_else(|| config::CLOUDFLARE_DEFAULT_BASE_URL.to_string());
        let token = cli
            .token
            .clone()
            .or_else(|| env::var("DNSYNC_CLOUDFLARE_API_TOKEN").ok())
            .ok_or_else(|| {
                Error::parse(
                    "Cloudflare API token is required from --token or DNSYNC_CLOUDFLARE_API_TOKEN",
                )
            })
            .map(ApiToken::new)?;
        return Ok((base_url, token));
    };

    let server = config.selected_server(cli.servers.first().map(|s| s.as_str()))?;
    let base_url = cli
        .base_url
        .clone()
        .or_else(|| env::var("DNSYNC_CLOUDFLARE_BASE_URL").ok())
        .or_else(|| server.base_url.clone())
        .unwrap_or_else(|| config::CLOUDFLARE_DEFAULT_BASE_URL.to_string());

    let token = cli
        .token
        .clone()
        .or_else(|| env::var("DNSYNC_CLOUDFLARE_API_TOKEN").ok())
        .or_else(|| server.token_env.as_ref().and_then(|k| env::var(k).ok()))
        .or_else(|| server.token.clone())
        .ok_or_else(|| {
            Error::parse(
                "Cloudflare API token is required from --token, DNSYNC_CLOUDFLARE_API_TOKEN, token_env, or config token",
            )
        })
        .map(ApiToken::new)?;

    Ok((base_url, token))
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

    eprintln!("Exporting '{zone}' from '{from_id}' ({:?})…", from_server.vendor);
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
async fn server_export_zone(
    server: &config::DnsServerConfig,
    zone: &str,
) -> Result<String, Error> {
    use dnslib::core::dns::service::ZoneExport;
    match server.vendor {
        #[cfg(feature = "technitium")]
        config::VendorKind::Technitium => {
            use dnslib::vendors::technitium::client::TechnitiumClient;
            let token = server.resolved_token(None)?;
            let client = TechnitiumClient::new(server.resolved_base_url(None), token)?;
            client.export_zone_file(zone).await
        }
        #[cfg(feature = "cloudflare")]
        config::VendorKind::Cloudflare => {
            use dnslib::vendors::cloudflare::client::CloudflareClient;
            let token = server.resolved_token(None)?;
            let client = CloudflareClient::new(server.resolved_base_url(None), token)?;
            client.export_zone_file(zone).await
        }
        #[cfg(feature = "pangolin")]
        config::VendorKind::Pangolin => Err(Error::unsupported("Pangolin", "zone export")),
        #[allow(unreachable_patterns)]
        _ => Err(Error::parse(format!(
            "server '{}' has unsupported vendor in this build",
            server.id
        ))),
    }
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
    use dnslib::core::dns::service::ZoneImport;
    match server.vendor {
        #[cfg(feature = "technitium")]
        config::VendorKind::Technitium => {
            use dnslib::vendors::technitium::client::TechnitiumClient;
            let token = server.resolved_token(None)?;
            let client = TechnitiumClient::new(server.resolved_base_url(None), token)?;
            client
                .import_zone_file(zone, file_name, file_bytes, overwrite, overwrite_zone, false)
                .await
        }
        #[cfg(feature = "cloudflare")]
        config::VendorKind::Cloudflare => {
            use dnslib::vendors::cloudflare::client::CloudflareClient;
            let token = server.resolved_token(None)?;
            let client = CloudflareClient::new(server.resolved_base_url(None), token)?;
            client
                .import_zone_file(zone, file_name, file_bytes, overwrite, overwrite_zone, false)
                .await
        }
        #[cfg(feature = "pangolin")]
        config::VendorKind::Pangolin => Err(Error::unsupported("Pangolin", "zone import")),
        #[allow(unreachable_patterns)]
        _ => Err(Error::parse(format!(
            "server '{}' has unsupported vendor in this build",
            server.id
        ))),
    }
}

#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
fn cli_policy(cli: &Cli, config: Option<&config::AppConfig>) -> Result<Policy, Error> {
    let mcp = config
        .and_then(|c| c.selected_server(cli.servers.first().map(|s| s.as_str())).ok())
        .map(|s| &s.mcp);

    let readonly = cli.readonly || mcp.is_some_and(|p| p.readonly);
    let allowed_zones = allowed_zones(cli, mcp)?;
    Ok(Policy::new(readonly, allowed_zones))
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

    let configured_policy = Policy::new(false, Some(configured.clone()));
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
            readonly: false,
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
            readonly: false,
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

    #[cfg(feature = "pangolin")]
    #[test]
    fn pangolin_credentials_default_base_url_from_config() {
        let app_config: config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "cloud"
                vendor = "pangolin"
                token = "pangolin-token"
                org_id = "org_123"
            "#,
        )
        .unwrap();

        let cli = Cli {
            config: None,
            servers: vec!["cloud".to_string()],
            all: false,
            base_url: None,
            token: None,
            readonly: false,
            allow_zone: Vec::new(),
            command: Command::Mcp,
        };

        let (base_url, token, org_id) =
            resolve_pangolin_credentials(&cli, Some(&app_config)).unwrap();

        assert_eq!(base_url, config::PANGOLIN_DEFAULT_BASE_URL);
        assert_eq!(token.expose_for_auth(), "pangolin-token");
        assert_eq!(org_id, "org_123");
    }

    #[cfg(feature = "cloudflare")]
    #[test]
    fn cloudflare_credentials_default_base_url_no_config() {
        let cli = Cli {
            config: None,
            servers: vec![],
            all: false,
            base_url: None,
            token: Some("cf-token".to_string()),
            readonly: false,
            allow_zone: Vec::new(),
            command: Command::Mcp,
        };

        let (base_url, token) = resolve_cloudflare_credentials(&cli, None).unwrap();

        assert_eq!(base_url, config::CLOUDFLARE_DEFAULT_BASE_URL);
        assert_eq!(token.expose_for_auth(), "cf-token");
    }

    #[cfg(feature = "cloudflare")]
    #[test]
    fn cloudflare_credentials_from_config() {
        let app_config: config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "cf"
                vendor = "cloudflare"
                token = "config-token"
            "#,
        )
        .unwrap();

        let cli = Cli {
            config: None,
            servers: vec!["cf".to_string()],
            all: false,
            base_url: None,
            token: None,
            readonly: false,
            allow_zone: Vec::new(),
            command: Command::Mcp,
        };

        let (base_url, token) = resolve_cloudflare_credentials(&cli, Some(&app_config)).unwrap();

        assert_eq!(base_url, config::CLOUDFLARE_DEFAULT_BASE_URL);
        assert_eq!(token.expose_for_auth(), "config-token");
    }

    #[cfg(feature = "cloudflare")]
    #[test]
    fn cloudflare_credentials_cli_token_wins_over_config() {
        let app_config: config::AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "cf"
                vendor = "cloudflare"
                token = "config-token"
            "#,
        )
        .unwrap();

        let cli = Cli {
            config: None,
            servers: vec!["cf".to_string()],
            all: false,
            base_url: None,
            token: Some("cli-token".to_string()),
            readonly: false,
            allow_zone: Vec::new(),
            command: Command::Mcp,
        };

        let (_, token) = resolve_cloudflare_credentials(&cli, Some(&app_config)).unwrap();

        assert_eq!(token.expose_for_auth(), "cli-token");
    }

    #[cfg(feature = "cloudflare")]
    #[test]
    fn cloudflare_credentials_error_when_no_token() {
        let cli = Cli {
            config: None,
            servers: vec![],
            all: false,
            base_url: None,
            token: None,
            readonly: false,
            allow_zone: Vec::new(),
            command: Command::Mcp,
        };

        let err = resolve_cloudflare_credentials(&cli, None).unwrap_err();
        assert!(err.to_string().contains("Cloudflare API token"));
    }
}
