#[cfg(not(any(
    feature = "technitium",
    feature = "pangolin",
    feature = "cloudflare",
    feature = "unifi",
    feature = "pihole"
)))]
compile_error!(
    "No DNS vendor feature is enabled. Enable at least one vendor feature, such as `technitium`, `pangolin`, `cloudflare`, `unifi`, or `pihole`."
);

#[cfg(not(any(
    feature = "technitium",
    feature = "pangolin",
    feature = "cloudflare",
    feature = "unifi",
    feature = "pihole"
)))]
fn main() {}

#[cfg(any(
    feature = "technitium",
    feature = "pangolin",
    feature = "cloudflare",
    feature = "unifi",
    feature = "pihole"
))]
use dnslib::{
    cli::{self, JobCmd, RecordCmd, ZoneCmd},
    control_plane::config::AppConfig,
    control_plane::{app, config, policy, sync, transfer},
    core::{dns::service::DnsService, error},
    daemon::commands as daemon_commands,
    daemon::runtime as daemon_runtime,
    mcp::server,
    vendors::runtime::{ClientOverrides, VendorClient},
};

use clap::Parser;
use dnslib::setup::init_tracing;
use rmcp::ServiceExt;
use tracing::{info, instrument, trace};

use cli::{Cli, Command, ConfigCmd, ServerEndpointCmd};
use dnslib::daemon::executor::JobOutcome;
use error::{Error, Result};
use policy::Policy;
#[cfg(any(
    feature = "technitium",
    feature = "pangolin",
    feature = "cloudflare",
    feature = "unifi",
    feature = "pihole"
))]
use server::DnsServer;

#[cfg(any(
    feature = "technitium",
    feature = "pangolin",
    feature = "cloudflare",
    feature = "unifi",
    feature = "pihole"
))]
#[tokio::main]
async fn main() -> miette::Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli)?;
    run(cli).await?;
    Ok(())
}

async fn run(cli: Cli) -> Result<()> {
    match run_inner(cli).await {
        Ok(()) => Ok(()),
        Err(Error::UserCancelled) => {
            eprintln!("bye felicia");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

#[instrument(
    level = "trace",
    skip_all,
    fields(
        command = ?cli.command.name(),
        verbose = cli.verbose,
        quiet = cli.quiet,
    )
)]
async fn run_inner(cli: Cli) -> Result<()> {
    trace!("starting run");
    if let Command::Completions { shell } = cli.command {
        cli::completions::generate_completions(shell);
        return Ok(());
    }

    if let Command::ServerIds = cli.command {
        let config = config::AppConfig::load_if_exists(cli.config).ok().flatten();
        if let Some(cfg) = config {
            for server in &cfg.servers {
                println!("{}", server.id);
            }
        }
        return Ok(());
    }

    if let Command::Query(query_args) = cli.command {
        // Query runs before AppConfig::load so an absent config file is not
        // an error (the system-resolver path works without one). We still
        // honour an explicit `--config` by going through `load_if_exists`.
        let config = config::AppConfig::load_if_exists(cli.config)?;
        let exit = cli::query::run_query(config, query_args).await?;
        std::process::exit(exit);
    }

    if let Command::Config(config_cmd) = cli.command {
        return match config_cmd {
            ConfigCmd::Init { force } => {
                let path = config::init_config(cli.config, force)?;
                println!("Wrote config file: {}", path.display());
                Ok(())
            }

            ConfigCmd::Print => {
                let toml = match config::AppConfig::load_if_exists(cli.config.clone())? {
                    Some(cfg) => cfg.redact().render_toml()?,
                    None => config::AppConfig::render_starter_toml()?,
                };
                print!("{toml}");
                Ok(())
            }

            ConfigCmd::Update => {
                let report = config::update_defaults(cli.config)?;
                info!(
                    "Updated config file: {} ({} default value(s) added across {} server(s))",
                    report.path.display(),
                    report.added_values,
                    report.updated_servers
                );
                Ok(())
            }

            ConfigCmd::Add {
                id,
                vendor,
                location,
                base_url,
                base_url_env,
                token_env,
                token,
                org_id,
                access,
                allow_zone,
                validation_endpoints,
            } => {
                let server = if id.is_none() {
                    let existing_ids: Vec<String> =
                        config::AppConfig::load_if_exists(cli.config.clone())
                            .ok()
                            .flatten()
                            .map(|c| c.servers.into_iter().map(|s| s.id).collect())
                            .unwrap_or_default();
                    cli::interactive::run_add_wizard(&existing_ids)?
                } else {
                    config::DnsServerConfig {
                        id: id.unwrap_or_default(),
                        vendor,
                        location,
                        base_url,
                        base_url_env,
                        token,
                        token_env,
                        org_id,
                        cluster: None,
                        dns: None,
                        dot: None,
                        doh: None,
                        doq: None,
                        mcp: config::McpPermissions {
                            access,
                            allowed_zones: allow_zone,
                            show_settings_secrets: false,
                        },
                        validation_endpoints,
                    }
                };
                let path = config::add_server(cli.config, server)?;
                println!("Updated config file: {}", path.display());
                Ok(())
            }

            ConfigCmd::Server {
                server_id,
                endpoint,
            } => {
                match endpoint {
                    Some(endpoint) => {
                        // Non-interactive: load existing config so omitted flags keep their
                        // current values rather than silently clearing them.
                        let id = server_id.ok_or_else(|| {
                            Error::parse(
                                "server_id is required when specifying an endpoint subcommand; \
                                 run `dns config server` with no arguments for interactive setup",
                            )
                        })?;
                        let cfg = config::AppConfig::load_if_exists(cli.config.clone())?
                            .ok_or_else(|| {
                                Error::config(
                                    "no config file found; run `dns config init` or \
                                     `dns config add` first",
                                )
                            })?;
                        let server = cfg.selected_server(Some(&id))?;
                        let update = build_endpoint_update(endpoint, server);
                        let path = config::update_server_endpoint(cli.config, &id, update)?;
                        println!("Updated config file: {}", path.display());
                    }
                    None => {
                        // Interactive path: pick server (if needed) then configure an endpoint.
                        let cfg = config::AppConfig::load_if_exists(cli.config.clone())?
                            .ok_or_else(|| {
                                Error::config(
                                    "no config file found; run `dns config init` or \
                                     `dns config add` first",
                                )
                            })?;

                        if cfg.servers.is_empty() {
                            return Err(Error::config(
                                "config file defines no servers; add one with `dns config add`",
                            ));
                        }

                        let resolved_id = if let Some(ref id) = server_id {
                            id.clone()
                        } else if cfg.servers.len() == 1 {
                            cfg.servers[0].id.clone()
                        } else {
                            cli::interactive::run_server_picker(&cfg.servers)?
                        };

                        let server = cfg.selected_server(Some(&resolved_id))?;
                        let update = cli::interactive::run_server_wizard(server)?;
                        let path =
                            config::update_server_endpoint(cli.config, &resolved_id, update)?;
                        println!("Updated config file: {}", path.display());
                    }
                }
                Ok(())
            }
        };
    }

    // ── Daemon commands — need app config but NOT a single-server client ─────
    if let Command::Daemon = cli.command {
        let cfg = config::AppConfig::load(cli.config.clone())?
            .unwrap_or_default();
        let cancel = tokio_util::sync::CancellationToken::new();
        daemon_runtime::run(cfg, cancel)
            .await
            .map_err(|e| error::Error::config(e))?;
        return Ok(());
    }

    if let Command::Job(ref job_cmd) = cli.command {
        let cfg = config::AppConfig::load(cli.config.clone())?
            .unwrap_or_default();
        match job_cmd {
            JobCmd::List => {
                let summaries = daemon_commands::list_jobs(&cfg)
                    .await
                    .map_err(|e| error::Error::config(e))?;
                if summaries.is_empty() {
                    println!("No jobs configured.");
                } else {
                    println!("{:<24} {:<14} {:<8} {:<12} {:<6}  {}", "JOB ID", "KIND", "ENABLED", "STATE", "FAILS", "LAST RUN");
                    println!("{}", "-".repeat(90));
                    for s in &summaries {
                        println!(
                            "{:<24} {:<14} {:<8} {:<12} {:<6}  {}",
                            s.job_id,
                            s.kind,
                            if s.enabled { "yes" } else { "no" },
                            s.state,
                            s.consecutive_failures,
                            s.last_run_at.as_deref().unwrap_or("never"),
                        );
                    }
                }
                return Ok(());
            }
            JobCmd::Run { id } => {
                let outcome = daemon_commands::run_job(&cfg, id)
                    .await
                    .map_err(|e| error::Error::config(e))?;
                match outcome {
                    JobOutcome::Success => println!("Job '{id}' completed successfully."),
                    JobOutcome::DryRun => println!("Job '{id}' completed (dry run — no changes applied)."),
                    JobOutcome::Failure { error: msg } => {
                        eprintln!("Job '{id}' failed: {msg}");
                        std::process::exit(1);
                    }
                }
                return Ok(());
            }
        }
    }

    if let Command::Healthcheck = cli.command {
        let cfg = config::AppConfig::load_if_exists(cli.config.clone())?
            .unwrap_or_default();
        match daemon_commands::healthcheck(&cfg).await {
            Ok(true) => {
                println!("daemon is live and healthy");
                return Ok(());
            }
            Ok(false) => {
                eprintln!("daemon is not healthy");
                std::process::exit(1);
            }
            Err(msg) => {
                eprintln!("{msg}");
                std::process::exit(1);
            }
        }
    }

    let app_config = config::AppConfig::load(cli.config.clone())?;

    // MCP is handled before single-client resolution so the server can start
    // without requiring a pre-selected server when multiple are configured.
    if let Command::Mcp = cli.command {
        return run_mcp(cli, app_config).await;
    }

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
            if cli.token.is_some() || cli.base_url.is_some() {
                return Err(Error::parse(
                    "cross-server record list does not accept --token/--base-url; configure credentials per server via config file or environment variables",
                ));
            }

            let selected = app::select_record_list_servers(
                app_config.as_ref(),
                domain.as_deref(),
                zone.as_deref(),
                effective_servers,
            )?;

            cli::runner::run_record_list_across_servers(
                &selected,
                domain.as_deref(),
                zone.as_deref(),
                *all_subdomains,
                *use_local_ip,
                *json,
            )
            .await?;
            return Ok(());
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
            return Err(Error::parse(
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

    if let Command::Sync {
        profile,
        from,
        to,
        zone,
        map,
        apply,
        json,
    } = &cli.command
    {
        if cli.token.is_some() || cli.base_url.is_some() {
            return Err(Error::parse(
                "sync does not accept --token/--base-url; \
                 configure credentials per server via config file or environment variables",
            ));
        }
        if !cli.servers.is_empty() || cli.all {
            return Err(Error::parse(
                "sync does not accept --server/--all; configure server selection via profile or explicit from/to",
            ));
        }
        sync::run_sync(
            app_config.as_ref(),
            profile.as_deref(),
            from.as_deref(),
            to.as_deref(),
            zone,
            map,
            *apply,
            *json,
        )
        .await?;
        return Ok(());
    }

    if cli.servers.len() > 1 {
        return Err(Error::parse(
            "multiple --server flags are only valid with `record list`; \
             use a single --server for all other commands",
        ));
    }

    let policy = Policy::from_cli_and_config(&cli, app_config.as_ref())?;

    let client = VendorClient::from_cli_options(
        app_config.as_ref(),
        ClientOverrides {
            selected_server: cli.servers.first().map(|s| s.as_str()),
            base_url: cli.base_url.as_deref(),
            token: cli.token.as_deref(),
        },
    )?;

    run_with_client(cli, client, policy).await
}

/// Build an `EndpointUpdate` by merging CLI flags onto the server's existing endpoint.
///
/// `Option` fields keep their current value when the corresponding flag is omitted.
/// `--disable` sets `enabled = false`; omitting it preserves the existing enabled state
/// (defaulting to `true` when no endpoint block exists yet).
fn build_endpoint_update(
    endpoint: ServerEndpointCmd,
    server: &config::DnsServerConfig,
) -> config::EndpointUpdate {
    match endpoint {
        ServerEndpointCmd::Dns {
            addr,
            timeout_ms,
            disable,
            clear,
        } => config::EndpointUpdate::Dns(if clear {
            None
        } else {
            let ex = server.dns.as_ref();
            Some(config::DnsTransportConfig {
                enabled: if disable {
                    false
                } else {
                    ex.map_or(true, |e| e.enabled)
                },
                addr: addr.or_else(|| ex.and_then(|e| e.addr.clone())),
                timeout_ms: timeout_ms.or_else(|| ex.and_then(|e| e.timeout_ms)),
            })
        }),
        ServerEndpointCmd::Dot {
            addr,
            server_name,
            timeout_ms,
            disable,
            clear,
        } => config::EndpointUpdate::Dot(if clear {
            None
        } else {
            let ex = server.dot.as_ref();
            Some(config::DotTransportConfig {
                enabled: if disable {
                    false
                } else {
                    ex.map_or(true, |e| e.enabled)
                },
                addr: addr.or_else(|| ex.and_then(|e| e.addr.clone())),
                server_name: server_name.or_else(|| ex.and_then(|e| e.server_name.clone())),
                timeout_ms: timeout_ms.or_else(|| ex.and_then(|e| e.timeout_ms)),
            })
        }),
        ServerEndpointCmd::Doh {
            url,
            addr,
            server_name,
            timeout_ms,
            disable,
            clear,
        } => config::EndpointUpdate::Doh(if clear {
            None
        } else {
            let ex = server.doh.as_ref();
            Some(config::DohTransportConfig {
                enabled: if disable {
                    false
                } else {
                    ex.map_or(true, |e| e.enabled)
                },
                url: url.or_else(|| ex.and_then(|e| e.url.clone())),
                addr: addr.or_else(|| ex.and_then(|e| e.addr.clone())),
                server_name: server_name.or_else(|| ex.and_then(|e| e.server_name.clone())),
                timeout_ms: timeout_ms.or_else(|| ex.and_then(|e| e.timeout_ms)),
            })
        }),
        ServerEndpointCmd::Doq {
            addr,
            server_name,
            timeout_ms,
            disable,
            clear,
        } => config::EndpointUpdate::Doq(if clear {
            None
        } else {
            let ex = server.doq.as_ref();
            Some(config::DoqTransportConfig {
                enabled: if disable {
                    false
                } else {
                    ex.map_or(true, |e| e.enabled)
                },
                addr: addr.or_else(|| ex.and_then(|e| e.addr.clone())),
                server_name: server_name.or_else(|| ex.and_then(|e| e.server_name.clone())),
                timeout_ms: timeout_ms.or_else(|| ex.and_then(|e| e.timeout_ms)),
            })
        }),
    }
}

#[instrument(
    level = "debug",
    skip(cli, app_config),
    fields(server_count = tracing::field::Empty)
)]
async fn run_mcp(cli: Cli, app_config: Option<AppConfig>) -> Result<()> {
    if cli.token.is_some() || cli.base_url.is_some() || !cli.servers.is_empty() {
        return Err(Error::parse(
            "`mcp` does not accept --token, --base-url, or --server; \
             configure server credentials in the config file and pass `server_id` per tool call",
        ));
    }

    let config = app_config.unwrap_or_default();
    tracing::Span::current().record("server_count", config.servers.len());
    tracing::info!("Starting MCP server (stdio)");
    let dns_server = DnsServer::new(config, cli.access, cli.allow_zone);
    let transport = (tokio::io::stdin(), tokio::io::stdout());
    let service = dns_server
        .serve(transport)
        .await
        .map_err(|e| Error::mcp(format!("failed to start MCP server: {e}")))?;
    service
        .waiting()
        .await
        .map_err(|e| Error::mcp(format!("MCP transport error: {e}")))?;
    Ok(())
}

#[instrument(level = "trace", skip_all)]
async fn run_with_client<C: DnsService + Clone + Send + Sync + 'static>(
    cli: Cli,
    client: C,
    _policy: Policy,
) -> Result<()> {
    match cli.command {
        Command::Mcp => unreachable!("handled in run()"),
        other => {
            cli::runner::run(&client, other).await?;
            Ok(())
        }
    }
}

#[instrument(
    level = "debug",
    skip(app_config),
    fields(zone, from = from_id, to = to_id, overwrite, overwrite_zone)
)]
async fn run_zone_transfer(
    app_config: Option<&config::AppConfig>,
    zone: &str,
    from_id: &str,
    to_id: &str,
    overwrite: bool,
    overwrite_zone: bool,
) -> Result<()> {
    let result =
        transfer::transfer_zone(app_config, zone, from_id, to_id, overwrite, overwrite_zone)
            .await?;
    tracing::debug!(bytes = result.bytes, "zone transfer complete");
    if !result.import_result.is_null() {
        let pretty = serde_json::to_string_pretty(&result.import_result)
            .map_err(|e| Error::parse(format!("serialise error: {e}")))?;
        println!("{pretty}");
    }
    Ok(())
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
            access: vec![],
            allow_zone,
            command: Command::Mcp,
            verbose: 0,
            quiet: 0,
            log_filter: None,
            color: colorchoice_clap::Color {
                color: clap::ColorChoice::Never,
            },
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
            access: vec![],
            allow_zone: Vec::new(),
            command: Command::Config(ConfigCmd::Init { force }),
            verbose: 0,
            quiet: 0,
            log_filter: None,
            color: colorchoice_clap::Color {
                color: clap::ColorChoice::Never,
            },
        }
    }

    #[test]
    fn cli_allow_zone_can_narrow_configured_zones() {
        let policy =
            Policy::from_cli_and_config(&cli(vec!["sub.example.com".to_string()]), None).unwrap();

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

        let err = Policy::from_cli_and_config(&cli(vec!["other.net".to_string()]), Some(&config))
            .unwrap_err();

        assert!(err.to_string().contains("outside this server's configured"));
    }

    #[tokio::test]
    async fn config_init_exits_before_token_resolution() {
        let path = temp_config_path("config-init");
        let status = run(config_cli(path.clone(), false)).await;

        assert!(status.is_ok(), "expected Ok, got: {status:?}");
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
    // #[tokio::test]
    // async fn failing_test() {
    //     assert_eq!(1, 3, "hi uh")
    // }
}
