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
    cli::{self, RecordCmd, ZoneCmd},
    control_plane::config::AppConfig,
    control_plane::{app, config, policy, sync},
    core::{dns::service::DnsService, error},
    mcp::server,
    vendors::runtime::{ClientOverrides, VendorClient},
};

use clap::Parser;
use rmcp::ServiceExt;
use tracing_subscriber::{EnvFilter, fmt};

use cli::{Cli, Command, ConfigCmd};
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

    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    run(cli).await?;
    Ok(())
}

async fn run(cli: Cli) -> Result<()> {
    match run_inner(cli).await {
        Ok(()) => Ok(()),
        Err(Error::UserCancelled) => {
            println!("bye felicia");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

async fn run_inner(cli: Cli) -> Result<()> {
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
                        mcp: config::McpPermissions {
                            access,
                            allowed_zones: allow_zone,
                        },
                        validation_endpoints,
                    }
                };
                let path = config::add_server(cli.config, server)?;
                println!("Updated config file: {}", path.display());
                Ok(())
            }
        };
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

async fn run_mcp(cli: Cli, app_config: Option<AppConfig>) -> Result<()> {
    if cli.token.is_some() || cli.base_url.is_some() || !cli.servers.is_empty() {
        return Err(Error::parse(
            "`mcp` does not accept --token, --base-url, or --server; \
             configure server credentials in the config file and pass `server_id` per tool call",
        ));
    }

    let config = app_config.unwrap_or_default();
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

async fn run_zone_transfer(
    app_config: Option<&config::AppConfig>,
    zone: &str,
    from_id: &str,
    to_id: &str,
    overwrite: bool,
    overwrite_zone: bool,
) -> Result<()> {
    let Some(cfg) = app_config else {
        return Err(Error::parse(
            "zone transfer requires a config file with --from and --to server entries",
        ));
    };

    let from_server = cfg.selected_server(Some(from_id))?;
    let to_server = cfg.selected_server(Some(to_id))?;

    tracing::info!(
        zone = %zone,
        from = %from_id,
        vendor = ?from_server.vendor,
        "Exporting zone"
    );
    let zone_file = server_export_zone(from_server, zone).await?;

    tracing::info!(
        bytes = zone_file.len(),
        to = %to_id,
        vendor = ?to_server.vendor,
        "Importing zone"
    );
    let file_name = format!("{zone}.txt");
    let result = server_import_zone(
        to_server,
        zone,
        file_name,
        zone_file.into_bytes(),
        overwrite,
        overwrite_zone,
    )
    .await?;
    if !result.is_null() {
        let pretty = serde_json::to_string_pretty(&result)
            .map_err(|e| Error::parse(format!("serialise error: {e}")))?;
        println!("{pretty}");
    }
    Ok(())
}

async fn server_export_zone(server: &config::DnsServerConfig, zone: &str) -> Result<String> {
    VendorClient::export_zone_for_server(server, zone).await
}

async fn server_import_zone(
    server: &config::DnsServerConfig,
    zone: &str,
    file_name: String,
    file_bytes: Vec<u8>,
    overwrite: bool,
    overwrite_zone: bool,
) -> Result<serde_json::Value> {
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
