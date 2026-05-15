#[cfg(not(any(feature = "technitium", feature = "pangolin")))]
compile_error!(
    "No DNS vendor feature is enabled. Enable at least one vendor feature, such as `technitium` or `pangolin`."
);

#[cfg(not(any(feature = "technitium", feature = "pangolin")))]
fn main() {}

#[cfg(any(feature = "technitium", feature = "pangolin"))]
use dnslib::{
    cli,
    control_plane::{config, policy},
    core::{dns::service::DnsService, error, secret::ApiToken},
    mcp::server,
};

#[cfg(any(feature = "technitium", feature = "pangolin"))]
use std::process;

#[cfg(any(feature = "technitium", feature = "pangolin"))]
use clap::Parser;
#[cfg(any(feature = "technitium", feature = "pangolin"))]
use miette::Report;
#[cfg(any(feature = "technitium", feature = "pangolin"))]
use rmcp::ServiceExt;
#[cfg(any(feature = "technitium", feature = "pangolin"))]
use tracing_subscriber::{EnvFilter, fmt};

#[cfg(any(feature = "technitium", feature = "pangolin"))]
use cli::{Cli, Command, ConfigCmd};
#[cfg(any(feature = "technitium", feature = "pangolin"))]
use error::Error;
#[cfg(any(feature = "technitium", feature = "pangolin"))]
use policy::Policy;
#[cfg(any(feature = "technitium", feature = "pangolin"))]
use server::DnsServer;

#[cfg(any(feature = "technitium", feature = "pangolin"))]
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

#[cfg(any(feature = "technitium", feature = "pangolin"))]
async fn run(cli: Cli) -> i32 {
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
                base_url,
                token_env,
                token,
                org_id,
                readonly,
                allow_zone,
            } => {
                let server = config::DnsServerConfig {
                    id,
                    vendor,
                    base_url,
                    token,
                    token_env,
                    org_id,
                    mcp: config::McpPermissions {
                        readonly,
                        allowed_zones: allow_zone,
                    },
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

    let policy = match cli_policy(&cli, app_config.as_ref()) {
        Ok(p) => p,
        Err(e) => return render_error(e),
    };

    let server_config = app_config
        .as_ref()
        .and_then(|c| c.selected_server(cli.server.as_deref()).ok());

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

        #[allow(unreachable_patterns)]
        _ => {
            eprintln!("error: vendor not supported in this build");
            1
        }
    }
}

#[cfg(any(feature = "technitium", feature = "pangolin"))]
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

#[cfg(any(feature = "technitium", feature = "pangolin"))]
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

    let server = config.selected_server(cli.server.as_deref())?;
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
        let server = config.selected_server(cli.server.as_deref())?;
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
            .or_else(|| {
                server.token_env.as_ref().and_then(|k| env::var(k).ok())
            })
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

#[cfg(any(feature = "technitium", feature = "pangolin"))]
fn cli_policy(cli: &Cli, config: Option<&config::AppConfig>) -> Result<Policy, Error> {
    let mcp = config
        .and_then(|c| c.selected_server(cli.server.as_deref()).ok())
        .map(|s| &s.mcp);

    let readonly = cli.readonly || mcp.is_some_and(|p| p.readonly);
    let allowed_zones = allowed_zones(cli, mcp)?;
    Ok(Policy::new(readonly, allowed_zones))
}

#[cfg(any(feature = "technitium", feature = "pangolin"))]
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

#[cfg(all(test, any(feature = "technitium", feature = "pangolin")))]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn cli(allow_zone: Vec<String>) -> Cli {
        Cli {
            config: None,
            server: None,
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
            server: None,
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
        // Build a minimal AppConfig with one server that has allowed_zones
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
            server: Some("cloud".to_string()),
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
}
