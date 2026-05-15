#[cfg(not(feature = "technitium"))]
compile_error!(
    "No DNS vendor feature is enabled. Enable at least one vendor feature, such as `technitium`."
);

#[cfg(not(feature = "technitium"))]
fn main() {}

#[cfg(feature = "technitium")]
use dnslib::{
    cli,
    control_plane::{config, policy},
    core::error,
    mcp::server,
    vendors::technitium::client,
};

#[cfg(feature = "technitium")]
use std::process;

#[cfg(feature = "technitium")]
use clap::Parser;
#[cfg(feature = "technitium")]
use miette::Report;
#[cfg(feature = "technitium")]
use rmcp::ServiceExt;
#[cfg(feature = "technitium")]
use tracing_subscriber::{EnvFilter, fmt};

#[cfg(feature = "technitium")]
use cli::{Cli, Command, ConfigCmd};
#[cfg(feature = "technitium")]
use client::TechnitiumClient;
#[cfg(feature = "technitium")]
use error::Error;
#[cfg(feature = "technitium")]
use policy::Policy;
#[cfg(feature = "technitium")]
use server::DnsServer;

#[cfg(feature = "technitium")]
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

#[cfg(feature = "technitium")]
async fn run(cli: Cli) -> i32 {
    if let Command::Config(ConfigCmd::Init { force }) = cli.command {
        return match config::init_config(cli.config, force) {
            Ok(path) => {
                println!("Wrote config file: {}", path.display());
                0
            }
            Err(e) => render_error(e),
        };
    }

    let config = match config::AppConfig::load(cli.config.clone()) {
        Ok(config) => config,
        Err(e) => return render_error(e),
    };

    let (base_url, token, policy) = match resolve_runtime(&cli, config.as_ref()) {
        Ok(runtime) => runtime,
        Err(e) => return render_error(e),
    };

    let http_client = match TechnitiumClient::new(base_url.clone(), token) {
        Ok(c) => c,
        Err(e) => return render_error(e),
    };

    match cli.command {
        Command::Mcp => {
            if policy.readonly {
                tracing::info!("MCP server starting in read-only mode");
            }
            if let Some(ref zones) = policy.allowed_zones {
                tracing::info!("MCP server zone restriction: {}", zones.join(", "));
            }
            tracing::info!("Starting MCP server (stdio) → {}", base_url);

            let dns_server = DnsServer::new(http_client, policy);
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
        other => match cli::runner::run(&http_client, other).await {
            Ok(_) => 0,
            Err(e) => render_error(e),
        },
    }
}

#[cfg(feature = "technitium")]
fn render_error(e: Error) -> i32 {
    let code = e.exit_code();
    eprintln!("{:?}", Report::from(e));
    code
}

#[cfg(feature = "technitium")]
fn resolve_runtime(
    cli: &Cli,
    config: Option<&config::AppConfig>,
) -> Result<(String, String, Policy), Error> {
    let Some(config) = config else {
        let base_url = cli
            .base_url
            .clone()
            .unwrap_or_else(|| "http://localhost:5380".to_string());
        let token = cli.token.clone().ok_or_else(|| {
            Error::parse("API token is required from --token, TECHNITIUM_API_TOKEN, or config")
        })?;
        return Ok((base_url, token, cli_policy(cli, None)?));
    };

    let server = config.selected_server(cli.server.as_deref())?;
    match server.vendor {
        config::VendorKind::Technitium => {
            let base_url = server.resolved_base_url(cli.base_url.as_deref());
            let token = server.resolved_token(cli.token.as_deref())?;
            Ok((base_url, token, cli_policy(cli, Some(&server.mcp))?))
        }
    }
}

#[cfg(feature = "technitium")]
fn cli_policy(cli: &Cli, mcp: Option<&config::McpPermissions>) -> Result<Policy, Error> {
    let readonly = cli.readonly || mcp.is_some_and(|permissions| permissions.readonly);
    let allowed_zones = allowed_zones(cli, mcp)?;

    Ok(Policy::new(readonly, allowed_zones))
}

#[cfg(feature = "technitium")]
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

#[cfg(all(test, feature = "technitium"))]
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

    fn permissions() -> config::McpPermissions {
        config::McpPermissions {
            readonly: false,
            allowed_zones: vec!["example.com".to_string()],
        }
    }

    #[test]
    fn cli_allow_zone_can_narrow_configured_zones() {
        let policy = cli_policy(
            &cli(vec!["sub.example.com".to_string()]),
            Some(&permissions()),
        )
        .unwrap();

        assert!(policy.check_zone("sub.example.com").is_ok());
        assert!(policy.check_zone("other.example.com").is_err());
    }

    #[test]
    fn cli_allow_zone_cannot_broaden_configured_zones() {
        let err =
            cli_policy(&cli(vec!["other.net".to_string()]), Some(&permissions())).unwrap_err();

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
