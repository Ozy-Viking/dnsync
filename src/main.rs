use technitium_dns_mcp::{cli, client, error, policy, server};

use std::process;

use clap::Parser;
use miette::Report;
use rmcp::ServiceExt;
use tracing_subscriber::{EnvFilter, fmt};

use cli::{Cli, Command};
use client::TechnitiumClient;
use error::Error;
use policy::Policy;
use server::DnsServer;

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

async fn run(cli: Cli) -> i32 {
    let http_client = match TechnitiumClient::new(cli.base_url.clone(), cli.token.clone()) {
        Ok(c) => c,
        Err(e) => return render_error(e),
    };

    let policy = Policy::new(
        cli.readonly,
        if cli.allow_zone.is_empty() {
            None
        } else {
            Some(cli.allow_zone.clone())
        },
    );

    match cli.command {
        Command::Mcp => {
            if policy.readonly {
                tracing::info!("MCP server starting in read-only mode");
            }
            if let Some(ref zones) = policy.allowed_zones {
                tracing::info!("MCP server zone restriction: {}", zones.join(", "));
            }
            tracing::info!("Starting MCP server (stdio) → {}", cli.base_url);

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

fn render_error(e: Error) -> i32 {
    let code = e.exit_code();
    eprintln!("{:?}", Report::from(e));
    code
}
