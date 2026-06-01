//! CLI command dispatch.
//!
//! `main.rs` parses the CLI and initialises tracing, then hands the parsed [`Cli`]
//! to [`run`]. This module owns the orchestration that used to live in `main.rs`:
//! routing each command to config handling, daemon handling, the MCP server,
//! cross-server operations, or the single-client command path.

pub mod client_cmd;
mod config_cmd;
mod cross_server;
mod daemon_cmd;
mod logs_time;

#[cfg(test)]
mod tests;

use tracing::{instrument, trace};

use crate::{
    cli::{Cli, Command, RecordCmd, ZoneCmd},
    control_plane::{app, config, policy::Policy, sync},
    core::{
        dns::service::DnsService,
        error::{Error, Result},
    },
    vendors::runtime::{ClientOverrides, VendorClient},
};

/// Top-level entry point invoked by `main`. Maps the cooperative-cancellation
/// error into a friendly message and otherwise propagates the result.
pub async fn run(cli: Cli) -> Result<()> {
    match run_inner(cli).await {
        Ok(()) => Ok(()),
        Err(Error::UserCancelled) => {
            eprintln!("bye felicia");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Dispatch a parsed CLI command to the appropriate handler.
///
/// Commands that do not need a single resolved server (completions, server IDs,
/// query, config, daemon/job/healthcheck, MCP, and the cross-server record list /
/// zone transfer / sync paths) are handled directly. Everything else resolves a
/// vendor client and delegates to [`client_cmd::run`].
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
        crate::cli::completions::generate_completions(shell);
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
        let exit = crate::cli::query::run_query(config, query_args).await?;
        std::process::exit(exit);
    }

    if let Command::Config(config_cmd) = cli.command {
        return config_cmd::handle(cli.config, config_cmd);
    }

    // ── Daemon commands — need app config but NOT a single-server client ─────
    if let Command::Daemon = cli.command {
        return daemon_cmd::handle_daemon(cli.config).await;
    }

    if let Command::Job(ref job_cmd) = cli.command {
        return daemon_cmd::handle_job(cli.config.clone(), job_cmd).await;
    }

    if let Command::Healthcheck = cli.command {
        return daemon_cmd::handle_healthcheck(cli.config.clone()).await;
    }

    let app_config = config::AppConfig::load(cli.config.clone())?;

    // MCP is handled before single-client resolution so the server can start
    // without requiring a pre-selected server when multiple are configured.
    if let Command::Mcp = cli.command {
        if cli.token.is_some() || cli.base_url.is_some() || !cli.servers.is_empty() {
            return Err(Error::parse(
                "`mcp` does not accept --token, --base-url, or --server; \
                 configure server credentials in the config file and pass `server_id` per tool call",
            ));
        }
        let config = app_config.unwrap_or_default();
        return crate::mcp::server::serve_stdio(config, cli.access, cli.allow_zone).await;
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

            cross_server::run_record_list_across_servers(
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
        return cross_server::run_zone_transfer(
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
            sync::SyncDiffOptions::default(),
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
            token: cli.token.as_ref(),
        },
    )?;

    run_with_client(cli, client, policy).await
}

#[instrument(level = "trace", skip_all)]
async fn run_with_client<C: DnsService + Clone + Send + Sync + 'static>(
    cli: Cli,
    client: C,
    _policy: Policy,
) -> Result<()> {
    match cli.command {
        Command::Mcp => unreachable!("handled in run_inner"),
        other => client_cmd::run(&client, other).await,
    }
}
