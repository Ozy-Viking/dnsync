//! Single-client CLI command execution.
//!
//! Converts parsed CLI commands into `core::dns::<resource>` operations against a
//! resolved [`DnsService`] client and renders the result. This is the per-server
//! command path; cross-server orchestration lives in [`super::cross_server`].

use serde_json::Value;

use crate::{
    cli::{AllowedCmd, BlockedCmd, CacheCmd, Command, RecordCmd, SettingsCmd, ZoneCmd, records},
    core::{
        dns::{
            access_lists, cache, logs, logs::LogsOptions, records as dns_records,
            service::DnsService, settings, stats, zones,
        },
        error::{Error, Result},
    },
};

use super::logs_time::resolve_time;

/// Execute a CLI command using the provided DNS service client.
///
/// This dispatches the supplied `command` to the appropriate handler on `client`,
/// performing command-specific output (printing tables or JSON, writing exported
/// zone files, etc.) and printing the final result to stdout when applicable.
/// Certain subcommands (for example record list and zone export) have dedicated
/// output paths handled before the generic dispatch.
#[tracing::instrument(skip(client, command), fields(command = tracing::field::Empty))]
pub async fn run<C: DnsService>(client: &C, command: Command) -> Result<()> {
    let cmd_name = match &command {
        Command::Zone(z) => match z {
            ZoneCmd::List { .. } => "zone list",
            ZoneCmd::Create { .. } => "zone create",
            ZoneCmd::Delete { .. } => "zone delete",
            ZoneCmd::Enable { .. } => "zone enable",
            ZoneCmd::Disable { .. } => "zone disable",
            ZoneCmd::Import { .. } => "zone import",
            ZoneCmd::Export { .. } => "zone export",
            ZoneCmd::Transfer { .. } => "zone transfer",
            ZoneCmd::Options { .. } => "zone options",
            ZoneCmd::OptionsSet { .. } => "zone options-set",
        },
        Command::Record(r) => match r {
            RecordCmd::List { .. } => "record list",
            RecordCmd::Add { .. } => "record add",
            RecordCmd::Delete { .. } => "record delete",
        },
        Command::Cache(c) => match c {
            CacheCmd::List { .. } => "cache list",
            CacheCmd::Delete { .. } => "cache delete",
            CacheCmd::Flush => "cache flush",
        },
        Command::Stats { .. } => "stats",
        Command::Blocked(b) => match b {
            BlockedCmd::List => "blocked list",
            BlockedCmd::Add { .. } => "blocked add",
            BlockedCmd::Delete { .. } => "blocked delete",
        },
        Command::Allowed(a) => match a {
            AllowedCmd::List => "allowed list",
            AllowedCmd::Add { .. } => "allowed add",
            AllowedCmd::Delete { .. } => "allowed delete",
        },
        Command::Settings(s) => match s {
            SettingsCmd::Show { .. } => "settings show",
            SettingsCmd::Set { .. } => "settings set",
        },
        Command::Logs { .. } => "logs",
        Command::Mcp
        | Command::Config(_)
        | Command::Completions { .. }
        | Command::ServerIds
        | Command::Sync { .. }
        | Command::Query(_)
        | Command::Daemon
        | Command::Job(_)
        | Command::Healthcheck => {
            unreachable!()
        }
    };
    tracing::Span::current().record("command", cmd_name);
    tracing::info!(command = cmd_name, "running CLI command");
    // Record list has its own output format logic — handle it before the
    // generic JSON path.
    if let Command::Record(RecordCmd::List {
        domain,
        zone,
        all_subdomains,
        use_local_ip,
        json,
        servers: _,
    }) = command
    {
        let response = dns_records::query::list_records_for_query(
            client,
            domain.as_deref(),
            zone.as_deref(),
            all_subdomains,
            use_local_ip,
        )
        .await?;

        if json {
            let value = serde_json::to_value(&response).map_err(|e| Error::parse(e.to_string()))?;
            print_result(&value)?;
        } else {
            records::print_records_table(&response);
        }
        return Ok(());
    }

    if let Command::Zone(ZoneCmd::Export { zone, output }) = command {
        let zone_text = zones::export_zone_file(client, &zone).await?;
        if let Some(path) = output {
            std::fs::write(&path, &zone_text)
                .map_err(|e| Error::io(format!("writing zone file '{}'", path.display()), e))?;
        } else {
            print!("{zone_text}");
        }
        return Ok(());
    }

    let result = match command {
        Command::Mcp => unreachable!("handled in main"),
        Command::Config(_) => unreachable!("handled in main"),
        Command::Sync { .. } => unreachable!("handled in main"),
        Command::Query(_) => unreachable!("handled in main"),
        Command::Record(RecordCmd::List { .. }) => unreachable!("handled above"),

        Command::Zone(cmd) => match cmd {
            ZoneCmd::List { page, per_page } => zones::list_zones(client, page, per_page).await?,
            ZoneCmd::Create { zone, r#type } => zones::create_zone(client, &zone, &r#type).await?,
            ZoneCmd::Delete { zone } => zones::delete_zone(client, &zone).await?,
            ZoneCmd::Enable { zone } => zones::enable_zone(client, &zone).await?,
            ZoneCmd::Disable { zone } => zones::disable_zone(client, &zone).await?,
            ZoneCmd::Export { .. } => unreachable!("handled above"),
            ZoneCmd::Transfer { .. } => unreachable!("handled in main"),
            ZoneCmd::Import {
                zone,
                file,
                options,
            } => {
                let file_name = file
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "zone.txt".into());
                let file_bytes = std::fs::read(&file)
                    .map_err(|e| Error::io(format!("reading zone file '{}'", file.display()), e))?;
                zones::import_zone_file(
                    client,
                    &zone,
                    file_name,
                    file_bytes,
                    options.overwrite,
                    options.overwrite_zone,
                    options.overwrite_soa_serial,
                )
                .await?
            }
            ZoneCmd::Options { zone } => zones::get_zone_options(client, &zone).await?,
            ZoneCmd::OptionsSet {
                zone,
                key,
                value,
                json,
            } => {
                let options = build_json_payload(key, value, json)?;
                zones::set_zone_options(client, &zone, &options).await?
            }
        },

        Command::Record(cmd) => match cmd {
            RecordCmd::List { .. } => unreachable!("handled above"),
            RecordCmd::Add {
                zone,
                domain,
                ttl,
                record,
            } => dns_records::create_record(client, &zone, &domain, ttl, &record).await?,
            RecordCmd::Delete {
                zone,
                domain,
                record,
            } => {
                let type_params = record.to_api_params();
                dns_records::delete_record(client, &zone, &domain, &type_params).await?
            }
        },

        Command::Cache(cmd) => match cmd {
            CacheCmd::List { domain } => cache::list_cache(client, &domain).await?,
            CacheCmd::Delete { domain } => cache::delete_cache_zone(client, &domain).await?,
            CacheCmd::Flush => cache::flush_cache(client).await?,
        },

        Command::Stats { r#type } => stats::get_stats(client, &r#type).await?,

        Command::Blocked(cmd) => match cmd {
            BlockedCmd::List => access_lists::list_blocked(client).await?,
            BlockedCmd::Add { domain } => access_lists::add_blocked(client, &domain).await?,
            BlockedCmd::Delete { domain } => access_lists::delete_blocked(client, &domain).await?,
        },

        Command::Allowed(cmd) => match cmd {
            AllowedCmd::List => access_lists::list_allowed(client).await?,
            AllowedCmd::Add { domain } => access_lists::add_allowed(client, &domain).await?,
            AllowedCmd::Delete { domain } => access_lists::delete_allowed(client, &domain).await?,
        },

        Command::Settings(cmd) => match cmd {
            SettingsCmd::Show { show_secrets } => {
                if show_secrets {
                    settings::get_settings_unredacted(client).await?
                } else {
                    settings::get_settings(client).await?
                }
            }
            SettingsCmd::Set { key, value, json } => {
                let payload = build_json_payload(key, value, json)?;
                settings::set_settings(client, &payload).await?
            }
        },

        Command::Logs {
            lines,
            start,
            end,
            level,
        } => {
            let lines_vec = logs::get_logs(
                client,
                LogsOptions {
                    lines: Some(lines),
                    start: start.map(|s| resolve_time(&s)),
                    end: end.map(|s| resolve_time(&s)),
                    level,
                },
            )
            .await?;
            serde_json::to_value(lines_vec).map_err(|e| Error::parse(e.to_string()))?
        }

        Command::Completions { .. } | Command::ServerIds => {
            unreachable!("handled in main")
        }

        Command::Daemon | Command::Job(_) | Command::Healthcheck => {
            unreachable!("handled in main")
        }
    };

    print_result(&result)?;
    Ok(())
}

/// Build a `serde_json::Value` object from either a single `--key`/`--value`
/// pair or a raw `--json` string. Exactly one of the two forms must be provided
/// (enforced by clap's `requires`/`conflicts_with_all` constraints).
fn build_json_payload(
    key: Option<String>,
    value: Option<String>,
    json: Option<String>,
) -> Result<Value> {
    if let (Some(k), Some(v)) = (key, value) {
        Ok(serde_json::json!({ k: v }))
    } else if let Some(raw) = json {
        let value: Value =
            serde_json::from_str(&raw).map_err(|e| Error::parse(format!("invalid JSON: {e}")))?;
        if value.is_object() {
            Ok(value)
        } else {
            Err(Error::parse("--json must be a JSON object"))
        }
    } else {
        Err(Error::parse("provide either --key/--value or --json"))
    }
}

fn print_result(value: &Value) -> Result<()> {
    let display = value.get("response").unwrap_or(value);
    let out = serde_json::to_string_pretty(display)
        .map_err(|e| Error::parse(format!("could not serialise response: {e}")))?;
    println!("{out}");
    Ok(())
}
