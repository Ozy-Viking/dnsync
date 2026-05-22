use serde_json::Value;

use crate::{
    cli::{AllowedCmd, BlockedCmd, CacheCmd, Command, RecordCmd, ZoneCmd, records},
    control_plane::config::DnsServerConfig,
    core::{
        dns::{
            access_lists, cache, records as dns_records, service::DnsService, settings, stats,
            zones,
        },
        error::{Error, Result},
    },
    vendors::runtime::VendorClient,
};

#[allow(clippy::too_many_arguments)]
pub async fn run_record_list_across_servers(
    selected: &[&DnsServerConfig],
    domain: Option<&str>,
    zone: Option<&str>,
    all_subdomains: bool,
    use_local_ip: bool,
    json: bool,
) -> Result<()> {
    let mut json_zones = Vec::new();
    let mut printed_servers = 0usize;

    for server in selected {
        let client = VendorClient::from_server(server)?;
        let response = dns_records::query::list_records_for_query(
            &client,
            domain,
            zone,
            all_subdomains,
            use_local_ip,
        )
        .await?;

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
            records::print_records_table(&response);
            printed_servers += 1;
        }
    }

    if json {
        let pretty = serde_json::to_string_pretty(&json_zones).map_err(|error| {
            Error::parse(format!("could not serialise record list response: {error}"))
        })?;
        println!("{pretty}");
    }

    Ok(())
}

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
        Command::Settings => "settings",
        Command::Mcp
        | Command::Config(_)
        | Command::Completions { .. }
        | Command::ServerIds
        | Command::Sync { .. } => {
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
        },

        Command::Record(cmd) => match cmd {
            RecordCmd::List { .. } => unreachable!("handled above"),
            RecordCmd::Add {
                zone,
                domain,
                ttl,
                record,
            } => {
                dns_records::create_record(client, &zone, &domain, ttl, &record).await?
            }
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

        Command::Settings => settings::get_settings(client).await?,

        Command::Completions { .. } | Command::ServerIds => {
            unreachable!("handled in main")
        }
    };

    print_result(&result)?;
    Ok(())
}

fn print_result(value: &Value) -> Result<()> {
    let display = value.get("response").unwrap_or(value);
    let out = serde_json::to_string_pretty(display)
        .map_err(|e| Error::parse(format!("could not serialise response: {e}")))?;
    println!("{out}");
    Ok(())
}
