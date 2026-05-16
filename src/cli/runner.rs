use serde_json::Value;

use crate::{
    cli::{AllowedCmd, BlockedCmd, CacheCmd, Command, RecordCmd, ZoneCmd, records},
    core::dns::service::{DnsService, ListRecordsOptions},
    core::error::{Error, Result},
};

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
        Command::Mcp | Command::Config(_) => unreachable!(),
    };
    tracing::Span::current().record("command", cmd_name);
    tracing::info!(command = cmd_name, "running CLI command");
    // Record list has its own output format logic — handle it before the
    // generic JSON path.
    if let Command::Record(RecordCmd::List {
        domain,
        zone,
        use_local_ip,
        json,
        servers: _,
    }) = command
    {
        let domain = domain.as_deref().ok_or_else(|| {
            Error::parse("domain is required for single-server record list (use --all/--server for cross-server mode)")
        })?;
        let response = client
            .list_records(domain, zone.as_deref(), ListRecordsOptions { use_local_ip })
            .await?;

        if json {
            let value = serde_json::to_value(&response).map_err(|e| Error::parse(e.to_string()))?;
            print_result(&value)?;
        } else {
            records::print_records_table(&response);
        }
        return Ok(());
    }

    let result = match command {
        Command::Mcp => unreachable!("handled in main"),
        Command::Config(_) => unreachable!("handled in main"),
        Command::Record(RecordCmd::List { .. }) => unreachable!("handled above"),

        Command::Zone(cmd) => match cmd {
            ZoneCmd::List { page, per_page } => client.list_zones(page, per_page).await?,
            ZoneCmd::Create { zone, r#type } => client.create_zone(&zone, &r#type).await?,
            ZoneCmd::Delete { zone } => client.delete_zone(&zone).await?,
            ZoneCmd::Enable { zone } => client.enable_zone(&zone).await?,
            ZoneCmd::Disable { zone } => client.disable_zone(&zone).await?,
            ZoneCmd::Import {
                zone,
                file,
                overwrite,
                overwrite_zone,
                overwrite_soa_serial,
            } => {
                let file_name = file
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "zone.txt".into());
                let file_bytes = std::fs::read(&file)
                    .map_err(|e| Error::io(format!("reading zone file '{}'", file.display()), e))?;
                client
                    .import_zone_file(
                        &zone,
                        file_name,
                        file_bytes,
                        overwrite,
                        overwrite_zone,
                        overwrite_soa_serial,
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
                let record_data = record.into();
                client.add_record(&zone, &domain, ttl, &record_data).await?
            }
            RecordCmd::Delete {
                zone,
                domain,
                record,
            } => {
                let type_params = record.to_api_params();
                client.delete_record(&zone, &domain, &type_params).await?
            }
        },

        Command::Cache(cmd) => match cmd {
            CacheCmd::List { domain } => client.list_cache(&domain).await?,
            CacheCmd::Delete { domain } => client.delete_cache_zone(&domain).await?,
            CacheCmd::Flush => client.flush_cache().await?,
        },

        Command::Stats { r#type } => client.get_stats(&r#type).await?,

        Command::Blocked(cmd) => match cmd {
            BlockedCmd::List => client.list_blocked().await?,
            BlockedCmd::Add { domain } => client.add_blocked(&domain).await?,
            BlockedCmd::Delete { domain } => client.delete_blocked(&domain).await?,
        },

        Command::Allowed(cmd) => match cmd {
            AllowedCmd::List => client.list_allowed().await?,
            AllowedCmd::Add { domain } => client.add_allowed(&domain).await?,
            AllowedCmd::Delete { domain } => client.delete_allowed(&domain).await?,
        },

        Command::Settings => client.get_settings().await?,
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
