use serde_json::Value;

use crate::{
    cli::{AllowedCmd, BlockedCmd, CacheCmd, Command, RecordCmd, ZoneCmd},
    client::TechnitiumClient,
    dns,
    error::{Error, Result},
};

pub async fn run(client: &TechnitiumClient, command: Command) -> Result<()> {
    let result = match command {
        Command::Mcp => unreachable!("handled in main"),

        Command::Zone(cmd) => match cmd {
            ZoneCmd::List { page, per_page } => dns::list_zones(client, page, per_page).await?,
            ZoneCmd::Create { zone, r#type } => dns::create_zone(client, &zone, &r#type).await?,
            ZoneCmd::Delete { zone } => dns::delete_zone(client, &zone).await?,
            ZoneCmd::Enable { zone } => dns::enable_zone(client, &zone).await?,
            ZoneCmd::Disable { zone } => dns::disable_zone(client, &zone).await?,
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
                dns::import_zone_file(
                    client,
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
            RecordCmd::List { domain, zone } => {
                serde_json::to_value(dns::list_records(client, &domain, zone.as_deref()).await?)
                    .map_err(|e| Error::parse(e.to_string()))?
            }
            RecordCmd::Add {
                zone,
                domain,
                ttl,
                record,
            } => dns::add_record(client, &zone, &domain, ttl, &record.into()).await?,
            RecordCmd::Delete {
                zone,
                domain,
                record,
            } => dns::delete_record(client, &zone, &domain, &record.to_api_params()).await?,
        },

        Command::Cache(cmd) => match cmd {
            CacheCmd::List { domain } => dns::list_cache(client, &domain).await?,
            CacheCmd::Delete { domain } => dns::delete_cache_zone(client, &domain).await?,
            CacheCmd::Flush => dns::flush_cache(client).await?,
        },

        Command::Stats { r#type } => dns::get_stats(client, &r#type).await?,

        Command::Blocked(cmd) => match cmd {
            BlockedCmd::List => dns::list_blocked(client).await?,
            BlockedCmd::Add { domain } => dns::add_blocked(client, &domain).await?,
            BlockedCmd::Delete { domain } => dns::delete_blocked(client, &domain).await?,
        },

        Command::Allowed(cmd) => match cmd {
            AllowedCmd::List => dns::list_allowed(client).await?,
            AllowedCmd::Add { domain } => dns::add_allowed(client, &domain).await?,
            AllowedCmd::Delete { domain } => dns::delete_allowed(client, &domain).await?,
        },

        Command::Settings => dns::get_settings(client).await?,
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
