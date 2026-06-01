//! Cross-server CLI orchestration: record listing across multiple servers and
//! zone transfer between two configured servers.

use crate::{
    cli::records,
    control_plane::{config::DnsServerConfig, transfer},
    core::{
        dns::records::query as record_query,
        error::{Error, Result},
    },
    vendors::runtime::VendorClient,
};

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(level = "debug", skip_all, fields(server_count = selected.len(), json))]
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
        tracing::trace!(server_id = %server.id, "fetching records from server");
        let client = VendorClient::from_server(server)?;
        let response = record_query::list_records_for_query(
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

#[tracing::instrument(
    level = "debug",
    skip(app_config),
    fields(zone, from = from_id, to = to_id, overwrite, overwrite_zone)
)]
pub async fn run_zone_transfer(
    app_config: Option<&crate::control_plane::config::AppConfig>,
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
