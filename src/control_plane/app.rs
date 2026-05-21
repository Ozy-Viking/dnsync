//! Application composition helpers.
//!
//! This module owns vendor selection and shared startup wiring as the
//! control plane is separated from vendor implementations.

use crate::cli::Cli;
use crate::control_plane::config::{AppConfig, DnsServerConfig};
use crate::core::{
    dns::{
        records::query::{
            filter_records_by_domain, infer_zone, list_records_for_all_zones, resolve_fqdn,
            search_bare_label_in_zones,
        },
        service::{ListRecordsOptions, ZoneRead},
    },
    error::{Error, Result},
};
use crate::vendors::runtime::VendorClient;
use serde_json::json;

 /// List records across all configured servers, handling domain inference,
 /// bare-label search, and JSON output formatting.
 ///
 /// This function mirrors the logic previously in `src/main.rs::run_record_list_across_servers`.
 #[allow(clippy::too_many_arguments)]
pub async fn run_record_list_across_servers(
    cli: &Cli,
    app_config: Option<&AppConfig>,
    domain: Option<&str>,
    zone: Option<&str>,
    all_subdomains: bool,
    servers: &[String],
    use_local_ip: bool,
    json: bool,
) -> Result<()> {
    if cli.token.is_some() || cli.base_url.is_some() {
        return Err(Error::parse(
            "cross-server record list does not accept --token/--base-url; configure credentials per server via config file or environment variables",
        ));
    }

     let Some(cfg) = app_config else {
         return Err(Error::parse(
             "--all/--server for record list requires a config file with server entries",
         ));
     };

     let bare_label_without_zone =
         zone.is_none() && domain.is_some_and(|domain| !domain.contains('.'));
     let query_all_servers =
         cli.all || (servers.is_empty() && (domain.is_none() || bare_label_without_zone));
     let selected: Vec<&DnsServerConfig> = if query_all_servers {
         cfg.servers.iter().collect()
     } else {
         let mut picked = Vec::with_capacity(servers.len());
         for server_id in servers {
             match cfg.selected_server(Some(server_id.as_str())) {
                 Ok(s) => picked.push(s),
                 Err(e) => return Err(e),
             }
         }
         picked
     };

     if selected.is_empty() {
         return Err(Error::parse(
             "--all requested, but no servers are configured; add at least one server in the config file",
         ));
     }

     let mut json_zones = Vec::new();
     let mut printed_servers = 0usize;

     for server in &selected {
         let client = match VendorClient::from_server(server) {
             Ok(client) => client,
             Err(e) => return Err(e),
         };
         let domain_query = domain.map(|domain| {
             let effective_fqdn = resolve_fqdn(domain, zone);
             let is_bare_label = zone.is_none() && !effective_fqdn.contains('.');
             let (query_domain, query_zone) = if !is_bare_label && all_subdomains {
                 let zone_name = zone
                     .map(str::to_string)
                     .or_else(|| infer_zone(&effective_fqdn).filter(|z| z.contains('.')))
                     .unwrap_or_else(|| effective_fqdn.clone());
                 (zone_name.clone(), Some(zone_name))
             } else {
                 (effective_fqdn.clone(), zone.map(str::to_string))
             };
             (effective_fqdn, is_bare_label, query_domain, query_zone)
         });
         let options = ListRecordsOptions {
             use_local_ip,
             all_subdomains,
         };
         let result = match &domain_query {
             None => list_records_for_all_zones(&client, options).await,
             Some((effective_fqdn, true, _, _)) => {
                 search_bare_label_in_zones(&client, effective_fqdn, all_subdomains, options).await
             }
             Some((_, false, query_domain, query_zone)) => {
                 client
                     .list_records(query_domain, query_zone.as_deref(), options)
                     .await
             }
         };

         match result {
             Ok(mut response) => {
                 // search_bare_label_in_zones already filters internally; only
                 // apply the outer filter for non-bare-label --all-subdomains queries.
                 if let Some((effective_fqdn, false, _, _)) = &domain_query
                     && all_subdomains
                 {
                     filter_records_by_domain(&mut response, effective_fqdn, true);
                 }
                 if json {
                     for mut zone_records in response.zones {
                         if zone_records.zone.id.is_none() {
                             zone_records.zone.id = Some(zone_records.zone.name.clone());
                         }
                         json_zones.push(json!({
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
                     crate::cli::records::print_records_table(&response);
                     printed_servers += 1;
                 }
             }
             Err(e) => return Err(e),
         }
     }

     if json {
         let pretty = serde_json::to_string_pretty(&json_zones)
             .map_err(|error| Error::parse(format!("could not serialise record list response: {error}")))?;
         println!("{pretty}");
     }

     Ok(())
 }
