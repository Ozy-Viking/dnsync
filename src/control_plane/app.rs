use crate::control_plane::config::{AppConfig, DnsServerConfig};
use crate::core::error::{Error, Result};

/// Select the configured DNS servers that should be queried by a cross-server command.
pub fn select_record_list_servers<'a>(
    app_config: Option<&'a AppConfig>,
    domain: Option<&str>,
    zone: Option<&str>,
    servers: &[String],
) -> Result<Vec<&'a DnsServerConfig>> {
    let Some(cfg) = app_config else {
        return Err(Error::parse(
            "--all/--server for record list requires a config file with server entries",
        ));
    };

    let bare_label_without_zone =
        zone.is_none() && domain.is_some_and(|domain| !domain.contains('.'));
    let query_all_servers = servers.is_empty() && (domain.is_none() || bare_label_without_zone);
    let selected: Vec<&DnsServerConfig> = if query_all_servers {
        cfg.servers.iter().collect()
    } else {
        let mut picked = Vec::with_capacity(servers.len());
        for server_id in servers {
            picked.push(cfg.selected_server(Some(server_id.as_str()))?);
        }
        picked
    };

    if selected.is_empty() {
        return Err(Error::parse(
            "--all requested, but no servers are configured; add at least one server in the config file",
        ));
    }

    Ok(selected)
}
