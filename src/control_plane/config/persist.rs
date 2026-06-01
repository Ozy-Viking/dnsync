//! Config persistence: init/add/update and endpoint updates.

use super::*;

pub fn init_config(path: Option<PathBuf>, force: bool) -> Result<PathBuf> {
    let Some(path) = path.or_else(default_config_path) else {
        return Err(Error::config(
            "could not determine a default config path; pass --config <path>",
        ));
    };

    write_default_config(&path, force)?;
    Ok(path)
}

/// Append a new server entry to the config file. Creates the file if it does
/// not exist yet. Existing file content — including comments and formatting —
/// is preserved; only the new `[[servers]]` block is appended.
pub fn add_server(path: Option<PathBuf>, server: DnsServerConfig) -> Result<PathBuf> {
    let Some(path) = path.or_else(default_config_path) else {
        return Err(Error::config(
            "could not determine a default config path; pass --config <path>",
        ));
    };

    // Validate via the serde types: check for duplicate IDs etc.
    let mut config = if path.exists() {
        load_from_path(&path)?
    } else {
        AppConfig::default()
    };
    config.servers.push(server.clone());
    config.validate()?;

    // Read the raw file so toml_edit can preserve comments and formatting.
    let raw = if path.exists() {
        std::fs::read_to_string(&path)
            .map_err(|e| Error::io(format!("reading config file '{}'", path.display()), e))?
    } else {
        String::new()
    };

    let mut doc: toml_edit::DocumentMut = raw.parse().map_err(|e| {
        Error::config(format!(
            "could not parse config file '{}': {e}",
            path.display()
        ))
    })?;

    append_server_entry(&mut doc, &server);

    ensure_config_dir(&path)?;
    write_private_file(&path, &doc.to_string())?;
    Ok(path)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateDefaultsReport {
    pub path: PathBuf,
    pub updated_servers: usize,
    pub added_values: usize,
}

/// Add currently-known default values to existing server entries without
/// overwriting any field or sub-table already present in the config file.
pub fn update_defaults(path: Option<PathBuf>) -> Result<UpdateDefaultsReport> {
    let Some(path) = path.or_else(default_config_path) else {
        return Err(Error::config(
            "could not determine a default config path; pass --config <path>",
        ));
    };

    let config = load_from_path(&path)?;
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| Error::io(format!("reading config file '{}'", path.display()), e))?;
    let mut doc: toml_edit::DocumentMut = raw.parse().map_err(|e| {
        Error::config(format!(
            "could not parse config file '{}': {e}",
            path.display()
        ))
    })?;

    let servers = doc
        .get_mut("servers")
        .and_then(|v| v.as_array_of_tables_mut())
        .ok_or_else(|| Error::config("config file has no [[servers]] entries"))?;

    let mut updated_servers = 0usize;
    let mut added_values = 0usize;

    for server_tbl in servers.iter_mut() {
        let Some(id) = server_tbl
            .get("id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
        else {
            continue;
        };
        let Some(server) = config
            .servers
            .iter()
            .find(|server| server.id.eq_ignore_ascii_case(&id))
        else {
            continue;
        };

        let before = added_values;
        added_values += add_missing_server_defaults(server_tbl, server);
        if added_values > before {
            updated_servers += 1;
        }
    }

    if added_values > 0 {
        let updated: AppConfig = toml::from_str(&doc.to_string())
            .map_err(|e| Error::config(format!("updated config would be invalid: {e}")))?;
        updated.validate()?;
        write_private_file(&path, &doc.to_string())?;
    }

    Ok(UpdateDefaultsReport {
        path,
        updated_servers,
        added_values,
    })
}

/// Specifies which transport endpoint on a server to create, replace, or remove.
///
/// `None` removes the transport block entirely. `Some(config)` creates or replaces it.
pub enum EndpointUpdate {
    Dns(Option<DnsTransportConfig>),
    Dot(Option<DotTransportConfig>),
    Doh(Option<DohTransportConfig>),
    Doq(Option<DoqTransportConfig>),
}

pub(crate) fn add_missing_server_defaults(
    server_tbl: &mut toml_edit::Table,
    server: &DnsServerConfig,
) -> usize {
    use toml_edit::{Array, Item, value};

    let mut added = 0usize;

    if !server_tbl.contains_key("vendor") {
        server_tbl["vendor"] = value(vendor_name(server.vendor));
        added += 1;
    }

    if !server_tbl.contains_key("base_url") && !server_tbl.contains_key("base_url_env") {
        server_tbl["base_url"] = value(default_base_url(server.vendor));
        added += 1;
    }

    if !server_tbl.contains_key("mcp_access") && !server_tbl.contains_key("mcp") {
        let mut access = Array::new();
        for rule in &server.mcp.access {
            access.push(policy_rule_name(*rule));
        }
        server_tbl["mcp_access"] = value(access);
        added += 1;
    } else if let Some(mcp) = server_tbl
        .get_mut("mcp")
        .and_then(|item| item.as_table_mut())
        && !mcp.contains_key("access")
    {
        let mut access = Array::new();
        for rule in &server.mcp.access {
            access.push(policy_rule_name(*rule));
        }
        mcp["access"] = value(access);
        added += 1;
    }

    if let Some(mcp) = server_tbl
        .get_mut("mcp")
        .and_then(|item| item.as_table_mut())
        && !mcp.contains_key("show_settings_secrets")
    {
        mcp["show_settings_secrets"] = value(server.mcp.show_settings_secrets);
        added += 1;
    }

    if !server_tbl.contains_key("dns")
        && let Some(ref dns) = server.dns
    {
        server_tbl["dns"] = Item::Table(dns_transport_table(dns));
        added += 1;
    }
    if !server_tbl.contains_key("dot")
        && let Some(ref dot) = server.dot
    {
        server_tbl["dot"] = Item::Table(dot_transport_table(dot));
        added += 1;
    }
    if !server_tbl.contains_key("doh")
        && let Some(ref doh) = server.doh
    {
        server_tbl["doh"] = Item::Table(doh_transport_table(doh));
        added += 1;
    }
    if !server_tbl.contains_key("doq")
        && let Some(ref doq) = server.doq
    {
        server_tbl["doq"] = Item::Table(doq_transport_table(doq));
        added += 1;
    }

    added
}

/// Update a single transport endpoint on an existing server entry in the config file.
///
/// The server is matched by ID (case-insensitive). Existing file content — including
/// comments and formatting — is preserved; only the targeted transport sub-table is
/// added, replaced, or removed.
pub fn update_server_endpoint(
    path: Option<PathBuf>,
    server_id: &str,
    update: EndpointUpdate,
) -> Result<PathBuf> {
    let Some(path) = path.or_else(default_config_path) else {
        return Err(Error::config(
            "could not determine a default config path; pass --config <path>",
        ));
    };

    // Validate via the serde types first so we catch bad values early.
    let mut config = load_from_path(&path)?;
    let pos = config
        .servers
        .iter()
        .position(|s| s.id.eq_ignore_ascii_case(server_id))
        .ok_or_else(|| {
            Error::config(format!(
                "config does not define a DNS server named '{server_id}'"
            ))
        })?;
    match &update {
        EndpointUpdate::Dns(cfg) => config.servers[pos].dns = cfg.clone(),
        EndpointUpdate::Dot(cfg) => config.servers[pos].dot = cfg.clone(),
        EndpointUpdate::Doh(cfg) => config.servers[pos].doh = cfg.clone(),
        EndpointUpdate::Doq(cfg) => config.servers[pos].doq = cfg.clone(),
    }
    config.validate()?;

    // Read the raw file so toml_edit can preserve comments and formatting.
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| Error::io(format!("reading config file '{}'", path.display()), e))?;
    let mut doc: toml_edit::DocumentMut = raw.parse().map_err(|e| {
        Error::config(format!(
            "could not parse config file '{}': {e}",
            path.display()
        ))
    })?;

    let servers = doc
        .get_mut("servers")
        .and_then(|v| v.as_array_of_tables_mut())
        .ok_or_else(|| Error::config("config file has no [[servers]] entries"))?;

    let server_tbl = servers
        .iter_mut()
        .find(|tbl| {
            tbl.get("id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| id.eq_ignore_ascii_case(server_id))
        })
        .ok_or_else(|| {
            Error::config(format!(
                "config does not define a DNS server named '{server_id}'"
            ))
        })?;

    use toml_edit::{Item, Table, value};

    match update {
        EndpointUpdate::Dns(None) => {
            server_tbl.remove("dns");
        }
        EndpointUpdate::Dns(Some(cfg)) => {
            let mut tbl = Table::new();
            tbl["enabled"] = value(cfg.enabled);
            if let Some(ref addr) = cfg.addr {
                tbl["addr"] = value(addr.as_str());
            }
            if let Some(ms) = cfg.timeout_ms {
                tbl["timeout_ms"] = value(ms as i64);
            }
            server_tbl["dns"] = Item::Table(tbl);
        }
        EndpointUpdate::Dot(None) => {
            server_tbl.remove("dot");
        }
        EndpointUpdate::Dot(Some(cfg)) => {
            let mut tbl = Table::new();
            tbl["enabled"] = value(cfg.enabled);
            if let Some(ref addr) = cfg.addr {
                tbl["addr"] = value(addr.as_str());
            }
            if let Some(ref sn) = cfg.server_name {
                tbl["server_name"] = value(sn.as_str());
            }
            if let Some(ms) = cfg.timeout_ms {
                tbl["timeout_ms"] = value(ms as i64);
            }
            server_tbl["dot"] = Item::Table(tbl);
        }
        EndpointUpdate::Doh(None) => {
            server_tbl.remove("doh");
        }
        EndpointUpdate::Doh(Some(cfg)) => {
            let mut tbl = Table::new();
            tbl["enabled"] = value(cfg.enabled);
            if let Some(ref url) = cfg.url {
                tbl["url"] = value(url.as_str());
            }
            if let Some(ref addr) = cfg.addr {
                tbl["addr"] = value(addr.as_str());
            }
            if let Some(ref sn) = cfg.server_name {
                tbl["server_name"] = value(sn.as_str());
            }
            if let Some(ms) = cfg.timeout_ms {
                tbl["timeout_ms"] = value(ms as i64);
            }
            server_tbl["doh"] = Item::Table(tbl);
        }
        EndpointUpdate::Doq(None) => {
            server_tbl.remove("doq");
        }
        EndpointUpdate::Doq(Some(cfg)) => {
            let mut tbl = Table::new();
            tbl["enabled"] = value(cfg.enabled);
            if let Some(ref addr) = cfg.addr {
                tbl["addr"] = value(addr.as_str());
            }
            if let Some(ref sn) = cfg.server_name {
                tbl["server_name"] = value(sn.as_str());
            }
            if let Some(ms) = cfg.timeout_ms {
                tbl["timeout_ms"] = value(ms as i64);
            }
            server_tbl["doq"] = Item::Table(tbl);
        }
    }

    write_private_file(&path, &doc.to_string())?;
    Ok(path)
}
