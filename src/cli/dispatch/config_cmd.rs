//! `config` subcommand handling: init/print/update/add/server.
//!
//! Dispatches directly to `control_plane::config`, using `cli::interactive` for
//! the optional wizard paths.

use std::path::PathBuf;

use tracing::info;

use crate::{
    cli::{self, ConfigCmd, ServerEndpointCmd},
    control_plane::config,
    core::error::{Error, Result},
};

/// Handle a parsed `config` subcommand against the config file at `config_path`
/// (or the default location when `None`).
pub fn handle(config_path: Option<PathBuf>, cmd: ConfigCmd) -> Result<()> {
    match cmd {
        ConfigCmd::Init { force } => {
            let path = config::init_config(config_path, force)?;
            println!("Wrote config file: {}", path.display());
            Ok(())
        }

        ConfigCmd::Print => {
            let toml = match config::AppConfig::load_if_exists(config_path)? {
                Some(cfg) => cfg.redact().render_toml()?,
                None => config::AppConfig::render_starter_toml()?,
            };
            print!("{toml}");
            Ok(())
        }

        ConfigCmd::Update => {
            let report = config::update_defaults(config_path)?;
            info!(
                "Updated config file: {} ({} default value(s) added across {} server(s))",
                report.path.display(),
                report.added_values,
                report.updated_servers
            );
            Ok(())
        }

        ConfigCmd::Add {
            id,
            vendor,
            location,
            base_url,
            base_url_env,
            token_env,
            token,
            org_id,
            access,
            allow_zone,
            validation_endpoints,
        } => {
            let server = if id.is_none() {
                let existing_ids: Vec<String> =
                    config::AppConfig::load_if_exists(config_path.clone())
                        .ok()
                        .flatten()
                        .map(|c| c.servers.into_iter().map(|s| s.id).collect())
                        .unwrap_or_default();
                cli::interactive::run_add_wizard(&existing_ids)?
            } else {
                config::DnsServerConfig {
                    id: id.unwrap_or_default(),
                    vendor,
                    location,
                    base_url,
                    base_url_env,
                    token,
                    token_env,
                    org_id,
                    cluster: None,
                    dns: None,
                    dot: None,
                    doh: None,
                    doq: None,
                    mcp: config::McpPermissions {
                        access,
                        allowed_zones: allow_zone,
                        show_settings_secrets: false,
                    },
                    validation_endpoints,
                }
            };
            let path = config::add_server(config_path, server)?;
            println!("Updated config file: {}", path.display());
            Ok(())
        }

        ConfigCmd::Server {
            server_id,
            endpoint,
        } => {
            match endpoint {
                Some(endpoint) => {
                    // Non-interactive: load existing config so omitted flags keep their
                    // current values rather than silently clearing them.
                    let id = server_id.ok_or_else(|| {
                        Error::parse(
                            "server_id is required when specifying an endpoint subcommand; \
                             run `dns config server` with no arguments for interactive setup",
                        )
                    })?;
                    let cfg = config::AppConfig::load_if_exists(config_path.clone())?.ok_or_else(
                        || {
                            Error::config(
                                "no config file found; run `dns config init` or \
                                 `dns config add` first",
                            )
                        },
                    )?;
                    let server = cfg.selected_server(Some(&id))?;
                    let update = build_endpoint_update(endpoint, server);
                    let path = config::update_server_endpoint(config_path, &id, update)?;
                    println!("Updated config file: {}", path.display());
                }
                None => {
                    // Interactive path: pick server (if needed) then configure an endpoint.
                    let cfg = config::AppConfig::load_if_exists(config_path.clone())?.ok_or_else(
                        || {
                            Error::config(
                                "no config file found; run `dns config init` or \
                                 `dns config add` first",
                            )
                        },
                    )?;

                    if cfg.servers.is_empty() {
                        return Err(Error::config(
                            "config file defines no servers; add one with `dns config add`",
                        ));
                    }

                    let resolved_id = if let Some(ref id) = server_id {
                        id.clone()
                    } else if cfg.servers.len() == 1 {
                        cfg.servers[0].id.clone()
                    } else {
                        cli::interactive::run_server_picker(&cfg.servers)?
                    };

                    let server = cfg.selected_server(Some(&resolved_id))?;
                    let update = cli::interactive::run_server_wizard(server)?;
                    let path = config::update_server_endpoint(config_path, &resolved_id, update)?;
                    println!("Updated config file: {}", path.display());
                }
            }
            Ok(())
        }
    }
}

/// Build an `EndpointUpdate` by merging CLI flags onto the server's existing endpoint.
///
/// `Option` fields keep their current value when the corresponding flag is omitted.
/// `--disable` sets `enabled = false`; omitting it preserves the existing enabled state
/// (defaulting to `true` when no endpoint block exists yet).
fn build_endpoint_update(
    endpoint: ServerEndpointCmd,
    server: &config::DnsServerConfig,
) -> config::EndpointUpdate {
    match endpoint {
        ServerEndpointCmd::Dns {
            addr,
            timeout_ms,
            disable,
            clear,
        } => config::EndpointUpdate::Dns(if clear {
            None
        } else {
            let ex = server.dns.as_ref();
            Some(config::DnsTransportConfig {
                enabled: if disable {
                    false
                } else {
                    ex.is_none_or(|e| e.enabled)
                },
                addr: addr.or_else(|| ex.and_then(|e| e.addr.clone())),
                timeout_ms: timeout_ms.or_else(|| ex.and_then(|e| e.timeout_ms)),
            })
        }),
        ServerEndpointCmd::Dot {
            addr,
            server_name,
            timeout_ms,
            disable,
            clear,
        } => config::EndpointUpdate::Dot(if clear {
            None
        } else {
            let ex = server.dot.as_ref();
            Some(config::DotTransportConfig {
                enabled: if disable {
                    false
                } else {
                    ex.is_none_or(|e| e.enabled)
                },
                addr: addr.or_else(|| ex.and_then(|e| e.addr.clone())),
                server_name: server_name.or_else(|| ex.and_then(|e| e.server_name.clone())),
                timeout_ms: timeout_ms.or_else(|| ex.and_then(|e| e.timeout_ms)),
            })
        }),
        ServerEndpointCmd::Doh {
            url,
            addr,
            server_name,
            timeout_ms,
            disable,
            clear,
        } => config::EndpointUpdate::Doh(if clear {
            None
        } else {
            let ex = server.doh.as_ref();
            Some(config::DohTransportConfig {
                enabled: if disable {
                    false
                } else {
                    ex.is_none_or(|e| e.enabled)
                },
                url: url.or_else(|| ex.and_then(|e| e.url.clone())),
                addr: addr.or_else(|| ex.and_then(|e| e.addr.clone())),
                server_name: server_name.or_else(|| ex.and_then(|e| e.server_name.clone())),
                timeout_ms: timeout_ms.or_else(|| ex.and_then(|e| e.timeout_ms)),
            })
        }),
        ServerEndpointCmd::Doq {
            addr,
            server_name,
            timeout_ms,
            disable,
            clear,
        } => config::EndpointUpdate::Doq(if clear {
            None
        } else {
            let ex = server.doq.as_ref();
            Some(config::DoqTransportConfig {
                enabled: if disable {
                    false
                } else {
                    ex.is_none_or(|e| e.enabled)
                },
                addr: addr.or_else(|| ex.and_then(|e| e.addr.clone())),
                server_name: server_name.or_else(|| ex.and_then(|e| e.server_name.clone())),
                timeout_ms: timeout_ms.or_else(|| ex.and_then(|e| e.timeout_ms)),
            })
        }),
    }
}
