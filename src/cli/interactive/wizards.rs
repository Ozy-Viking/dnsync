//! top-level interactive wizards (add server / configure endpoints / pick server).

use super::*;

pub fn run_add_wizard(existing_ids: &[String]) -> Result<DnsServerConfig> {
    let existing: Vec<String> = existing_ids.iter().map(|s| s.to_lowercase()).collect();
    let id = Text::new("Server ID:")
        .with_help_message("Unique identifier for this server entry")
        .with_validator(move |input: &str| {
            if existing.iter().any(|id| id == &input.to_lowercase()) {
                Ok(Validation::Invalid(
                    format!("a server with id '{input}' already exists").into(),
                ))
            } else {
                Ok(Validation::Valid)
            }
        })
        .prompt()
        .map_err(wizard_err)?;

    let vendor = {
        let choices = vec![
            VendorChoice {
                kind: VendorKind::Technitium,
                label: "technitium",
            },
            VendorChoice {
                kind: VendorKind::Pangolin,
                label: "pangolin",
            },
            VendorChoice {
                kind: VendorKind::Cloudflare,
                label: "cloudflare",
            },
            VendorChoice {
                kind: VendorKind::Unifi,
                label: "unifi",
            },
            VendorChoice {
                kind: VendorKind::Pihole,
                label: "pihole",
            },
        ];
        Select::new("Vendor:", choices)
            .prompt()
            .map_err(wizard_err)?
            .kind
    };

    let default_url = match vendor {
        VendorKind::Technitium => TECHNITIUM_DEFAULT_BASE_URL,
        VendorKind::Pangolin => PANGOLIN_DEFAULT_BASE_URL,
        VendorKind::Cloudflare => CLOUDFLARE_DEFAULT_BASE_URL,
        VendorKind::Unifi => UNIFI_DEFAULT_BASE_URL,
        VendorKind::Pihole => PIHOLE_DEFAULT_BASE_URL,
    };

    let base_url = optional_text(
        "Base URL:",
        &format!("Press Enter for default ({default_url}), or type a custom URL"),
        Some(default_url),
    )?;

    let token_env = optional_text(
        "Token environment variable:",
        "Name of the env var holding the API token (recommended). Leave empty to skip.",
        None,
    )?;

    let token = if token_env.is_none() {
        optional_text(
            "API token (stored in plain text — prefer token env var above):",
            "Leave empty to skip",
            None,
        )?
    } else {
        None
    };

    let org_id = match vendor {
        VendorKind::Pangolin => {
            optional_text("Organisation ID (Pangolin):", "Leave empty to skip", None)?
        }
        VendorKind::Unifi => Some(
            Text::new("Site name (UniFi):")
                .with_help_message(
                    "Human-readable site name (e.g. \"Default\") or site UUID; stored in org_id. \
                     Run `dns settings` after saving to list valid site names.",
                )
                .with_validator(|input: &str| {
                    if input.trim().is_empty() {
                        Ok(Validation::Invalid("site is required for UniFi".into()))
                    } else {
                        Ok(Validation::Valid)
                    }
                })
                .prompt()
                .map_err(wizard_err)?,
        ),
        _ => None,
    };

    let location = {
        let choices = vec![
            LocationChoice {
                value: None,
                label: "auto-detect",
            },
            LocationChoice {
                value: Some(ServerLocation::Local),
                label: "local",
            },
            LocationChoice {
                value: Some(ServerLocation::External),
                label: "external",
            },
        ];
        Select::new("Location:", choices)
            .with_help_message(
                "auto-detect infers from the base URL (localhost/private IP → local)",
            )
            .prompt()
            .map_err(wizard_err)?
            .value
    };

    let access: Vec<PolicyRule> = {
        let choices = vec![
            AccessChoice {
                rule: PolicyRule::Read,
                label: "read   (list/export/stats/settings)",
            },
            AccessChoice {
                rule: PolicyRule::Write,
                label: "write  (create/update/import/flush)",
            },
            AccessChoice {
                rule: PolicyRule::Delete,
                label: "delete (delete zones/records/cache)",
            },
        ];
        let defaults: Vec<usize> = (0..choices.len()).collect();
        let chosen = MultiSelect::new("MCP allowed operations:", choices)
            .with_default(&defaults)
            .with_help_message("Select which operations are permitted for MCP tools on this server")
            .prompt()
            .map_err(wizard_err)?;
        chosen.into_iter().map(|c| c.rule).collect()
    };

    let mut allowed_zones: Vec<String> = Vec::new();
    loop {
        let help = if allowed_zones.is_empty() {
            "Restrict zone-targeting tools to specific zones; subdomains are also permitted. Leave empty to skip.".to_string()
        } else {
            format!(
                "Added: {} — enter another, or leave empty to finish",
                allowed_zones.join(", ")
            )
        };
        let zone = match Text::new("Allowed zone:").with_help_message(&help).prompt() {
            Ok(z) => z,
            Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => {
                return Err(Error::cancelled());
            }
            Err(e) => return Err(wizard_err(e)),
        };
        if zone.is_empty() {
            break;
        }
        allowed_zones.push(zone);
    }

    let mut validation_endpoints: Vec<ValidationEndpointConfig> = Vec::new();
    loop {
        let help = if validation_endpoints.is_empty() {
            "Optional DNS validation endpoints as name:transport:address (transport: dns, doh, dot). Leave empty to skip.".to_string()
        } else {
            format!(
                "Added: {} — enter another, or leave empty to finish",
                validation_endpoints
                    .iter()
                    .map(|endpoint| endpoint.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let endpoint = match Text::new("Validation endpoint:")
            .with_help_message(&help)
            .prompt()
        {
            Ok(endpoint) => endpoint,
            Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => {
                return Err(Error::cancelled());
            }
            Err(e) => return Err(wizard_err(e)),
        };
        if endpoint.is_empty() {
            break;
        }
        validation_endpoints.push(
            endpoint
                .parse::<ValidationEndpointConfig>()
                .map_err(Error::parse)?,
        );
    }

    let (dns, dot, doh, doq) = prompt_transport_endpoints_for_add()?;

    Ok(DnsServerConfig {
        id,
        vendor,
        location,
        base_url,
        base_url_env: None,
        token: token.map(crate::core::secret::ApiToken::new),
        token_env,
        org_id,
        cluster: None,
        dns,
        dot,
        doh,
        doq,
        mcp: McpPermissions {
            access,
            allowed_zones,
            show_settings_secrets: false,
        },
        validation_endpoints,
    })
}

/// Interactive wizard for updating a single transport endpoint on an existing server.
///
/// Shows the current status of each endpoint and prompts the user to pick one to
/// configure, update, or remove.
pub fn run_server_wizard(server: &DnsServerConfig) -> Result<EndpointUpdate> {
    let choices = vec![
        EndpointChoice {
            protocol: EndpointProtocol::Dns,
            label: format_endpoint_label(
                "dns",
                "plain DNS, port 53",
                endpoint_addr_status(server.dns.as_ref(), false),
            ),
        },
        EndpointChoice {
            protocol: EndpointProtocol::Dot,
            label: format_endpoint_label(
                "dot",
                "DNS-over-TLS, port 853",
                endpoint_addr_status(server.dot.as_ref(), false),
            ),
        },
        EndpointChoice {
            protocol: EndpointProtocol::Doh,
            label: format_endpoint_label(
                "doh",
                "DNS-over-HTTPS",
                endpoint_addr_status(server.doh.as_ref(), true),
            ),
        },
        EndpointChoice {
            protocol: EndpointProtocol::Doq,
            label: format_endpoint_label(
                "doq",
                "DNS-over-QUIC",
                endpoint_addr_status(server.doq.as_ref(), false),
            ),
        },
    ];

    let chosen = Select::new("Select endpoint to configure:", choices)
        .with_help_message("Use arrow keys to select; current status shown on the right")
        .prompt()
        .map_err(wizard_err)?;

    match chosen.protocol {
        EndpointProtocol::Dns => {
            let cfg = configure_or_remove("DNS", server.dns.as_ref(), |existing| {
                prompt_dns_config(existing)
            })?;
            Ok(EndpointUpdate::Dns(cfg))
        }
        EndpointProtocol::Dot => {
            let cfg = configure_or_remove("DoT", server.dot.as_ref(), |existing| {
                prompt_dot_config(existing)
            })?;
            Ok(EndpointUpdate::Dot(cfg))
        }
        EndpointProtocol::Doh => {
            let cfg = configure_or_remove("DoH", server.doh.as_ref(), |existing| {
                prompt_doh_config(existing)
            })?;
            Ok(EndpointUpdate::Doh(cfg))
        }
        EndpointProtocol::Doq => {
            let cfg = configure_or_remove("DoQ", server.doq.as_ref(), |existing| {
                prompt_doq_config(existing)
            })?;
            Ok(EndpointUpdate::Doq(cfg))
        }
    }
}

/// Lets the user pick a server by ID from a list. Returns the chosen server ID.
pub fn run_server_picker(servers: &[DnsServerConfig]) -> Result<String> {
    let choices: Vec<ServerChoice> = servers
        .iter()
        .map(|s| ServerChoice {
            id: s.id.clone(),
            label: format_server_summary(s),
        })
        .collect();

    let chosen = Select::new("Select server to update:", choices)
        .prompt()
        .map_err(wizard_err)?;

    Ok(chosen.id)
}
