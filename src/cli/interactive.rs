use inquire::validator::Validation;
use inquire::{InquireError, MultiSelect, Select, Text};

use crate::control_plane::config::{
    CLOUDFLARE_DEFAULT_BASE_URL, DnsServerConfig, McpPermissions, PANGOLIN_DEFAULT_BASE_URL,
    PIHOLE_DEFAULT_BASE_URL, ServerLocation, TECHNITIUM_DEFAULT_BASE_URL, UNIFI_DEFAULT_BASE_URL,
    ValidationEndpointConfig, VendorKind,
};
use crate::control_plane::policy::PolicyRule;
use crate::core::error::{Error, Result};

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
                        Ok(Validation::Invalid(
                            "site is required for UniFi".into(),
                        ))
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
        validation_endpoints.push(endpoint.parse::<ValidationEndpointConfig>().map_err(Error::parse)?);
    }

    Ok(DnsServerConfig {
        id,
        vendor,
        location,
        base_url,
        base_url_env: None,
        token,
        token_env,
        org_id,
        cluster: None,
        dns: None,
        dot: None,
        doh: None,
        mcp: McpPermissions {
            access,
            allowed_zones,
        },
        validation_endpoints,
    })
}

fn optional_text(label: &str, help: &str, default: Option<&str>) -> Result<Option<String>> {
    let mut builder = Text::new(label).with_help_message(help);
    if let Some(d) = default {
        builder = builder.with_default(d);
    }
    let val = builder.prompt().map_err(wizard_err)?;
    Ok(if val.is_empty() { None } else { Some(val) })
}

fn wizard_err(e: inquire::InquireError) -> Error {
    match e {
        InquireError::OperationCanceled | InquireError::OperationInterrupted => Error::cancelled(),
        other => Error::io(
            format!("interactive prompt failed: {other}"),
            std::io::Error::other(other.to_string()),
        ),
    }
}

// ─── Display wrappers so Select can render enum variants ─────────────────────

struct VendorChoice {
    kind: VendorKind,
    label: &'static str,
}

impl std::fmt::Display for VendorChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label)
    }
}

struct LocationChoice {
    value: Option<ServerLocation>,
    label: &'static str,
}

impl std::fmt::Display for LocationChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label)
    }
}

struct AccessChoice {
    rule: PolicyRule,
    label: &'static str,
}

impl std::fmt::Display for AccessChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label)
    }
}
