use inquire::validator::Validation;
use inquire::{Confirm, InquireError, MultiSelect, Select, Text};

use crate::control_plane::config::{
    CLOUDFLARE_DEFAULT_BASE_URL, DnsServerConfig, DnsTransportConfig, DohTransportConfig,
    DotTransportConfig, DoqTransportConfig, EndpointUpdate, McpPermissions,
    PANGOLIN_DEFAULT_BASE_URL, ServerLocation, TECHNITIUM_DEFAULT_BASE_URL,
    UNIFI_DEFAULT_BASE_URL, ValidationEndpointConfig, VendorKind,
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

    let (dns, dot, doh, doq) = prompt_transport_endpoints_for_add()?;

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
        dns,
        dot,
        doh,
        doq,
        mcp: McpPermissions {
            access,
            allowed_zones,
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
            label: format_endpoint_label("dns", "plain DNS, port 53", endpoint_addr_status(server.dns.as_ref(), false)),
        },
        EndpointChoice {
            protocol: EndpointProtocol::Dot,
            label: format_endpoint_label("dot", "DNS-over-TLS, port 853", endpoint_addr_status(server.dot.as_ref(), false)),
        },
        EndpointChoice {
            protocol: EndpointProtocol::Doh,
            label: format_endpoint_label("doh", "DNS-over-HTTPS", endpoint_addr_status(server.doh.as_ref(), true)),
        },
        EndpointChoice {
            protocol: EndpointProtocol::Doq,
            label: format_endpoint_label("doq", "DNS-over-QUIC", endpoint_addr_status(server.doq.as_ref(), false)),
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

// ─── Transport endpoint prompts ───────────────────────────────────────────────

fn prompt_transport_endpoints_for_add() -> Result<(
    Option<DnsTransportConfig>,
    Option<DotTransportConfig>,
    Option<DohTransportConfig>,
    Option<DoqTransportConfig>,
)> {
    let configure = Confirm::new("Configure DNS transport endpoints (dns/dot/doh/doq)?")
        .with_default(false)
        .with_help_message(
            "Set up direct DNS query endpoints for validation and resolution. \
             You can always add these later with `dns config server <id> <protocol>`.",
        )
        .prompt()
        .map_err(wizard_err)?;

    if !configure {
        return Ok((None, None, None, None));
    }

    let choices = vec![
        ProtocolChoice { id: 0, label: "dns  (plain DNS, port 53)" },
        ProtocolChoice { id: 1, label: "dot  (DNS-over-TLS, port 853)" },
        ProtocolChoice { id: 2, label: "doh  (DNS-over-HTTPS)" },
        ProtocolChoice { id: 3, label: "doq  (DNS-over-QUIC)" },
    ];

    let selected = MultiSelect::new("Select protocols to configure:", choices)
        .with_help_message("Space to toggle, Enter to confirm")
        .prompt()
        .map_err(wizard_err)?;

    let mut dns = None;
    let mut dot = None;
    let mut doh = None;
    let mut doq = None;

    for choice in selected {
        match choice.id {
            0 => dns = Some(prompt_dns_config(None)?),
            1 => dot = Some(prompt_dot_config(None)?),
            2 => doh = Some(prompt_doh_config(None)?),
            3 => doq = Some(prompt_doq_config(None)?),
            _ => unreachable!(),
        }
    }

    Ok((dns, dot, doh, doq))
}

fn prompt_dns_config(existing: Option<&DnsTransportConfig>) -> Result<DnsTransportConfig> {
    let addr = Text::new("Address (host:port):")
        .with_help_message("e.g. 10.0.0.1:53 or dns.example.com:53")
        .with_default(
            existing
                .and_then(|e| e.addr.as_deref())
                .unwrap_or(""),
        )
        .prompt()
        .map_err(wizard_err)?;

    let timeout_ms = optional_u64(
        "Timeout (ms):",
        "Query timeout in milliseconds, e.g. 2000. Leave empty to use the default.",
        existing.and_then(|e| e.timeout_ms),
    )?;

    let enabled = Confirm::new("Enable this endpoint?")
        .with_default(existing.map_or(true, |e| e.enabled))
        .prompt()
        .map_err(wizard_err)?;

    Ok(DnsTransportConfig {
        enabled,
        addr: Some(addr).filter(|a| !a.is_empty()),
        timeout_ms,
    })
}

fn prompt_dot_config(existing: Option<&DotTransportConfig>) -> Result<DotTransportConfig> {
    let addr = Text::new("Address (host:port):")
        .with_help_message("e.g. 10.0.0.1:853 or dns.example.com:853")
        .with_default(
            existing
                .and_then(|e| e.addr.as_deref())
                .unwrap_or(""),
        )
        .prompt()
        .map_err(wizard_err)?;

    let server_name = optional_text(
        "TLS server name (SNI):",
        "Hostname for TLS certificate validation. Leave empty to use the hostname from address.",
        existing.and_then(|e| e.server_name.as_deref()),
    )?;

    let timeout_ms = optional_u64(
        "Timeout (ms):",
        "Query timeout in milliseconds, e.g. 2000. Leave empty to use the default.",
        existing.and_then(|e| e.timeout_ms),
    )?;

    let enabled = Confirm::new("Enable this endpoint?")
        .with_default(existing.map_or(true, |e| e.enabled))
        .prompt()
        .map_err(wizard_err)?;

    Ok(DotTransportConfig {
        enabled,
        addr: Some(addr).filter(|a| !a.is_empty()),
        server_name,
        timeout_ms,
    })
}

fn prompt_doh_config(existing: Option<&DohTransportConfig>) -> Result<DohTransportConfig> {
    let url = optional_text(
        "URL:",
        "Full HTTPS URL, e.g. https://dns.example.com/dns-query",
        existing.and_then(|e| e.url.as_deref()),
    )?;

    let addr = optional_text(
        "Address override (host:port):",
        "Override the TCP address resolved from the URL, e.g. 10.0.0.1:443. Leave empty to use DNS.",
        existing.and_then(|e| e.addr.as_deref()),
    )?;

    let server_name = optional_text(
        "TLS server name (SNI):",
        "Hostname for TLS certificate validation. Leave empty to use the hostname from the URL.",
        existing.and_then(|e| e.server_name.as_deref()),
    )?;

    let timeout_ms = optional_u64(
        "Timeout (ms):",
        "Query timeout in milliseconds, e.g. 2000. Leave empty to use the default.",
        existing.and_then(|e| e.timeout_ms),
    )?;

    let enabled = Confirm::new("Enable this endpoint?")
        .with_default(existing.map_or(true, |e| e.enabled))
        .prompt()
        .map_err(wizard_err)?;

    Ok(DohTransportConfig {
        enabled,
        url,
        addr,
        server_name,
        timeout_ms,
    })
}

fn prompt_doq_config(existing: Option<&DoqTransportConfig>) -> Result<DoqTransportConfig> {
    let addr = Text::new("Address (host:port):")
        .with_help_message("e.g. 10.0.0.1:853 or dns.example.com:853")
        .with_default(
            existing
                .and_then(|e| e.addr.as_deref())
                .unwrap_or(""),
        )
        .prompt()
        .map_err(wizard_err)?;

    let server_name = optional_text(
        "TLS server name (SNI):",
        "Hostname for TLS certificate validation. Leave empty to use the hostname from address.",
        existing.and_then(|e| e.server_name.as_deref()),
    )?;

    let timeout_ms = optional_u64(
        "Timeout (ms):",
        "Query timeout in milliseconds, e.g. 2000. Leave empty to use the default.",
        existing.and_then(|e| e.timeout_ms),
    )?;

    let enabled = Confirm::new("Enable this endpoint?")
        .with_default(existing.map_or(true, |e| e.enabled))
        .prompt()
        .map_err(wizard_err)?;

    Ok(DoqTransportConfig {
        enabled,
        addr: Some(addr).filter(|a| !a.is_empty()),
        server_name,
        timeout_ms,
    })
}

/// If an existing config is present, ask the user whether to update or remove it.
/// If not present, go straight to the configure prompt.
fn configure_or_remove<T, F>(protocol: &str, existing: Option<&T>, configure: F) -> Result<Option<T>>
where
    F: FnOnce(Option<&T>) -> Result<T>,
{
    if existing.is_some() {
        let choices = vec![
            ActionChoice { action: EndpointAction::Configure, label: "configure / update" },
            ActionChoice { action: EndpointAction::Remove, label: "remove endpoint" },
        ];
        let chosen = Select::new(&format!("{protocol} endpoint:"), choices)
            .prompt()
            .map_err(wizard_err)?;

        if matches!(chosen.action, EndpointAction::Remove) {
            return Ok(None);
        }
    }

    configure(existing).map(Some)
}

// ─── Formatting helpers ───────────────────────────────────────────────────────

fn format_endpoint_label(protocol: &str, description: &str, status: String) -> String {
    format!("{protocol:<4}  {description:<30}  {status}")
}

/// Returns a short status string for an addr-based endpoint (dns/dot/doq).
/// When `is_url` is true, uses url instead of addr.
fn endpoint_addr_status<T: EndpointInfo>(endpoint: Option<&T>, is_url: bool) -> String {
    match endpoint {
        None => "not configured".to_string(),
        Some(ep) => {
            let target = if is_url {
                ep.url_str().unwrap_or_else(|| ep.addr_str().unwrap_or("?"))
            } else {
                ep.addr_str().unwrap_or("?")
            };
            let state = if ep.is_enabled() { "enabled" } else { "disabled" };
            format!("{state} → {target}")
        }
    }
}

fn format_server_summary(server: &DnsServerConfig) -> String {
    let vendor = match server.vendor {
        crate::control_plane::config::VendorKind::Technitium => "technitium",
        crate::control_plane::config::VendorKind::Pangolin => "pangolin",
        crate::control_plane::config::VendorKind::Cloudflare => "cloudflare",
        crate::control_plane::config::VendorKind::Unifi => "unifi",
    };
    let url = server
        .base_url
        .as_deref()
        .unwrap_or("(default)");
    format!("{}  [{vendor}]  {url}", server.id)
}

// ─── Trait to unify transport config access for status formatting ─────────────

trait EndpointInfo {
    fn is_enabled(&self) -> bool;
    fn addr_str(&self) -> Option<&str>;
    fn url_str(&self) -> Option<&str> {
        None
    }
}

impl EndpointInfo for DnsTransportConfig {
    fn is_enabled(&self) -> bool { self.enabled }
    fn addr_str(&self) -> Option<&str> { self.addr.as_deref() }
}

impl EndpointInfo for DotTransportConfig {
    fn is_enabled(&self) -> bool { self.enabled }
    fn addr_str(&self) -> Option<&str> { self.addr.as_deref() }
}

impl EndpointInfo for DohTransportConfig {
    fn is_enabled(&self) -> bool { self.enabled }
    fn addr_str(&self) -> Option<&str> { self.addr.as_deref() }
    fn url_str(&self) -> Option<&str> { self.url.as_deref() }
}

impl EndpointInfo for DoqTransportConfig {
    fn is_enabled(&self) -> bool { self.enabled }
    fn addr_str(&self) -> Option<&str> { self.addr.as_deref() }
}

// ─── Prompt utilities ─────────────────────────────────────────────────────────

fn optional_text(label: &str, help: &str, default: Option<&str>) -> Result<Option<String>> {
    let mut builder = Text::new(label).with_help_message(help);
    if let Some(d) = default {
        builder = builder.with_default(d);
    }
    let val = builder.prompt().map_err(wizard_err)?;
    Ok(if val.is_empty() { None } else { Some(val) })
}

fn optional_u64(label: &str, help: &str, current: Option<u64>) -> Result<Option<u64>> {
    let default = current.map(|n| n.to_string());
    let mut builder = Text::new(label)
        .with_help_message(help)
        .with_validator(|input: &str| {
            if input.is_empty() {
                return Ok(Validation::Valid);
            }
            if input.parse::<u64>().is_ok() {
                Ok(Validation::Valid)
            } else {
                Ok(Validation::Invalid("must be a non-negative integer".into()))
            }
        });
    if let Some(ref d) = default {
        builder = builder.with_default(d.as_str());
    }
    let val = builder.prompt().map_err(wizard_err)?;
    if val.is_empty() {
        Ok(None)
    } else {
        val.parse::<u64>()
            .map(Some)
            .map_err(|_| Error::parse(format!("'{val}' is not a valid integer")))
    }
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

// ─── Display wrappers so Select/MultiSelect can render enum variants ──────────

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

struct ProtocolChoice {
    id: u8,
    label: &'static str,
}

impl std::fmt::Display for ProtocolChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label)
    }
}

enum EndpointProtocol {
    Dns,
    Dot,
    Doh,
    Doq,
}

struct EndpointChoice {
    protocol: EndpointProtocol,
    label: String,
}

impl std::fmt::Display for EndpointChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label)
    }
}

enum EndpointAction {
    Configure,
    Remove,
}

struct ActionChoice {
    action: EndpointAction,
    label: &'static str,
}

impl std::fmt::Display for ActionChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label)
    }
}

struct ServerChoice {
    id: String,
    label: String,
}

impl std::fmt::Display for ServerChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label)
    }
}
