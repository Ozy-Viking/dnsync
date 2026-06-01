//! per-transport endpoint prompts and small input helpers.

use super::*;

// ─── Transport endpoint prompts ───────────────────────────────────────────────

pub(crate) fn prompt_transport_endpoints_for_add() -> Result<(
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
        ProtocolChoice {
            id: 0,
            label: "dns  (plain DNS, port 53)",
        },
        ProtocolChoice {
            id: 1,
            label: "dot  (DNS-over-TLS, port 853)",
        },
        ProtocolChoice {
            id: 2,
            label: "doh  (DNS-over-HTTPS)",
        },
        ProtocolChoice {
            id: 3,
            label: "doq  (DNS-over-QUIC)",
        },
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

pub(crate) fn prompt_dns_config(
    existing: Option<&DnsTransportConfig>,
) -> Result<DnsTransportConfig> {
    let addr = Text::new("Address (host:port):")
        .with_help_message("e.g. 10.0.0.1:53 or dns.example.com:53")
        .with_default(existing.and_then(|e| e.addr.as_deref()).unwrap_or(""))
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

    let addr = addr.trim().to_string();
    Ok(DnsTransportConfig {
        enabled,
        addr: Some(addr).filter(|a| !a.is_empty()),
        timeout_ms,
    })
}

pub(crate) fn prompt_dot_config(
    existing: Option<&DotTransportConfig>,
) -> Result<DotTransportConfig> {
    let addr = Text::new("Address (host:port):")
        .with_help_message("e.g. 10.0.0.1:853 or dns.example.com:853")
        .with_default(existing.and_then(|e| e.addr.as_deref()).unwrap_or(""))
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

    let addr = addr.trim().to_string();
    Ok(DotTransportConfig {
        enabled,
        addr: Some(addr).filter(|a| !a.is_empty()),
        server_name,
        timeout_ms,
    })
}

pub(crate) fn prompt_doh_config(
    existing: Option<&DohTransportConfig>,
) -> Result<DohTransportConfig> {
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

pub(crate) fn prompt_doq_config(
    existing: Option<&DoqTransportConfig>,
) -> Result<DoqTransportConfig> {
    let addr = Text::new("Address (host:port):")
        .with_help_message("e.g. 10.0.0.1:853 or dns.example.com:853")
        .with_default(existing.and_then(|e| e.addr.as_deref()).unwrap_or(""))
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

    let addr = addr.trim().to_string();
    Ok(DoqTransportConfig {
        enabled,
        addr: Some(addr).filter(|a| !a.is_empty()),
        server_name,
        timeout_ms,
    })
}

/// If an existing config is present, ask the user whether to update or remove it.
/// If not present, go straight to the configure prompt.
pub(crate) fn configure_or_remove<T, F>(
    protocol: &str,
    existing: Option<&T>,
    configure: F,
) -> Result<Option<T>>
where
    F: FnOnce(Option<&T>) -> Result<T>,
{
    if existing.is_some() {
        let choices = vec![
            ActionChoice {
                action: EndpointAction::Configure,
                label: "configure / update",
            },
            ActionChoice {
                action: EndpointAction::Remove,
                label: "remove endpoint",
            },
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

// ─── Prompt utilities ─────────────────────────────────────────────────────────

pub(crate) fn optional_text(
    label: &str,
    help: &str,
    default: Option<&str>,
) -> Result<Option<String>> {
    let mut builder = Text::new(label).with_help_message(help);
    if let Some(d) = default {
        builder = builder.with_default(d);
    }
    let val = builder.prompt().map_err(wizard_err)?;
    let val = val.trim();
    Ok(if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    })
}

pub(crate) fn optional_u64(label: &str, help: &str, current: Option<u64>) -> Result<Option<u64>> {
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

pub(crate) fn wizard_err(e: inquire::InquireError) -> Error {
    match e {
        InquireError::OperationCanceled | InquireError::OperationInterrupted => Error::cancelled(),
        other => Error::io(
            format!("interactive prompt failed: {other}"),
            std::io::Error::other(other.to_string()),
        ),
    }
}
