//! target/argument parsing and validation.

use super::*;

/// Split the positionals into a single domain plus an optional `@addr`.
pub(crate) fn split_targets(positionals: &[String]) -> Result<(String, Option<String>)> {
    let mut domain: Option<&str> = None;
    let mut at: Option<String> = None;
    for raw in positionals {
        if let Some(rest) = raw.strip_prefix('@') {
            if at.is_some() {
                return Err(Error::parse("only one `@ADDR` positional is accepted"));
            }
            if rest.is_empty() {
                return Err(Error::parse("`@ADDR` is missing an address after `@`"));
            }
            at = Some(rest.to_string());
        } else if domain.is_none() {
            domain = Some(raw);
        } else {
            return Err(Error::parse(format!(
                "unexpected positional argument '{raw}': pass a single domain plus an optional `@ADDR`",
            )));
        }
    }
    let Some(domain) = domain else {
        return Err(Error::parse(
            "missing required positional `<DOMAIN>` (the name to resolve)",
        ));
    };
    Ok((domain.to_string(), at))
}

pub(crate) fn validate_cli_rules(args: &QueryArgs) -> Result<()> {
    let has_server = !args.server.is_empty() || args.all_servers;

    if has_server && args.at.is_some() {
        return Err(Error::parse(
            "`--server`/`--all-servers` and `--at`/`@ADDR` are mutually exclusive",
        ));
    }

    if !args.server.is_empty() && args.all_servers {
        return Err(Error::parse(
            "`--all-servers` already queries every server; drop the explicit `--server`",
        ));
    }

    let any_transport = args.dns || args.dot || args.doh || args.doq;
    let has_target = has_server || args.at.is_some();

    if args.all_transports && any_transport {
        return Err(Error::parse(
            "`--all-transports` is mutually exclusive with `--dns` / `--dot` / `--doh` / `--doq`",
        ));
    }

    if args.all_transports && !has_server {
        return Err(Error::parse(
            "`--all-transports` requires a server target (`--server <ID>` or `--all-servers`) — there's no way to enumerate transports for an ad-hoc target or the system resolver",
        ));
    }

    if !has_target && (any_transport || args.all_transports) {
        return Err(Error::parse(
            "transport flags (--dns/--dot/--doh/--doq/--all-transports) require a resolver target — pass --server <ID> or --at <ADDR>",
        ));
    }

    if args.at.is_some() && (args.dns as u8 + args.dot as u8 + args.doh as u8 + args.doq as u8) > 1
    {
        return Err(Error::parse(
            "with `--at`/`@ADDR`, at most one of --dns/--dot/--doh/--doq is accepted",
        ));
    }

    if has_server && (args.port.is_some() || args.tls_server_name.is_some() || args.tcp) {
        return Err(Error::parse(
            "`--port` / `--tls-server-name` / `--tcp` only apply to ad-hoc resolvers (`--at` / `@ADDR`); for `--server`, the transport block owns those values",
        ));
    }

    Ok(())
}

pub(crate) fn parse_record_types(input: &[String], all_types: bool) -> Result<Vec<String>> {
    if all_types || input.is_empty() {
        return Ok(DEFAULT_RECORD_TYPES
            .iter()
            .map(|rr_type| (*rr_type).to_string())
            .collect());
    }
    let mut out = Vec::with_capacity(input.len());
    for raw in input {
        let upper = raw.trim().to_ascii_uppercase();
        if upper.is_empty() {
            return Err(Error::parse("--type cannot be empty"));
        }
        upper
            .parse::<RecordType>()
            .map_err(|_| Error::parse(format!("unknown record type '{raw}'")))?;
        if !out.contains(&upper) {
            out.push(upper);
        }
    }
    Ok(out)
}

#[derive(Debug, Default)]
pub(crate) struct ParsedAdHoc {
    pub(crate) transport: Option<ValidationTransport>,
    pub(crate) host: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) url: Option<String>,
}

pub(crate) fn parse_ad_hoc(raw: &str) -> Result<ParsedAdHoc> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::parse("--at value is empty"));
    }

    if let Some((scheme, rest)) = trimmed.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        let (transport, is_url_transport) = match scheme.as_str() {
            "udp" | "tcp" | "dns" => (Some(ValidationTransport::Dns), false),
            "tls" | "dot" => (Some(ValidationTransport::Dot), false),
            "https" | "doh" => (Some(ValidationTransport::Doh), true),
            "quic" | "doq" => (Some(ValidationTransport::Doq), false),
            other => {
                return Err(Error::parse(format!(
                    "unknown ad-hoc scheme '{other}'; expected one of udp/tcp/dns/tls/dot/https/doh/quic/doq",
                )));
            }
        };
        if is_url_transport {
            let url = if scheme == "doh" {
                format!("https://{rest}")
            } else {
                trimmed.to_string()
            };
            return Ok(ParsedAdHoc {
                transport,
                host: None,
                port: None,
                url: Some(url),
            });
        }
        let (host, port) = split_addr(rest)?;
        return Ok(ParsedAdHoc {
            transport,
            host: Some(host),
            port,
            url: None,
        });
    }

    let (host, port) = split_addr(trimmed)?;
    Ok(ParsedAdHoc {
        transport: None,
        host: Some(host),
        port,
        url: None,
    })
}

pub(crate) fn split_addr(raw: &str) -> Result<(String, Option<u16>)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(Error::parse("ad-hoc target is empty"));
    }
    if let Some(stripped) = raw.strip_prefix('[') {
        let (host, rest) = stripped
            .split_once(']')
            .ok_or_else(|| Error::parse("unmatched `[` in IPv6 literal"))?;
        let port = rest
            .strip_prefix(':')
            .map(|p| {
                p.parse::<u16>()
                    .map_err(|_| Error::parse(format!("invalid port '{p}'")))
            })
            .transpose()?;
        return Ok((host.to_string(), port));
    }
    if let Some((host, port_s)) = raw.rsplit_once(':')
        && !host.is_empty()
        && !host.contains(':')
    {
        let port = port_s
            .parse::<u16>()
            .map_err(|_| Error::parse(format!("invalid port '{port_s}'")))?;
        return Ok((host.to_string(), Some(port)));
    }
    Ok((raw.to_string(), None))
}

pub(crate) fn describe_target(
    target: &ResolverTarget,
) -> (
    String,
    Vec<(String, String)>,
    Option<String>,
    Option<String>,
    Option<u16>,
) {
    let mut extras: Vec<(String, String)> = Vec::new();
    let (label, url_for_json, host_for_json, port_for_json) = match target.transport {
        ValidationTransport::Doh => {
            let url = target.url.clone();
            let label = url
                .as_deref()
                .map(strip_https_scheme_for_display)
                .unwrap_or_else(|| target.host.clone().unwrap_or_default());
            if let Some(name) = target.server_name.as_deref()
                && !name.is_empty()
                && !label.starts_with(name)
            {
                extras.push(("sni".to_string(), name.to_string()));
            }
            (label, url, target.host.clone(), target.port)
        }
        ValidationTransport::Dot | ValidationTransport::Doq => {
            let port = target.port.unwrap_or(853);
            let label = format!("{}:{}", target.host.clone().unwrap_or_default(), port);
            if let Some(name) = target.server_name.as_deref()
                && !name.is_empty()
            {
                extras.push(("sni".to_string(), name.to_string()));
            }
            (label, None, target.host.clone(), Some(port))
        }
        ValidationTransport::Dns => {
            let port = target.port.unwrap_or(53);
            let host = target.host.clone().unwrap_or_default();
            let label = if port == 53 {
                host.clone()
            } else {
                format!("{host}:{port}")
            };
            (label, None, target.host.clone(), Some(port))
        }
    };
    (label, extras, url_for_json, host_for_json, port_for_json)
}

pub(crate) fn strip_https_scheme_for_display(url: &str) -> String {
    url.strip_prefix("https://")
        .map(str::to_string)
        .unwrap_or_else(|| url.to_string())
}

pub(crate) fn extract_doh_host(url: &str) -> Option<&str> {
    let after_scheme = url.strip_prefix("https://").unwrap_or(url);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host_port)| host_port);
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split_once(']').map_or(authority, |(host, _)| host)
    } else {
        authority
            .split_once(':')
            .map_or(authority, |(host, _)| host)
    };
    if host.is_empty() { None } else { Some(host) }
}
