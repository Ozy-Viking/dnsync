//! query planning (system / configured-server / ad-hoc).

use super::*;

/// Internal: per-target plan entry, plus the overall `target.kind` for
/// JSON output.
pub(crate) struct QueryPlan {
    pub(crate) kind: TargetKind,
    pub(crate) targets: Vec<PlanTarget>,
}

pub(crate) struct PlanTarget {
    pub(crate) transport: ValidationTransport,
    /// The configured server id this plan entry came from, when named.
    pub(crate) server_id: Option<String>,
    /// The vendor of the named server, carried for group headers.
    pub(crate) server_vendor: Option<VendorKind>,
    /// `Some(target)` runs the lookup; `None` records a `skipped` row
    /// without a network call (explicit transport flag on a missing
    /// or disabled block).
    pub(crate) target: Option<ResolverTarget>,
    pub(crate) target_label: String,
    pub(crate) extras: Vec<(String, String)>,
    pub(crate) url: Option<String>,
    pub(crate) host_for_json: Option<String>,
    pub(crate) port_for_json: Option<u16>,
    pub(crate) timeout: Duration,
    pub(crate) skip_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub enum TargetKind {
    System { display: String },
    Named { servers: Vec<NamedServer> },
    AdHoc,
}

/// One named server in a (possibly multi-server) query, kept for JSON
/// output so each result can be attributed to its server and cluster.
#[derive(Debug, Clone)]
pub struct NamedServer {
    pub server_id: String,
    pub cluster: Option<String>,
}

pub(crate) fn build_query_plan(
    config: Option<&AppConfig>,
    args: &QueryArgs,
    timeout: Duration,
) -> Result<QueryPlan> {
    if args.all_servers || !args.server.is_empty() {
        return build_servers_plan(config, args, timeout);
    }
    if let Some(at) = args.at.as_deref() {
        return build_ad_hoc_plan(at, args, timeout);
    }
    build_system_plan(args, timeout)
}

pub(crate) fn build_system_plan(_args: &QueryArgs, timeout: Duration) -> Result<QueryPlan> {
    let display = system_resolver_display();
    // System path uses Resolver::builder_tokio() directly; we don't
    // construct a ResolverTarget. Encode that with a synthetic
    // PlanTarget that the runner recognises.
    let mut extras = Vec::new();
    extras.push(("system".to_string(), String::new()));
    Ok(QueryPlan {
        kind: TargetKind::System {
            display: display.clone(),
        },
        targets: vec![PlanTarget {
            transport: ValidationTransport::Dns,
            server_id: None,
            server_vendor: None,
            target: None,
            target_label: display,
            extras,
            url: None,
            host_for_json: None,
            port_for_json: None,
            timeout,
            skip_reason: Some("__system__".to_string()),
        }],
    })
}

/// Render the system resolver's nameserver(s) for the header line.
/// Best-effort: reads the platform config; falls back to `system` on
/// error or no entries.
pub(crate) fn system_resolver_display() -> String {
    match hickory_resolver::system_conf::read_system_conf() {
        Ok((config, _)) => {
            let mut servers = config
                .name_servers()
                .iter()
                .map(|ns| ns.ip.to_string())
                .collect::<Vec<_>>();
            servers.sort();
            servers.dedup();
            if servers.is_empty() {
                "system".to_string()
            } else if servers.len() == 1 {
                servers.into_iter().next().unwrap()
            } else {
                servers.join(",")
            }
        }
        Err(_) => "system".to_string(),
    }
}

pub(crate) fn build_servers_plan(
    config: Option<&AppConfig>,
    args: &QueryArgs,
    timeout: Duration,
) -> Result<QueryPlan> {
    let cfg = config.ok_or_else(|| {
        Error::parse("querying a configured server requires a config file; none was loaded")
    })?;

    let servers = select_query_servers(cfg, &args.server, args.all_servers)?;

    let mut named = Vec::with_capacity(servers.len());
    let mut plan_targets = Vec::new();
    for server in &servers {
        plan_targets.extend(plan_targets_for_server(server, args, timeout));
        named.push(NamedServer {
            server_id: server.id.clone(),
            cluster: server.cluster.clone(),
        });
    }

    Ok(QueryPlan {
        kind: TargetKind::Named { servers: named },
        targets: plan_targets,
    })
}

/// Build the per-transport plan entries for a single server, honouring
/// explicit transport flags, `--all-transports`, and the default
/// (single-best) precedence pick.
pub(crate) fn plan_targets_for_server(
    server: &DnsServerConfig,
    args: &QueryArgs,
    timeout: Duration,
) -> Vec<PlanTarget> {
    let mut transports = chosen_transports(args);
    transports.sort_by_key(|t| precedence_index(*t));
    // Unless a transport was named explicitly, drop ones that can't run
    // in this build (DoQ on a non-`doq` build). This keeps fan-outs
    // (`--all`/`--all-transports`) and the default single-best pick from
    // emitting noisy UNSUPPORTED rows for a transport the user never
    // asked for; an explicit `--doq` still surfaces UNSUPPORTED.
    if !has_explicit_transport(args) {
        transports.retain(|t| transport_compiled_in(*t));
    }
    if !args.all_transports
        && !has_explicit_transport(args)
        && let Some(best) = transports
            .iter()
            .copied()
            .find(|transport| ResolverTarget::is_enabled_on(server, *transport))
    {
        transports = vec![best];
    }

    let mut plan_targets = Vec::new();
    for transport in transports {
        let block_enabled = ResolverTarget::is_enabled_on(server, transport);
        if !block_enabled {
            if args.all_transports {
                continue;
            }
            plan_targets.push(skipped_plan_target(
                transport,
                server,
                "block not configured or disabled",
                timeout,
            ));
            continue;
        }
        let Some(mut target) = ResolverTarget::from_server_block(server, transport) else {
            if args.all_transports {
                continue;
            }
            plan_targets.push(skipped_plan_target(
                transport,
                server,
                "block not configured",
                timeout,
            ));
            continue;
        };
        if let Some(override_ms) = args.timeout {
            target.timeout = Duration::from_millis(override_ms);
        } else {
            // Timeout-override is the only thing applied here; everything
            // else (port, server_name, etc.) lives in the block.
            if target.timeout == Duration::ZERO {
                target.timeout = timeout;
            }
        }
        let (label, extras, url, host_for_json, port_for_json) = describe_target(&target);
        let target_timeout = target.timeout;
        plan_targets.push(PlanTarget {
            transport,
            server_id: Some(server.id.clone()),
            server_vendor: Some(server.vendor),
            target: Some(target),
            target_label: label,
            extras,
            url,
            host_for_json,
            port_for_json,
            timeout: target_timeout,
            skip_reason: None,
        });
    }

    plan_targets
}

pub(crate) fn skipped_plan_target(
    transport: ValidationTransport,
    server: &DnsServerConfig,
    reason: &str,
    timeout: Duration,
) -> PlanTarget {
    PlanTarget {
        transport,
        server_id: Some(server.id.clone()),
        server_vendor: Some(server.vendor),
        target: None,
        target_label: format!(
            "—  (no [servers.{}] on {})",
            transport_word(transport),
            server.id
        ),
        extras: Vec::new(),
        url: None,
        host_for_json: None,
        port_for_json: None,
        timeout,
        skip_reason: Some(reason.to_string()),
    }
}

pub(crate) fn has_explicit_transport(args: &QueryArgs) -> bool {
    args.dns || args.dot || args.doh || args.doq
}

pub(crate) fn chosen_transports(args: &QueryArgs) -> Vec<ValidationTransport> {
    let any_explicit = has_explicit_transport(args);
    if args.all {
        return TRANSPORT_PRECEDENCE.to_vec();
    }
    if !any_explicit {
        // Single-best: caller will use precedence to pick the first
        // enabled block.
        return TRANSPORT_PRECEDENCE.to_vec();
    }
    let mut out = Vec::new();
    if args.doh {
        out.push(ValidationTransport::Doh);
    }
    if args.dot {
        out.push(ValidationTransport::Dot);
    }
    if args.dns {
        out.push(ValidationTransport::Dns);
    }
    if args.doq {
        out.push(ValidationTransport::Doq);
    }
    out
}

pub(crate) fn build_ad_hoc_plan(
    at: &str,
    args: &QueryArgs,
    timeout: Duration,
) -> Result<QueryPlan> {
    let parsed = parse_ad_hoc(at)?;
    let forced = forced_transport_from_flags(args);
    let transport = match (parsed.transport, forced) {
        (Some(parsed_t), Some(forced_t)) if parsed_t != forced_t => {
            return Err(Error::parse(format!(
                "ad-hoc target scheme implies {parsed_t:?} but a different transport flag was supplied",
            )));
        }
        (_, Some(t)) | (Some(t), None) => t,
        (None, None) => ValidationTransport::Dns,
    };

    let mut target = ResolverTarget {
        kind: ResolverKind::AdHoc,
        transport,
        host: parsed.host.clone(),
        port: args.port.or(parsed.port),
        url: parsed.url.clone(),
        server_name: args.tls_server_name.clone(),
        tcp_only: transport == ValidationTransport::Dns && args.tcp,
        timeout,
    };
    if let Some(override_ms) = args.timeout {
        target.timeout = Duration::from_millis(override_ms);
    }

    let (label, extras, url, host_for_json, port_for_json) = describe_target(&target);
    let target_timeout = target.timeout;
    Ok(QueryPlan {
        kind: TargetKind::AdHoc,
        targets: vec![PlanTarget {
            transport,
            server_id: None,
            server_vendor: None,
            target: Some(target),
            target_label: label,
            extras,
            url,
            host_for_json,
            port_for_json,
            timeout: target_timeout,
            skip_reason: None,
        }],
    })
}

pub(crate) fn forced_transport_from_flags(args: &QueryArgs) -> Option<ValidationTransport> {
    if args.doh {
        Some(ValidationTransport::Doh)
    } else if args.dot {
        Some(ValidationTransport::Dot)
    } else if args.dns {
        Some(ValidationTransport::Dns)
    } else if args.doq {
        Some(ValidationTransport::Doq)
    } else {
        None
    }
}

pub(crate) fn precedence_index(t: ValidationTransport) -> u8 {
    TRANSPORT_PRECEDENCE
        .iter()
        .position(|p| *p == t)
        .map(|i| i as u8)
        .unwrap_or(255)
}

/// Whether a transport can actually run in this build. Everything is
/// available except DoQ, which is gated behind the non-default `doq`
/// Cargo feature.
pub(crate) fn transport_compiled_in(t: ValidationTransport) -> bool {
    // Everything except DoQ is always available; DoQ needs the feature.
    !matches!(t, ValidationTransport::Doq) || cfg!(feature = "doq")
}

pub(crate) fn transport_word(t: ValidationTransport) -> &'static str {
    match t {
        ValidationTransport::Dns => "dns",
        ValidationTransport::Dot => "dot",
        ValidationTransport::Doh => "doh",
        ValidationTransport::Doq => "doq",
    }
}
