//! `dns query` — direct DNS lookups (dig-style).
//!
//! Resolves a name via the system resolver by default, or via a
//! configured `[[servers]]` entry (`--server <ID>` + one or more of
//! `--dns`/`--dot`/`--doh`/`--doq` or `--all`), or via an ad-hoc
//! resolver (`--at <ADDR>` or dig-style `@ADDR` positional).
//!
//! Output is dig-flavoured: a header line starting with `@`, a blank
//! line, then a column-aligned table of answers (one block per
//! transport when fanning out). `--short` emits answers only;
//! `--json` emits a stable JSON shape.

use std::{fmt::Write, time::Duration, time::Instant};

use clap::Args;
use hickory_resolver::{
    Resolver, config::ResolverOpts, net::runtime::TokioRuntimeProvider, proto::rr::Record,
    proto::rr::RecordType,
};
use serde::Serialize;
use serde_json::json;

use crate::{
    control_plane::config::{AppConfig, DnsServerConfig, ValidationTransport},
    core::{
        dns::{
            resolver::{ResolverKind, ResolverTarget, build_resolver, classify_hickory_error},
            validation::{ObservedRecord, ValidationFailureKind},
        },
        error::{Error, Result},
    },
};

/// Default per-attempt timeout when no `--timeout` and no per-block
/// `timeout_ms` is configured.
const DEFAULT_TIMEOUT_MS: u64 = 5_000;

/// Order in which transports render and run when fanning out, and the
/// precedence used to pick a server's *default* transport when none is
/// requested explicitly. Plain DNS is first (the universally-available
/// baseline); DoQ is last because it is an opt-in build. A server with
/// a single configured transport block uses that block as its default
/// regardless of where the block sits in this list.
pub const TRANSPORT_PRECEDENCE: [ValidationTransport; 4] = [
    ValidationTransport::Dns,
    ValidationTransport::Dot,
    ValidationTransport::Doh,
    ValidationTransport::Doq,
];

const DEFAULT_RECORD_TYPES: [&str; 10] = [
    "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA", "PTR", "SOA",
];

#[derive(Args, Debug, Clone, Default)]
pub struct QueryArgs {
    /// Domain to resolve, plus an optional dig-style `@ADDR` positional
    /// (alias for `--at`). The non-`@` positional is the domain; the
    /// `@`-prefixed one, if any, is the ad-hoc resolver target.
    pub targets: Vec<String>,

    /// Record type, repeatable (default: query all supported standard
    /// types). Standard mnemonics:
    /// `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SRV`, `CAA`, `PTR`,
    /// `SOA`, `ANY`.
    #[arg(short = 't', long = "type", value_name = "RR")]
    pub r#type: Vec<String>,

    /// A configured `[[servers]]` entry to query, repeatable. Each is
    /// matched case-insensitively against `server.id`. Mutually
    /// exclusive with `--at`/`@ADDR`. Pass `--server` more than once to
    /// fan out across several servers, or use `--all-servers`.
    #[arg(long)]
    pub server: Vec<String>,

    /// Ad-hoc resolver. `host[:port]` or `scheme://host[:port][/path]`.
    /// Schemes recognised: `udp://`, `tcp://`, `dns://`, `tls://`,
    /// `dot://`, `https://`, `doh://`, `quic://`, `doq://`.
    #[arg(long)]
    pub at: Option<String>,

    /// Use the `[servers.dns]` block (plain DNS). With `--at`, forces
    /// plain DNS.
    #[arg(long)]
    pub dns: bool,

    /// Use the `[servers.dot]` block (DoT). With `--at`, forces DoT.
    #[arg(long)]
    pub dot: bool,

    /// Use the `[servers.doh]` block (DoH). With `--at`, forces DoH.
    #[arg(long)]
    pub doh: bool,

    /// Use the `[servers.doq]` block (DoQ). With `--at`, forces DoQ.
    /// Requires the `doq` Cargo feature.
    #[arg(long)]
    pub doq: bool,

    /// Query every transport block (DNS/DoT/DoH/DoQ) present and
    /// `enabled = true` on the target. Requires a server target
    /// (`--server`/`--all-servers`). Mutually exclusive with the
    /// individual `--dns`/`--dot`/`--doh`/`--doq` flags.
    #[arg(long)]
    pub all_transports: bool,

    /// Query every configured `[[servers]]` entry. Cannot be combined
    /// with `--at`/`@ADDR`. Without a transport flag, each server is
    /// queried over its default transport (see precedence).
    #[arg(long)]
    pub all_servers: bool,

    /// Query every supported record type, overriding any `-t`/`--type`.
    /// This is also the default when no `-t` is given.
    #[arg(long)]
    pub all_types: bool,

    /// Shorthand for `--all-servers --all-types --all-transports`:
    /// every server, every record type, every enabled transport.
    #[arg(long)]
    pub all: bool,

    /// Override the port. Defaults: DNS 53, DoT 853, DoH 443, DoQ 853.
    /// Only valid with an ad-hoc target.
    #[arg(long)]
    pub port: Option<u16>,

    /// SNI / certificate name override for DoT, DoH, DoQ. Only valid
    /// with an ad-hoc target.
    #[arg(long = "tls-server-name")]
    pub tls_server_name: Option<String>,

    /// Per-attempt timeout in milliseconds (default 5000).
    #[arg(long)]
    pub timeout: Option<u64>,

    /// With `--dns`, force TCP only for the plain-DNS query (skip
    /// UDP). Ignored for other transports.
    #[arg(long)]
    pub tcp: bool,

    /// Follow CNAME (and DNAME) chains to their terminal address
    /// records. Without this, a single-type query like `-t CNAME` shows
    /// only the CNAME hop; with it, the chain is walked to its A/AAAA
    /// terminal and the whole chain is shown in order. Bounded against
    /// loops by a depth limit.
    #[arg(long, visible_alias = "chain")]
    pub chase: bool,

    /// Print only the data column. Mirrors `dig +short`.
    #[arg(long)]
    pub short: bool,

    /// Emit structured JSON output.
    #[arg(long)]
    pub json: bool,
}

/// Maximum number of chain hops `--chase` will follow before giving up,
/// guarding against CNAME loops and pathologically long chains.
const MAX_CHASE_DEPTH: usize = 8;

/// Record types `--chase` looks up when walking to a chain's terminal:
/// further CNAMEs to keep walking, plus the address types that end it.
const CHASE_TYPES: [&str; 3] = ["CNAME", "A", "AAAA"];

/// Per-transport outcome for one block within a single `dns query`
/// invocation. The renderer turns these into header+rows / short
/// lines / JSON entries.
#[derive(Debug, Clone)]
pub struct QueryResultBlock {
    pub target_label: String,
    /// The configured server id this block was produced for, when the
    /// target was a named `[[servers]]` entry. `None` for the system
    /// resolver and ad-hoc targets. Used to disambiguate headers and
    /// JSON results when fanning out across multiple servers.
    pub server_id: Option<String>,
    pub transport: ValidationTransport,
    pub extras: Vec<(String, String)>,
    pub url: Option<String>,
    pub host_for_json: Option<String>,
    pub port_for_json: Option<u16>,
    pub elapsed: Duration,
    pub status: QueryStatus,
    pub records: Vec<ObservedRecord>,
    pub asked_types: Vec<String>,
    /// The domain that was queried, kept so status rows (NXDOMAIN,
    /// TIMEOUT, …) can show the name on the left even when no answer
    /// records came back.
    pub queried_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryStatus {
    NoError,
    NxDomain,
    Servfail,
    Refused,
    Timeout,
    TlsFailure,
    DohHttpFailure,
    MalformedResponse,
    UnsupportedTransport,
    Skipped { reason: String },
}

impl QueryStatus {
    fn header_word(&self) -> Option<&str> {
        Some(match self {
            QueryStatus::NoError => return None,
            QueryStatus::NxDomain => "NXDOMAIN",
            QueryStatus::Servfail => "SERVFAIL",
            QueryStatus::Refused => "REFUSED",
            QueryStatus::Timeout => "TIMEOUT",
            QueryStatus::TlsFailure => "TLS_FAILURE",
            QueryStatus::DohHttpFailure => "HTTP_FAILURE",
            QueryStatus::MalformedResponse => "MALFORMED",
            QueryStatus::UnsupportedTransport => "UNSUPPORTED",
            QueryStatus::Skipped { .. } => "SKIPPED",
        })
    }

    fn json_tag(&self) -> &'static str {
        match self {
            QueryStatus::NoError => "noerror",
            QueryStatus::NxDomain => "nxdomain",
            QueryStatus::Servfail => "servfail",
            QueryStatus::Refused => "refused",
            QueryStatus::Timeout => "timeout",
            QueryStatus::TlsFailure => "tls_failure",
            QueryStatus::DohHttpFailure => "doh_http_failure",
            QueryStatus::MalformedResponse => "malformed_response",
            QueryStatus::UnsupportedTransport => "unsupported_transport",
            QueryStatus::Skipped { .. } => "skipped",
        }
    }

    /// Severity rank — `noerror` is best (0), failure modes worst.
    /// Used for the "worst across blocks" exit-code rule.
    fn severity(&self) -> u8 {
        match self {
            QueryStatus::NoError => 0,
            QueryStatus::Skipped { .. } => 1,
            QueryStatus::NxDomain => 2,
            QueryStatus::Servfail
            | QueryStatus::Refused
            | QueryStatus::Timeout
            | QueryStatus::TlsFailure
            | QueryStatus::DohHttpFailure
            | QueryStatus::MalformedResponse
            | QueryStatus::UnsupportedTransport => 3,
        }
    }
}

impl From<ValidationFailureKind> for QueryStatus {
    fn from(kind: ValidationFailureKind) -> Self {
        match kind {
            ValidationFailureKind::Timeout => QueryStatus::Timeout,
            ValidationFailureKind::Nxdomain => QueryStatus::NxDomain,
            ValidationFailureKind::Servfail => QueryStatus::Servfail,
            ValidationFailureKind::Refused => QueryStatus::Refused,
            ValidationFailureKind::TlsFailure => QueryStatus::TlsFailure,
            ValidationFailureKind::DohHttpFailure => QueryStatus::DohHttpFailure,
            ValidationFailureKind::MalformedResponse => QueryStatus::MalformedResponse,
            ValidationFailureKind::UnsupportedTransport => QueryStatus::UnsupportedTransport,
        }
    }
}

/// Entry point for the `dns query` subcommand.
///
/// Returns an exit code (0 on success; non-zero per-status mapping).
/// Output goes to stdout; errors that prevent any query from running
/// (parse-time invariants, unknown `--server`) return `Err`.
pub async fn run_query(config: Option<AppConfig>, args: QueryArgs) -> Result<i32> {
    let outcome = execute_query(config, args.clone()).await?;

    if args.json {
        print_json(
            &outcome.domain,
            &outcome.record_types,
            &outcome.target_kind,
            &outcome.blocks,
        );
    } else if args.short {
        print_short(&outcome.blocks);
    } else {
        print_table(&outcome.blocks, &outcome.record_types);
    }

    Ok(exit_code_for(&outcome.blocks))
}

/// Programmatic entry point — runs a query and returns the per-
/// transport results without printing anything. Shared between the
/// CLI runner and the MCP `dns_resolve` tool so behaviour stays in
/// parity by construction.
pub async fn execute_query(config: Option<AppConfig>, args: QueryArgs) -> Result<QueryOutcome> {
    let (domain, ad_hoc_from_positional) = split_targets(&args.targets)?;
    let mut effective = args;
    if let Some(at) = ad_hoc_from_positional {
        if effective.at.is_some() {
            return Err(Error::parse(
                "ambiguous resolver target: pass either `@ADDR` or `--at <ADDR>`, not both",
            ));
        }
        effective.at = Some(at);
    }

    // `--all` is sugar for the three independent "all" axes. Expand it
    // up front so the rest of the pipeline only reasons about the
    // specific flags.
    if effective.all {
        effective.all_servers = true;
        effective.all_types = true;
        effective.all_transports = true;
    }

    validate_cli_rules(&effective)?;

    let record_types = parse_record_types(&effective.r#type, effective.all_types)?;
    let default_timeout = Duration::from_millis(effective.timeout.unwrap_or(DEFAULT_TIMEOUT_MS));

    let plan = build_query_plan(config.as_ref(), &effective, default_timeout)?;

    let mut blocks = Vec::with_capacity(plan.targets.len());
    for plan_target in plan.targets {
        blocks.push(run_block(plan_target, &record_types, &domain, effective.chase).await);
    }

    Ok(QueryOutcome {
        domain,
        record_types,
        target_kind: plan.kind,
        blocks,
    })
}

/// Result of `execute_query` — everything needed to render output or
/// shape a JSON response for the MCP tool.
#[derive(Debug, Clone)]
pub struct QueryOutcome {
    pub domain: String,
    pub record_types: Vec<String>,
    pub target_kind: TargetKind,
    pub blocks: Vec<QueryResultBlock>,
}

impl QueryOutcome {
    /// Render the same JSON shape `dns query --json` emits. Used by
    /// the MCP `dns_resolve` tool to keep CLI/MCP parity.
    pub fn to_json(&self) -> serde_json::Value {
        build_json_value(
            &self.domain,
            &self.record_types,
            &self.target_kind,
            &self.blocks,
        )
    }
}

/// Split the positionals into a single domain plus an optional `@addr`.
fn split_targets(positionals: &[String]) -> Result<(String, Option<String>)> {
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

fn validate_cli_rules(args: &QueryArgs) -> Result<()> {
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

fn parse_record_types(input: &[String], all_types: bool) -> Result<Vec<String>> {
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

/// Internal: per-target plan entry, plus the overall `target.kind` for
/// JSON output.
struct QueryPlan {
    kind: TargetKind,
    targets: Vec<PlanTarget>,
}

struct PlanTarget {
    transport: ValidationTransport,
    /// The configured server id this plan entry came from, when named.
    server_id: Option<String>,
    /// `Some(target)` runs the lookup; `None` records a `skipped` row
    /// without a network call (explicit transport flag on a missing
    /// or disabled block).
    target: Option<ResolverTarget>,
    target_label: String,
    extras: Vec<(String, String)>,
    url: Option<String>,
    host_for_json: Option<String>,
    port_for_json: Option<u16>,
    timeout: Duration,
    skip_reason: Option<String>,
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

fn build_query_plan(
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

fn build_system_plan(_args: &QueryArgs, timeout: Duration) -> Result<QueryPlan> {
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
fn system_resolver_display() -> String {
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

fn build_servers_plan(
    config: Option<&AppConfig>,
    args: &QueryArgs,
    timeout: Duration,
) -> Result<QueryPlan> {
    let cfg = config.ok_or_else(|| {
        Error::parse("querying a configured server requires a config file; none was loaded")
    })?;

    let servers = resolve_server_set(cfg, args)?;

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

/// Resolve the set of servers to query: every configured server for
/// `--all-servers`, or each explicitly-named `--server <ID>` (rejecting
/// cluster ids and de-duplicating repeats).
fn resolve_server_set<'a>(
    cfg: &'a AppConfig,
    args: &QueryArgs,
) -> Result<Vec<&'a DnsServerConfig>> {
    if args.all_servers {
        if cfg.servers.is_empty() {
            return Err(Error::parse(
                "`--all-servers` was given but the config defines no `[[servers]]`",
            ));
        }
        return Ok(cfg.servers.iter().collect());
    }

    let mut out: Vec<&DnsServerConfig> = Vec::new();
    for id in &args.server {
        if cfg.clusters.contains_key(id) {
            let members = cfg
                .clusters
                .get(id)
                .map(|c| c.members.join(", "))
                .unwrap_or_default();
            return Err(Error::parse(format!(
                "'{id}' is a cluster id, not a server. Pick one of its members ({members}) with --server",
            )));
        }
        let server = cfg.selected_server(Some(id))?;
        if !out.iter().any(|existing| existing.id == server.id) {
            out.push(server);
        }
    }
    Ok(out)
}

/// Build the per-transport plan entries for a single server, honouring
/// explicit transport flags, `--all-transports`, and the default
/// (single-best) precedence pick.
fn plan_targets_for_server(
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

fn skipped_plan_target(
    transport: ValidationTransport,
    server: &DnsServerConfig,
    reason: &str,
    timeout: Duration,
) -> PlanTarget {
    PlanTarget {
        transport,
        server_id: Some(server.id.clone()),
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

fn has_explicit_transport(args: &QueryArgs) -> bool {
    args.dns || args.dot || args.doh || args.doq
}

fn chosen_transports(args: &QueryArgs) -> Vec<ValidationTransport> {
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

fn build_ad_hoc_plan(at: &str, args: &QueryArgs, timeout: Duration) -> Result<QueryPlan> {
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

fn forced_transport_from_flags(args: &QueryArgs) -> Option<ValidationTransport> {
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

#[derive(Debug, Default)]
struct ParsedAdHoc {
    transport: Option<ValidationTransport>,
    host: Option<String>,
    port: Option<u16>,
    url: Option<String>,
}

fn parse_ad_hoc(raw: &str) -> Result<ParsedAdHoc> {
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

fn split_addr(raw: &str) -> Result<(String, Option<u16>)> {
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

fn describe_target(
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

fn strip_https_scheme_for_display(url: &str) -> String {
    url.strip_prefix("https://")
        .map(str::to_string)
        .unwrap_or_else(|| url.to_string())
}

fn precedence_index(t: ValidationTransport) -> u8 {
    TRANSPORT_PRECEDENCE
        .iter()
        .position(|p| *p == t)
        .map(|i| i as u8)
        .unwrap_or(255)
}

/// Whether a transport can actually run in this build. Everything is
/// available except DoQ, which is gated behind the non-default `doq`
/// Cargo feature.
fn transport_compiled_in(t: ValidationTransport) -> bool {
    match t {
        ValidationTransport::Doq => cfg!(feature = "doq"),
        _ => true,
    }
}

fn transport_word(t: ValidationTransport) -> &'static str {
    match t {
        ValidationTransport::Dns => "dns",
        ValidationTransport::Dot => "dot",
        ValidationTransport::Doh => "doh",
        ValidationTransport::Doq => "doq",
    }
}

async fn run_block(
    plan: PlanTarget,
    record_types: &[String],
    domain: &str,
    chase: bool,
) -> QueryResultBlock {
    let started = Instant::now();
    let asked_types = record_types.to_vec();
    let queried_name = domain.to_string();
    let status_for_skip = plan.skip_reason.clone();

    let finish = |status: QueryStatus, records: Vec<ObservedRecord>| QueryResultBlock {
        target_label: plan.target_label.clone(),
        server_id: plan.server_id.clone(),
        transport: plan.transport,
        extras: plan.extras.clone(),
        url: plan.url.clone(),
        host_for_json: plan.host_for_json.clone(),
        port_for_json: plan.port_for_json,
        elapsed: started.elapsed(),
        status,
        records,
        asked_types: asked_types.clone(),
        queried_name: queried_name.clone(),
    };

    // System path: special-case.
    if plan.skip_reason.as_deref() == Some("__system__") {
        let resolver = match build_system_resolver(plan.timeout) {
            Ok(r) => r,
            Err(status) => return finish(status, Vec::new()),
        };
        let (status, records) =
            lookup_all(&resolver, domain, record_types, plan.transport, chase).await;
        return finish(status, records);
    }

    let Some(mut target) = plan.target.clone() else {
        return finish(
            QueryStatus::Skipped {
                reason: status_for_skip.unwrap_or_else(|| "skipped".to_string()),
            },
            Vec::new(),
        );
    };

    // Bootstrap: hickory's NameServerConfig variants all need an IP address.
    // Resolve any hostname via the system resolver before building the resolver.
    let needs_bootstrap = target
        .host
        .as_deref()
        .is_none_or(|h| h.parse::<std::net::IpAddr>().is_err());
    if needs_bootstrap {
        match target.transport {
            ValidationTransport::Doh => {
                if let Some(ref url) = target.url {
                    match bootstrap_doh_host(url, target.timeout).await {
                        Ok(ip) => target.host = Some(ip),
                        Err(status) => return finish(status, Vec::new()),
                    }
                }
            }
            ValidationTransport::Dns
            | ValidationTransport::Dot
            | ValidationTransport::Doq => {
                if let Some(ref host) = target.host.clone() {
                    match bootstrap_host(host, target.transport, target.timeout).await {
                        Ok(ip) => target.host = Some(ip),
                        Err(status) => return finish(status, Vec::new()),
                    }
                }
            }
        }
    }

    let resolver = match build_resolver(&target) {
        Ok(r) => r,
        Err(kind) => return finish(QueryStatus::from(kind), Vec::new()),
    };
    let (status, records) =
        lookup_all(&resolver, domain, record_types, plan.transport, chase).await;
    finish(status, records)
}

/// Resolve a hostname via the system resolver, preferring IPv4 for
/// container/CI compatibility. Returns early if `host` is already an IP.
async fn bootstrap_host(
    host: &str,
    transport: ValidationTransport,
    timeout: Duration,
) -> std::result::Result<String, QueryStatus> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ip.to_string());
    }
    let resolver = build_system_resolver(timeout)?;
    let lookup = resolver.lookup_ip(host).await.map_err(|e| {
        QueryStatus::from(classify_hickory_error(transport, &e.to_string()))
    })?;
    // Prefer IPv4: many container/CI environments have no IPv6 outbound.
    let ips: Vec<std::net::IpAddr> = lookup.iter().collect();
    ips.iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| ips.first())
        .map(|ip| ip.to_string())
        .ok_or(QueryStatus::NxDomain)
}

/// Resolve the host portion of a DoH URL via the system resolver.
async fn bootstrap_doh_host(
    url: &str,
    timeout: Duration,
) -> std::result::Result<String, QueryStatus> {
    let host = extract_doh_host(url).ok_or(QueryStatus::MalformedResponse)?;
    bootstrap_host(host, ValidationTransport::Doh, timeout).await
}

fn extract_doh_host(url: &str) -> Option<&str> {
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

fn build_system_resolver(
    timeout: Duration,
) -> std::result::Result<Resolver<TokioRuntimeProvider>, QueryStatus> {
    let mut opts = ResolverOpts::default();
    opts.timeout = timeout;
    opts.attempts = 1;
    let builder = Resolver::builder_tokio().map_err(|e| {
        tracing::debug!(%e, "could not load system resolver");
        QueryStatus::MalformedResponse
    })?;
    builder.with_options(opts).build().map_err(|e| {
        tracing::debug!(%e, "system resolver build failed");
        QueryStatus::MalformedResponse
    })
}

async fn lookup_all(
    resolver: &Resolver<TokioRuntimeProvider>,
    domain: &str,
    record_types: &[String],
    transport: ValidationTransport,
    chase: bool,
) -> (QueryStatus, Vec<ObservedRecord>) {
    let mut all_records = Vec::new();
    let mut worst_status = QueryStatus::NoError;

    for rr_name in record_types {
        let Ok(rr_type) = rr_name.parse::<RecordType>() else {
            worst_status = worst(worst_status, QueryStatus::MalformedResponse);
            continue;
        };
        match resolver.lookup(domain, rr_type).await {
            Ok(lookup) => {
                if lookup.answers().is_empty() {
                    // Empty answer set for that type — treat as no data
                    // (NoError but no records emitted for this type).
                } else {
                    for record in observed_records_from_answers(lookup.answers()) {
                        push_observed_record_once(&mut all_records, record);
                    }
                }
            }
            Err(err) => {
                let kind = classify_hickory_error(transport, &err.to_string());
                worst_status = worst(worst_status, QueryStatus::from(kind));
            }
        }
    }

    if chase {
        chase_chain(resolver, &mut all_records).await;
    }

    if all_records.is_empty() {
        (worst_status, all_records)
    } else {
        // If we have any successful records, return NoError status so
        // expand_rows will display them instead of showing status-only rows.
        // Mixed success/failure means we show the successful answers.
        (QueryStatus::NoError, all_records)
    }
}

/// Follow CNAME (and DNAME) targets to their terminal address records,
/// appending the discovered hops/terminals to `records` in chain order.
///
/// A "dangling" target is a CNAME/DNAME value that is not itself the
/// owner of any record we've already collected — i.e. the chain's
/// current tail. We look up the chase types for each dangling target,
/// repeating until no new tail appears, the depth limit is reached, or a
/// target loops back (tracked via `visited`). Lookups here are
/// best-effort: errors and NODATA terminals simply stop that branch
/// without changing the block's status.
async fn chase_chain(resolver: &Resolver<TokioRuntimeProvider>, records: &mut Vec<ObservedRecord>) {
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();

    for _ in 0..MAX_CHASE_DEPTH {
        let owners: std::collections::HashSet<String> =
            records.iter().map(|r| chain_key(&r.name)).collect();

        let mut targets: Vec<String> = Vec::new();
        for record in records.iter() {
            if !is_chain_record(&record.record_type) {
                continue;
            }
            for value in &record.values {
                let key = chain_key(value);
                if owners.contains(&key) || visited.contains(&key) {
                    continue;
                }
                if !targets.contains(value) {
                    targets.push(value.clone());
                }
            }
        }

        if targets.is_empty() {
            break;
        }

        let mut added_any = false;
        for target in targets {
            visited.insert(chain_key(&target));
            for rr_name in CHASE_TYPES {
                let Ok(rr_type) = rr_name.parse::<RecordType>() else {
                    continue;
                };
                if let Ok(lookup) = resolver.lookup(target.as_str(), rr_type).await {
                    for record in observed_records_from_answers(lookup.answers()) {
                        let before = records.len();
                        push_observed_record_once(records, record);
                        if records.len() > before {
                            added_any = true;
                        }
                    }
                }
            }
        }

        // Nothing new resolved (NODATA terminal or only dead branches) —
        // stop rather than spin until the depth limit.
        if !added_any {
            break;
        }
    }
}

/// True for record types whose rdata is a target name worth chasing.
fn is_chain_record(record_type: &str) -> bool {
    matches!(record_type, "CNAME" | "DNAME")
}

/// Normalise a name for chain-membership comparison: drop the trailing
/// dot and lowercase, so `Target.Example.` and `target.example` match.
fn chain_key(name: &str) -> String {
    trim_trailing_dot(name).to_ascii_lowercase()
}

fn push_observed_record_once(records: &mut Vec<ObservedRecord>, record: ObservedRecord) {
    // Identity is (name, type, values) — TTL is deliberately excluded.
    // The same chain record (e.g. a CNAME) is returned by more than one
    // type-lookup in a multi-type query (the A lookup follows the chain
    // and includes the CNAME; the explicit CNAME lookup returns it too).
    // A caching resolver hands back a decrementing TTL, so the copies
    // differ only in TTL. Collapse them into one row, keeping the
    // smallest TTL (the most current view of the cache countdown).
    if let Some(existing) = records.iter_mut().find(|existing| {
        existing.name == record.name
            && existing.record_type == record.record_type
            && existing.values == record.values
    }) {
        existing.ttl = match (existing.ttl, record.ttl) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        return;
    }
    records.push(record);
}

fn observed_records_from_answers(answers: &[Record]) -> Vec<ObservedRecord> {
    answers
        .iter()
        .map(|record| ObservedRecord {
            name: record.name.to_string(),
            record_type: record.record_type().to_string(),
            ttl: Some(record.ttl),
            values: vec![record.data.to_string()],
        })
        .collect()
}

fn worst(a: QueryStatus, b: QueryStatus) -> QueryStatus {
    if a.severity() >= b.severity() { a } else { b }
}

fn exit_code_for(blocks: &[QueryResultBlock]) -> i32 {
    let mut worst = 0u8;
    for b in blocks {
        worst = worst.max(b.status.severity());
    }
    match worst {
        0 => 0,
        1 => 0, // implicit skip doesn't affect exit
        2 => 1, // NXDOMAIN
        _ => 2,
    }
}

// ───── Rendering ─────────────────────────────────────────────────────────────

fn print_table(blocks: &[QueryResultBlock], asked_types: &[String]) {
    let multi_type = asked_types.len() > 1;
    let multi_server = distinct_server_count(blocks) > 1;
    let mut first = true;
    for block in blocks {
        if !first {
            println!();
        }
        first = false;
        print_header(block, multi_server);
        println!();
        let rows = expand_rows(block, multi_type);
        print_rows(&rows, multi_type);
    }
}

/// Number of distinct named servers represented across the blocks. Used
/// to decide whether headers need to spell out which server a block
/// belongs to.
fn distinct_server_count(blocks: &[QueryResultBlock]) -> usize {
    let mut ids: Vec<&str> = blocks
        .iter()
        .filter_map(|b| b.server_id.as_deref())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids.len()
}

fn print_header(block: &QueryResultBlock, multi_server: bool) {
    let mut line = format!(
        "@ {}  {}",
        block.target_label,
        transport_word(block.transport)
    );
    if multi_server && let Some(id) = block.server_id.as_deref() {
        let _ = write!(&mut line, "  server={id}");
    }
    for (k, v) in &block.extras {
        if v.is_empty() {
            line.push_str("  ");
            line.push_str(k);
        } else {
            let _ = write!(&mut line, "  {k}={v}");
        }
    }
    let _ = write!(&mut line, "  {}ms", block.elapsed.as_millis());
    println!("{line}");
}

#[derive(Debug)]
struct Row {
    name: String,
    rr_type: String,
    ttl: Option<String>,
    data: String,
}

fn expand_rows(block: &QueryResultBlock, _multi_type: bool) -> Vec<Row> {
    // For noerror, one row per record value; for non-noerror, one row
    // per asked type with the status word as the data field. Status
    // rows fall back to `queried_name` so NXDOMAIN/TIMEOUT/etc still
    // show what was asked.
    let mut rows = Vec::new();
    if let Some(status_word) = block.status.header_word() {
        let name = trim_trailing_dot(&block.queried_name).to_string();
        for rr_type in &block.asked_types {
            rows.push(Row {
                name: name.clone(),
                rr_type: rr_type.clone(),
                ttl: None,
                data: status_word.to_string(),
            });
        }
        return rows;
    }
    for record in &block.records {
        for value in &record.values {
            rows.push(Row {
                name: trim_trailing_dot(&record.name).to_string(),
                rr_type: record.record_type.clone(),
                ttl: record.ttl.map(|ttl| ttl.to_string()),
                data: value.clone(),
            });
        }
    }
    rows
}

fn trim_trailing_dot(name: &str) -> &str {
    name.strip_suffix('.').unwrap_or(name)
}

fn print_rows(rows: &[Row], multi_type: bool) {
    if rows.is_empty() {
        return;
    }
    let name_w = rows.iter().map(|r| r.name.len()).max().unwrap_or(0);
    let type_w = rows.iter().map(|r| r.rr_type.len()).max().unwrap_or(0);
    let ttl_w = rows
        .iter()
        .map(|r| r.ttl.as_deref().unwrap_or("").len())
        .max()
        .unwrap_or(0);

    for row in rows {
        let mut line = String::new();
        let _ = write!(&mut line, "{:<name_w$}", row.name);
        if multi_type
            || ttl_w > 0
            || rows.iter().any(|r| r.ttl.is_some())
            || !row.rr_type.is_empty()
        {
            let _ = write!(&mut line, "  {:<type_w$}", row.rr_type);
        }
        if let Some(ttl) = &row.ttl {
            let _ = write!(&mut line, "  {:<ttl_w$}", ttl);
        }
        let _ = write!(&mut line, "  {}", row.data);
        println!("{line}");
    }
}

fn print_short(blocks: &[QueryResultBlock]) {
    for block in blocks {
        for record in &block.records {
            for value in &record.values {
                println!("{value}");
            }
        }
    }
}

#[derive(Serialize)]
struct JsonOutput<'a> {
    query: JsonQuery<'a>,
    target: JsonTarget<'a>,
    results: Vec<JsonResult<'a>>,
}

#[derive(Serialize)]
struct JsonQuery<'a> {
    name: &'a str,
    types: &'a [String],
}

#[derive(Serialize)]
struct JsonTarget<'a> {
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_resolver: Option<&'a str>,
}

#[derive(Serialize)]
struct JsonResult<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<&'a str>,
    resolver: JsonResolver<'a>,
    elapsed_ms: u128,
    status: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    skip_reason: Option<&'a str>,
    answers: Vec<JsonAnswer>,
}

#[derive(Serialize)]
struct JsonResolver<'a> {
    transport: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_name: Option<&'a str>,
}

#[derive(Serialize)]
struct JsonAnswer {
    name: String,
    #[serde(rename = "type")]
    rr_type: String,
    data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
}

fn print_json(
    domain: &str,
    record_types: &[String],
    kind: &TargetKind,
    blocks: &[QueryResultBlock],
) {
    let value = build_json_value(domain, record_types, kind, blocks);
    println!(
        "{}",
        serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
    );
}

/// Produce the stable JSON shape `dns query --json` emits, without
/// printing. Reused by the MCP `dns_resolve` tool so CLI and MCP
/// return identical structured payloads.
fn build_json_value(
    domain: &str,
    record_types: &[String],
    kind: &TargetKind,
    blocks: &[QueryResultBlock],
) -> serde_json::Value {
    let target = match kind {
        TargetKind::System { display } => JsonTarget {
            kind: "system",
            server: None,
            cluster: None,
            system_resolver: Some(display.as_str()),
        },
        TargetKind::Named { servers } => {
            // Top-level `server`/`cluster` stay populated for the common
            // single-server case (back-compat); for a multi-server fan-
            // out they are null and each result carries its own `server`.
            let (server, cluster) = match servers.as_slice() {
                [only] => (Some(only.server_id.as_str()), only.cluster.as_deref()),
                _ => (None, None),
            };
            JsonTarget {
                kind: "named",
                server,
                cluster,
                system_resolver: None,
            }
        }
        TargetKind::AdHoc => JsonTarget {
            kind: "ad_hoc",
            server: None,
            cluster: None,
            system_resolver: None,
        },
    };

    let results: Vec<JsonResult> = blocks
        .iter()
        .map(|b| JsonResult {
            server: b.server_id.as_deref(),
            resolver: JsonResolver {
                transport: transport_word(b.transport),
                address: b.host_for_json.as_deref(),
                port: b.port_for_json,
                url: b.url.as_deref(),
                server_name: b
                    .extras
                    .iter()
                    .find(|(k, _)| k == "sni")
                    .map(|(_, v)| v.as_str()),
            },
            elapsed_ms: b.elapsed.as_millis(),
            status: b.status.json_tag(),
            skip_reason: match &b.status {
                QueryStatus::Skipped { reason } => Some(reason.as_str()),
                _ => None,
            },
            answers: b
                .records
                .iter()
                .flat_map(|r| {
                    r.values.iter().map(move |v| JsonAnswer {
                        name: trim_trailing_dot(&r.name).to_string(),
                        rr_type: r.record_type.clone(),
                        data: v.clone(),
                        ttl: r.ttl,
                    })
                })
                .collect(),
        })
        .collect();

    let out = JsonOutput {
        query: JsonQuery {
            name: domain,
            types: record_types,
        },
        target,
        results,
    };
    json!(out)
}

// ───── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use clap::Parser;
    use hickory_resolver::proto::rr::{Name, RData, Record};
    use rstest::rstest;
    use std::str::FromStr;

    fn parse(args: &[&str]) -> Result<QueryArgs> {
        let mut argv = vec!["dns", "query"];
        argv.extend_from_slice(args);
        let cli = Cli::try_parse_from(argv).map_err(|e| Error::parse(e.to_string()))?;
        match cli.command {
            Command::Query(q) => Ok(q),
            _ => Err(Error::parse("expected Command::Query")),
        }
    }

    #[test]
    fn split_targets_domain_only() {
        let (domain, at) = split_targets(&["huly.hankin.io".to_string()]).unwrap();
        assert_eq!(domain, "huly.hankin.io");
        assert_eq!(at, None);
    }

    #[test]
    fn split_targets_with_at_sugar() {
        let (domain, at) =
            split_targets(&["huly.hankin.io".to_string(), "@1.1.1.1".to_string()]).unwrap();
        assert_eq!(domain, "huly.hankin.io");
        assert_eq!(at.as_deref(), Some("1.1.1.1"));
    }

    #[test]
    fn split_targets_at_before_domain() {
        let (domain, at) =
            split_targets(&["@1.1.1.1".to_string(), "huly.hankin.io".to_string()]).unwrap();
        assert_eq!(domain, "huly.hankin.io");
        assert_eq!(at.as_deref(), Some("1.1.1.1"));
    }

    #[test]
    fn split_targets_rejects_multiple_at() {
        assert!(
            split_targets(&[
                "huly.hankin.io".to_string(),
                "@1.1.1.1".to_string(),
                "@8.8.8.8".to_string(),
            ])
            .is_err()
        );
    }

    #[test]
    fn split_targets_rejects_extra_positional() {
        assert!(
            split_targets(&["huly.hankin.io".to_string(), "extra.example".to_string(),]).is_err()
        );
    }

    #[test]
    fn split_targets_requires_domain() {
        assert!(split_targets(&[]).is_err());
        assert!(split_targets(&["@1.1.1.1".to_string()]).is_err());
    }

    #[test]
    fn parse_record_types_default_to_supported_standard_types() {
        let types = parse_record_types(&[], false).unwrap();
        assert_eq!(
            types,
            DEFAULT_RECORD_TYPES
                .iter()
                .map(|rr_type| (*rr_type).to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn parse_record_types_all_types_overrides_explicit() {
        let types = parse_record_types(&["A".to_string()], true).unwrap();
        assert_eq!(
            types,
            DEFAULT_RECORD_TYPES
                .iter()
                .map(|rr_type| (*rr_type).to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn parse_record_types_uppercases_and_dedups() {
        let types =
            parse_record_types(&["a".to_string(), "AAAA".to_string(), "A".to_string()], false)
                .unwrap();
        assert_eq!(types, vec!["A".to_string(), "AAAA".to_string()]);
    }

    #[test]
    fn parse_record_types_rejects_unknown() {
        assert!(parse_record_types(&["BOGUS".to_string()], false).is_err());
    }

    #[test]
    fn validate_rejects_server_and_at() {
        let mut args = QueryArgs::default();
        args.server = vec!["dns1".to_string()];
        args.at = Some("1.1.1.1".to_string());
        assert!(validate_cli_rules(&args).is_err());
    }

    #[test]
    fn validate_rejects_all_servers_with_explicit_server() {
        let mut args = QueryArgs::default();
        args.all_servers = true;
        args.server = vec!["dns1".to_string()];
        assert!(validate_cli_rules(&args).is_err());
    }

    #[test]
    fn validate_rejects_all_servers_with_at() {
        let mut args = QueryArgs::default();
        args.all_servers = true;
        args.at = Some("1.1.1.1".to_string());
        assert!(validate_cli_rules(&args).is_err());
    }

    #[test]
    fn validate_rejects_all_transports_with_explicit_transport() {
        let mut args = QueryArgs::default();
        args.server = vec!["dns1".to_string()];
        args.all_transports = true;
        args.dot = true;
        assert!(validate_cli_rules(&args).is_err());
    }

    #[test]
    fn validate_rejects_all_transports_without_server() {
        let mut args = QueryArgs::default();
        args.all_transports = true;
        args.at = Some("1.1.1.1".to_string());
        assert!(validate_cli_rules(&args).is_err());
    }

    #[test]
    fn validate_rejects_transport_flags_with_no_target() {
        let mut args = QueryArgs::default();
        args.dot = true;
        assert!(validate_cli_rules(&args).is_err());
    }

    #[test]
    fn validate_rejects_multiple_transport_flags_with_at() {
        let mut args = QueryArgs::default();
        args.at = Some("1.1.1.1".to_string());
        args.dns = true;
        args.dot = true;
        assert!(validate_cli_rules(&args).is_err());
    }

    #[test]
    fn validate_rejects_port_with_named_server() {
        let mut args = QueryArgs::default();
        args.server = vec!["dns1".to_string()];
        args.port = Some(53);
        assert!(validate_cli_rules(&args).is_err());
    }

    #[test]
    fn validate_accepts_single_target_with_no_transport_flags() {
        let mut args = QueryArgs::default();
        args.server = vec!["dns1".to_string()];
        validate_cli_rules(&args).unwrap();

        let mut args = QueryArgs::default();
        args.at = Some("1.1.1.1".to_string());
        validate_cli_rules(&args).unwrap();
    }

    #[test]
    fn validate_accepts_multiple_servers() {
        let mut args = QueryArgs::default();
        args.server = vec!["dns1".to_string(), "dns2".to_string()];
        validate_cli_rules(&args).unwrap();
    }

    fn server_with_dns_and_doq() -> DnsServerConfig {
        use crate::control_plane::config::{
            DnsTransportConfig, DoqTransportConfig, McpPermissions, VendorKind,
        };
        DnsServerConfig {
            id: "dns1".to_string(),
            vendor: VendorKind::Technitium,
            location: None,
            base_url: None,
            base_url_env: None,
            token: None,
            token_env: None,
            org_id: None,
            cluster: None,
            dns: Some(DnsTransportConfig {
                enabled: true,
                addr: Some("10.5.0.53:53".to_string()),
                timeout_ms: None,
            }),
            dot: None,
            doh: None,
            doq: Some(DoqTransportConfig {
                enabled: true,
                addr: Some("10.5.0.53:853".to_string()),
                server_name: Some("dns1.hankin.io".to_string()),
                timeout_ms: None,
            }),
            mcp: McpPermissions::default(),
            validation_endpoints: Vec::new(),
        }
    }

    #[test]
    fn transport_compiled_in_gates_only_doq() {
        assert!(transport_compiled_in(ValidationTransport::Dns));
        assert!(transport_compiled_in(ValidationTransport::Dot));
        assert!(transport_compiled_in(ValidationTransport::Doh));
        assert_eq!(
            transport_compiled_in(ValidationTransport::Doq),
            cfg!(feature = "doq")
        );
    }

    #[test]
    fn all_transports_skips_doq_unless_compiled_in() {
        let server = server_with_dns_and_doq();
        let mut args = QueryArgs::default();
        args.all_transports = true;
        let targets = plan_targets_for_server(&server, &args, Duration::from_millis(1000));
        // DNS is always planned; DoQ only when the feature is enabled.
        assert!(
            targets
                .iter()
                .any(|t| t.transport == ValidationTransport::Dns)
        );
        assert_eq!(
            targets
                .iter()
                .any(|t| t.transport == ValidationTransport::Doq),
            cfg!(feature = "doq")
        );
    }

    #[test]
    fn explicit_doq_is_always_planned() {
        let server = server_with_dns_and_doq();
        let mut args = QueryArgs::default();
        args.doq = true;
        let targets = plan_targets_for_server(&server, &args, Duration::from_millis(1000));
        // An explicit `--doq` is honoured regardless of build, so the
        // UNSUPPORTED status still surfaces when the feature is off.
        assert!(
            targets
                .iter()
                .any(|t| t.transport == ValidationTransport::Doq)
        );
    }

    #[test]
    fn parse_ad_hoc_plain_ip_no_scheme() {
        let p = parse_ad_hoc("1.1.1.1").unwrap();
        assert_eq!(p.transport, None);
        assert_eq!(p.host.as_deref(), Some("1.1.1.1"));
        assert_eq!(p.port, None);
    }

    #[test]
    fn parse_ad_hoc_ip_with_port() {
        let p = parse_ad_hoc("9.9.9.9:53").unwrap();
        assert_eq!(p.host.as_deref(), Some("9.9.9.9"));
        assert_eq!(p.port, Some(53));
    }

    #[test]
    fn parse_ad_hoc_tls_scheme_maps_to_dot() {
        let p = parse_ad_hoc("tls://9.9.9.9").unwrap();
        assert_eq!(p.transport, Some(ValidationTransport::Dot));
        assert_eq!(p.host.as_deref(), Some("9.9.9.9"));
    }

    #[test]
    fn parse_ad_hoc_https_scheme_carries_url() {
        let p = parse_ad_hoc("https://cloudflare-dns.com/dns-query").unwrap();
        assert_eq!(p.transport, Some(ValidationTransport::Doh));
        assert_eq!(
            p.url.as_deref(),
            Some("https://cloudflare-dns.com/dns-query")
        );
    }

    #[test]
    fn parse_ad_hoc_doq_scheme() {
        let p = parse_ad_hoc("doq://dns.adguard.com:853").unwrap();
        assert_eq!(p.transport, Some(ValidationTransport::Doq));
        assert_eq!(p.host.as_deref(), Some("dns.adguard.com"));
        assert_eq!(p.port, Some(853));
    }

    #[test]
    fn parse_ad_hoc_rejects_unknown_scheme() {
        assert!(parse_ad_hoc("ftp://1.1.1.1").is_err());
    }

    #[test]
    fn parse_ad_hoc_ipv6_literal_no_port() {
        let p = parse_ad_hoc("[2001:db8::1]").unwrap();
        assert_eq!(p.host.as_deref(), Some("2001:db8::1"));
        assert_eq!(p.port, None);
    }

    #[test]
    fn parse_ad_hoc_ipv6_literal_with_port() {
        let p = parse_ad_hoc("[2001:db8::1]:53").unwrap();
        assert_eq!(p.host.as_deref(), Some("2001:db8::1"));
        assert_eq!(p.port, Some(53));
    }

    #[test]
    fn clap_parses_query_alias_q() {
        let args = parse(&["huly.hankin.io"]).unwrap();
        assert_eq!(args.targets, vec!["huly.hankin.io".to_string()]);
    }

    #[test]
    fn clap_parses_at_sugar_as_positional() {
        let args = parse(&["huly.hankin.io", "@1.1.1.1"]).unwrap();
        assert_eq!(args.targets.len(), 2);
        assert!(args.targets.contains(&"@1.1.1.1".to_string()));
    }

    #[test]
    fn clap_parses_multiple_transport_flags() {
        let args = parse(&["huly.hankin.io", "--server", "dns1", "--dot", "--doh"]).unwrap();
        assert!(args.dot);
        assert!(args.doh);
        assert!(!args.dns);
        assert!(!args.all);
        assert!(!args.all_transports);
        assert_eq!(args.server, vec!["dns1".to_string()]);
    }

    #[test]
    fn clap_parses_repeated_server() {
        let args = parse(&[
            "huly.hankin.io",
            "--server",
            "dns1",
            "--server",
            "dns2",
        ])
        .unwrap();
        assert_eq!(
            args.server,
            vec!["dns1".to_string(), "dns2".to_string()]
        );
    }

    #[test]
    fn clap_parses_all_flags() {
        let args = parse(&["huly.hankin.io", "--all-servers", "--all-types"]).unwrap();
        assert!(args.all_servers);
        assert!(args.all_types);
        assert!(!args.all_transports);
    }

    #[test]
    fn clap_parses_chase_and_chain_alias() {
        assert!(parse(&["huly.hankin.io", "--chase"]).unwrap().chase);
        assert!(parse(&["huly.hankin.io", "--chain"]).unwrap().chase);
        assert!(!parse(&["huly.hankin.io"]).unwrap().chase);
    }

    #[test]
    fn chain_key_normalises_trailing_dot_and_case() {
        assert_eq!(chain_key("Target.Example."), "target.example");
        assert_eq!(chain_key("target.example"), "target.example");
        assert_eq!(chain_key("HULY.Hankin.IO."), "huly.hankin.io");
    }

    #[test]
    fn is_chain_record_matches_only_cname_and_dname() {
        assert!(is_chain_record("CNAME"));
        assert!(is_chain_record("DNAME"));
        assert!(!is_chain_record("A"));
        assert!(!is_chain_record("AAAA"));
        assert!(!is_chain_record("MX"));
    }

    #[test]
    fn clap_q_alias_works() {
        let cli = Cli::try_parse_from(["dns", "q", "huly.hankin.io"]).unwrap();
        match cli.command {
            Command::Query(q) => assert_eq!(q.targets, vec!["huly.hankin.io".to_string()]),
            _ => panic!("expected Command::Query"),
        }
    }

    #[test]
    fn forced_transport_picks_in_precedence_order() {
        let mut args = QueryArgs::default();
        args.doh = true;
        assert_eq!(
            forced_transport_from_flags(&args),
            Some(ValidationTransport::Doh)
        );
        let mut args = QueryArgs::default();
        args.doq = true;
        assert_eq!(
            forced_transport_from_flags(&args),
            Some(ValidationTransport::Doq)
        );
        let args = QueryArgs::default();
        assert_eq!(forced_transport_from_flags(&args), None);
    }

    #[test]
    fn worst_status_picks_higher_severity() {
        assert_eq!(
            worst(QueryStatus::NoError, QueryStatus::NxDomain),
            QueryStatus::NxDomain
        );
        assert_eq!(
            worst(QueryStatus::NxDomain, QueryStatus::NoError),
            QueryStatus::NxDomain
        );
        assert_eq!(
            worst(QueryStatus::Timeout, QueryStatus::NxDomain),
            QueryStatus::Timeout
        );
    }

    #[test]
    fn exit_code_worst_across_blocks() {
        fn block(status: QueryStatus) -> QueryResultBlock {
            QueryResultBlock {
                target_label: String::new(),
                server_id: None,
                transport: ValidationTransport::Dns,
                extras: Vec::new(),
                url: None,
                host_for_json: None,
                port_for_json: None,
                elapsed: Duration::ZERO,
                status,
                records: Vec::new(),
                asked_types: vec!["A".to_string()],
                queried_name: "example.com".to_string(),
            }
        }
        assert_eq!(exit_code_for(&[block(QueryStatus::NoError)]), 0);
        assert_eq!(
            exit_code_for(&[block(QueryStatus::NoError), block(QueryStatus::NxDomain)]),
            1
        );
        assert_eq!(
            exit_code_for(&[block(QueryStatus::NoError), block(QueryStatus::Timeout)]),
            2
        );
        // Implicit skip doesn't change the exit code
        assert_eq!(
            exit_code_for(&[
                block(QueryStatus::NoError),
                block(QueryStatus::Skipped {
                    reason: "block not configured or disabled".to_string()
                })
            ]),
            0
        );
    }

    #[rstest]
    #[case("A", "192.0.2.10", "192.0.2.10")]
    #[case("AAAA", "2001:db8::10", "2001:db8::10")]
    #[case("CNAME", "target.example.com.", "target.example.com.")]
    #[case("MX", "10 mail.example.com.", "10 mail.example.com.")]
    #[case("TXT", "\"v=spf1 -all\"", "v=spf1 -all")]
    #[case("NS", "ns1.example.com.", "ns1.example.com.")]
    #[case("SRV", "10 20 5060 sip.example.com.", "10 20 5060 sip.example.com.")]
    #[case("CAA", "0 issue \"letsencrypt.org\"", "0 issue \"letsencrypt.org\"")]
    #[case("PTR", "host.example.com.", "host.example.com.")]
    #[case(
        "SOA",
        "ns1.example.com. hostmaster.example.com. 2026052901 3600 900 604800 300",
        "ns1.example.com. hostmaster.example.com. 2026052901 3600 900 604800 300"
    )]
    fn observed_records_preserve_actual_type_name_ttl_and_value(
        #[case] rr_type: &str,
        #[case] rdata_text: &str,
        #[case] expected_value: &str,
    ) {
        let rr_type = rr_type.parse::<RecordType>().unwrap();
        let record = test_record("owner.example.com.", 600, rr_type, rdata_text);

        let observed = observed_records_from_answers(&[record]);

        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].name, "owner.example.com.");
        assert_eq!(observed[0].record_type, rr_type.to_string());
        assert_eq!(observed[0].ttl, Some(600));
        assert_eq!(observed[0].values, vec![expected_value.to_string()]);
    }

    #[test]
    fn observed_records_keep_cname_type_returned_during_aaaa_lookup() {
        let records = vec![
            test_record(
                "alias.example.com.",
                300,
                RecordType::CNAME,
                "target.example.com.",
            ),
            test_record("target.example.com.", 300, RecordType::AAAA, "2001:db8::10"),
        ];

        let observed = observed_records_from_answers(&records);

        assert_eq!(observed[0].name, "alias.example.com.");
        assert_eq!(observed[0].record_type, "CNAME");
        assert_eq!(observed[0].values, vec!["target.example.com.".to_string()]);
        assert_eq!(observed[1].name, "target.example.com.");
        assert_eq!(observed[1].record_type, "AAAA");
        assert_eq!(observed[1].values, vec!["2001:db8::10".to_string()]);
    }

    #[test]
    fn observed_records_keep_cname_type_returned_during_a_lookup() {
        let records = vec![
            test_record(
                "alias.example.com.",
                300,
                RecordType::CNAME,
                "target.example.com.",
            ),
            test_record("target.example.com.", 300, RecordType::A, "192.0.2.10"),
        ];

        let observed = observed_records_from_answers(&records);

        assert_eq!(observed[0].name, "alias.example.com.");
        assert_eq!(observed[0].record_type, "CNAME");
        assert_eq!(observed[0].values, vec!["target.example.com.".to_string()]);
        assert_eq!(observed[1].name, "target.example.com.");
        assert_eq!(observed[1].record_type, "A");
        assert_eq!(observed[1].values, vec!["192.0.2.10".to_string()]);
    }
    #[test]
    fn push_observed_record_once_deduplicates_cname_seen_from_multiple_type_lookups() {
        let mut records = Vec::new();
        let cname = ObservedRecord {
            name: "alias.example.com.".to_string(),
            record_type: "CNAME".to_string(),
            ttl: Some(300),
            values: vec!["target.example.com.".to_string()],
        };

        push_observed_record_once(&mut records, cname.clone());
        push_observed_record_once(&mut records, cname);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_type, "CNAME");
    }

    #[test]
    fn push_observed_record_once_collapses_differing_ttls_keeping_smallest() {
        // The same CNAME comes back from the A-type lookup (cache TTL
        // 3600) and the explicit CNAME-type lookup (counted down to 599).
        // It should collapse to a single row carrying the smaller TTL.
        let mut records = Vec::new();
        let high = ObservedRecord {
            name: "huly.hankin.io.".to_string(),
            record_type: "CNAME".to_string(),
            ttl: Some(3600),
            values: vec!["nasapps.hankin.io.".to_string()],
        };
        let low = ObservedRecord {
            ttl: Some(599),
            ..high.clone()
        };

        push_observed_record_once(&mut records, high);
        push_observed_record_once(&mut records, low);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ttl, Some(599));
    }

    fn test_record(name: &str, ttl: u32, rr_type: RecordType, rdata_text: &str) -> Record {
        Record::from_rdata(
            Name::from_str(name).unwrap(),
            ttl,
            RData::try_from_str(rr_type, rdata_text).unwrap(),
        )
    }
}
