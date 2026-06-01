//! query entry points and execution orchestration.

use super::*;

/// Entry point for the `dns query` subcommand.
///
/// Returns an exit code (0 on success; non-zero per-status mapping).
/// Output goes to stdout; errors that prevent any query from running
/// (parse-time invariants, unknown `--server`) return `Err`.
#[instrument(
    level = "debug",
    skip_all,
    fields(
        target_count = tracing::field::Empty,
        server_ids = tracing::field::Empty,
        record_types = tracing::field::Empty,
        transports = tracing::field::Empty,
        all_servers = tracing::field::Empty,
        all_types = tracing::field::Empty,
        all_transports = tracing::field::Empty,
        chase = tracing::field::Empty,
        short = tracing::field::Empty,
        json = tracing::field::Empty,
    )
)]
pub async fn run_query(config: Option<AppConfig>, args: QueryArgs) -> Result<i32> {
    let span = Span::current();

    let all_servers = args.all || args.all_servers;
    let all_types = args.all || args.all_types;
    let all_transports = args.all || args.all_transports;

    span.record("target_count", args.targets.len());

    span.record(
        "server_ids",
        tracing::field::display(join_or_default(&args.server, "default")),
    );

    span.record(
        "record_types",
        tracing::field::display(join_or_default(&args.r#type, "default")),
    );

    span.record(
        "transports",
        tracing::field::display(selected_transports(&args)),
    );

    span.record("all_servers", all_servers);
    span.record("all_types", all_types);
    span.record("all_transports", all_transports);

    span.record("chase", args.chase);
    span.record("short", args.short);
    span.record("json", args.json);

    tracing::debug!("sending query");
    tracing::debug!("sending query");

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

pub(crate) fn join_or_default<T>(values: &[T], default: &str) -> String
where
    T: std::fmt::Display,
{
    if values.is_empty() {
        default.to_string()
    } else {
        values
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}
pub(crate) fn selected_transports(args: &QueryArgs) -> String {
    if args.all_transports {
        return "dns,dot,doh,doq".to_string();
    }

    let mut transports = Vec::new();

    if args.dns {
        transports.push("dns");
    }

    if args.dot {
        transports.push("dot");
    }

    if args.doh {
        transports.push("doh");
    }

    if args.doq {
        transports.push("doq");
    }

    if transports.is_empty() {
        "default".to_string()
    } else {
        transports.join(",")
    }
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
