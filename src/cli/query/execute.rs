//! resolver execution, CNAME/DNAME chasing, observed records.

use super::*;

pub(crate) async fn run_block(
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
        server_vendor: plan.server_vendor,
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
            ValidationTransport::Dns | ValidationTransport::Dot | ValidationTransport::Doq => {
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
pub(crate) async fn bootstrap_host(
    host: &str,
    transport: ValidationTransport,
    timeout: Duration,
) -> std::result::Result<String, QueryStatus> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ip.to_string());
    }
    let resolver = build_system_resolver(timeout)?;
    let lookup = resolver
        .lookup_ip(host)
        .await
        .map_err(|e| QueryStatus::from(classify_hickory_error(transport, &e.to_string())))?;
    // Prefer IPv4: many container/CI environments have no IPv6 outbound.
    let ips: Vec<std::net::IpAddr> = lookup.iter().collect();
    ips.iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| ips.first())
        .map(|ip| ip.to_string())
        .ok_or(QueryStatus::NxDomain)
}

/// Resolve the host portion of a DoH URL via the system resolver.
pub(crate) async fn bootstrap_doh_host(
    url: &str,
    timeout: Duration,
) -> std::result::Result<String, QueryStatus> {
    let host = extract_doh_host(url).ok_or(QueryStatus::MalformedResponse)?;
    bootstrap_host(host, ValidationTransport::Doh, timeout).await
}

pub(crate) fn build_system_resolver(
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

pub(crate) async fn lookup_all(
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
pub(crate) async fn chase_chain(
    resolver: &Resolver<TokioRuntimeProvider>,
    records: &mut Vec<ObservedRecord>,
) {
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
pub(crate) fn is_chain_record(record_type: &str) -> bool {
    matches!(record_type, "CNAME" | "DNAME")
}

/// Normalise a name for chain-membership comparison: drop the trailing
/// dot and lowercase, so `Target.Example.` and `target.example` match.
pub(crate) fn chain_key(name: &str) -> String {
    trim_trailing_dot(name).to_ascii_lowercase()
}

pub(crate) fn push_observed_record_once(records: &mut Vec<ObservedRecord>, record: ObservedRecord) {
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

pub(crate) fn observed_records_from_answers(answers: &[Record]) -> Vec<ObservedRecord> {
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
