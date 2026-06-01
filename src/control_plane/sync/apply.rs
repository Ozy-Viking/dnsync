//! applying a sync plan and IP remapping.

use super::*;

/// Apply the planned changes to the destination, reporting per-record outcomes.
pub(crate) async fn apply_plans(
    to_client: &VendorClient,
    plans: &[ZonePlan],
) -> Result<SyncApplySummary> {
    apply_plans_with_client(to_client, plans).await
}

#[instrument(
    level = "debug",
    skip(to_client, plans),
    fields(zone_count = plans.len())
)]
pub(crate) async fn apply_plans_with_client<C>(
    to_client: &C,
    plans: &[ZonePlan],
) -> Result<SyncApplySummary>
where
    C: RecordWrite + ?Sized,
{
    let mut applied = 0;
    let mut failures = 0;

    for plan in plans {
        // Add new values before removing stale ones, to minimise the window in
        // which a name resolves to nothing.
        let mut zone_add_failed = false;
        for rec in &plan.adds {
            trace!(zone = %plan.zone, fqdn = %rec.fqdn, rtype = %rec.rtype, "applying add");
            match to_client
                .add_record(&plan.zone, &rec.fqdn, rec.ttl, &rec.record)
                .await
            {
                Ok(_) => applied += 1,
                Err(e) => {
                    debug!(zone = %plan.zone, fqdn = %rec.fqdn, rtype = %rec.rtype, error = %e, "add failed");
                    failures += 1;
                    zone_add_failed = true;
                    eprintln!("  ! add {} {} failed: {e}", rec.fqdn, rec.rtype);
                }
            }
        }
        // Don't run destructive deletes for a zone whose additions failed —
        // we might remove the only working copy of a record.
        if zone_add_failed {
            eprintln!(
                "  ! skipping removals for zone '{}' because one or more additions failed",
                plan.zone
            );
            continue;
        }
        for rec in &plan.deletes {
            trace!(zone = %plan.zone, fqdn = %rec.fqdn, rtype = %rec.rtype, "applying delete");
            let params = rec.record.to_api_params();
            match to_client
                .delete_record(&plan.zone, &rec.fqdn, &params)
                .await
            {
                Ok(_) => applied += 1,
                Err(e) => {
                    debug!(zone = %plan.zone, fqdn = %rec.fqdn, rtype = %rec.rtype, error = %e, "delete failed");
                    failures += 1;
                    eprintln!("  ! remove {} {} failed: {e}", rec.fqdn, rec.rtype);
                }
            }
        }
    }

    debug!(applied, failures, "apply complete");
    if failures > 0 {
        return Err(Error::api(format!("{failures} sync change(s) failed")));
    }
    Ok(SyncApplySummary { applied, failures })
}

/// Rewrite an A/AAAA record's address through the IP map. Other record types
/// and unmapped addresses pass through unchanged.
pub(crate) fn apply_ip_map(record: RecordData, map: &HashMap<IpAddr, IpAddr>) -> RecordData {
    match record {
        RecordData::A { ip } => match map.get(&IpAddr::V4(ip)) {
            Some(IpAddr::V4(mapped)) => RecordData::A { ip: *mapped },
            _ => RecordData::A { ip },
        },
        RecordData::Aaaa { ip } => match map.get(&IpAddr::V6(ip)) {
            Some(IpAddr::V6(mapped)) => RecordData::Aaaa { ip: *mapped },
            _ => RecordData::Aaaa { ip },
        },
        other => other,
    }
}

/// Parse a `SRC=DST` IP-mapping spec. Both sides must be IP addresses of the
/// same family.
pub(crate) fn parse_ip_pair(spec: &str) -> Result<(IpAddr, IpAddr)> {
    let (src, dst) = spec
        .split_once('=')
        .ok_or_else(|| Error::parse(format!("invalid IP mapping '{spec}': expected SRC=DST")))?;
    let src = src.trim();
    let dst = dst.trim();
    let source: IpAddr = src
        .parse()
        .map_err(|_| Error::parse(format!("invalid IP mapping '{spec}': '{src}' is not an IP")))?;
    let dest: IpAddr = dst
        .parse()
        .map_err(|_| Error::parse(format!("invalid IP mapping '{spec}': '{dst}' is not an IP")))?;
    if source.is_ipv4() != dest.is_ipv4() {
        return Err(Error::parse(format!(
            "invalid IP mapping '{spec}': mixes IPv4 and IPv6"
        )));
    }
    Ok((source, dest))
}
