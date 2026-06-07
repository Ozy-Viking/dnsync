//! Ownership reconciliation: pruning records a job created on its destination
//! once they disappear from the source.
//!
//! This is the safe, stateful counterpart to `delete_destination_only` (the
//! blunt mirror mode). Where mirror mode deletes *any* destination record with
//! no source counterpart, ownership pruning deletes only records this job
//! previously created — and only when the live destination value still matches
//! what the job recorded, so out-of-band edits are never clobbered.

use std::collections::{HashMap, HashSet};

use super::*;
use crate::core::dns::service::ListRecordsOptions;
use crate::core::dns::service::{RecordWrite, ZoneRead};
use tracing::warn;

/// Reconcile the ownership ledger against the desired owned set for this run.
///
/// `desired` is the union of every zone plan's owned records. Records the
/// ledger holds for `ownership.job_key` that are absent from `desired` are
/// pruned from the destination (value-match gated) and forgotten; the desired
/// set is then recorded as the new ownership snapshot.
///
/// When `apply` is false this is a no-op preview: it returns a zeroed summary
/// and touches neither the destination nor the ledger. The caller is
/// responsible for surfacing the planned prune to the operator.
pub(crate) async fn reconcile_ownership<C>(
    to_client: &C,
    plans: &[ZonePlan],
    ownership: &Ownership<'_>,
    apply: bool,
) -> Result<PruneSummary>
where
    C: ZoneRead + RecordWrite + ?Sized,
{
    if !ownership.prune {
        return Ok(PruneSummary::default());
    }

    let job_key = ownership.job_key.as_str();

    // Desired owned set for this run, keyed for identity comparison.
    let desired: Vec<OwnedRecord> = plans
        .iter()
        .flat_map(|p| {
            p.owned
                .iter()
                .map(|r| OwnedRecord::from_planned(&p.zone, r))
        })
        .collect();
    let desired_keys: HashSet<_> = desired.iter().map(OwnedRecord::key).collect();

    // Previously owned records that are no longer desired are prune candidates.
    let previous = ownership.ledger.load_owned(job_key)?;
    let candidates: Vec<OwnedRecord> = previous
        .into_iter()
        .filter(|r| !desired_keys.contains(&r.key()))
        .collect();

    debug!(
        job_key,
        desired = desired.len(),
        prune_candidates = candidates.len(),
        apply,
        "reconciling ownership"
    );

    // Dry-run: report intent without touching the destination or the ledger.
    if !apply {
        return Ok(PruneSummary {
            pruned: candidates.len(),
            ..PruneSummary::default()
        });
    }

    let mut summary = PruneSummary::default();
    let mut forget: Vec<OwnedRecord> = Vec::new();

    // Group candidates by zone so we list each destination zone at most once.
    let mut by_zone: HashMap<String, Vec<OwnedRecord>> = HashMap::new();
    for rec in candidates {
        by_zone.entry(rec.zone.clone()).or_default().push(rec);
    }

    for (zone, recs) in by_zone {
        // Re-read the destination so drift is detected against the live state.
        let live = match list_destination(to_client, &zone).await {
            Ok(live) => live,
            Err(e) => {
                warn!(%zone, error = %e, "prune: could not list destination zone; skipping");
                summary.failures += recs.len();
                continue;
            }
        };

        for rec in recs {
            let live_key = (
                rec.fqdn.to_lowercase(),
                rec.rtype.clone(),
                rec.value.clone(),
            );
            match live.get(&live_key) {
                // Value still matches what we recorded — safe to delete.
                Some(record) => {
                    let params = record.to_api_params();
                    match to_client.delete_record(&zone, &rec.fqdn, &params).await {
                        Ok(_) => {
                            debug!(%zone, fqdn = %rec.fqdn, rtype = %rec.rtype, "pruned owned record");
                            summary.pruned += 1;
                            forget.push(rec);
                        }
                        Err(e) => {
                            warn!(%zone, fqdn = %rec.fqdn, rtype = %rec.rtype, error = %e, "prune delete failed");
                            summary.failures += 1;
                        }
                    }
                }
                // Either gone already, or changed out-of-band. Don't clobber a
                // drifted value; relinquish tracking either way.
                None => {
                    warn!(
                        %zone, fqdn = %rec.fqdn, rtype = %rec.rtype,
                        "prune: live value drifted or already removed; leaving destination untouched"
                    );
                    summary.skipped_drift += 1;
                    forget.push(rec);
                }
            }
        }
    }

    // Record the new ownership snapshot and forget what we pruned/relinquished.
    ownership.ledger.record_owned(job_key, &desired)?;
    if !forget.is_empty() {
        ownership.ledger.forget_owned(job_key, &forget)?;
    }

    debug!(
        job_key,
        pruned = summary.pruned,
        skipped_drift = summary.skipped_drift,
        failures = summary.failures,
        "ownership reconciliation complete"
    );
    Ok(summary)
}

/// Tear down everything a job owns: remove every record the job created on its
/// destination and clear its ledger entries.
///
/// Like pruning, deletes are value-match gated — a record whose live value has
/// drifted from what the job recorded is left in place. When `apply` is false
/// this previews the count without touching the destination or the ledger.
pub(crate) async fn teardown_ownership<C>(
    to_client: &C,
    ownership: &Ownership<'_>,
    apply: bool,
) -> Result<PruneSummary>
where
    C: ZoneRead + RecordWrite + ?Sized,
{
    let job_key = ownership.job_key.as_str();
    let owned = ownership.ledger.load_owned(job_key)?;
    debug!(
        job_key,
        owned = owned.len(),
        apply,
        "tearing down ownership"
    );

    if !apply {
        return Ok(PruneSummary {
            pruned: owned.len(),
            ..PruneSummary::default()
        });
    }

    let mut summary = PruneSummary::default();
    let mut by_zone: HashMap<String, Vec<OwnedRecord>> = HashMap::new();
    for rec in owned {
        by_zone.entry(rec.zone.clone()).or_default().push(rec);
    }

    for (zone, recs) in by_zone {
        let live = match list_destination(to_client, &zone).await {
            Ok(live) => live,
            Err(e) => {
                warn!(%zone, error = %e, "teardown: could not list destination zone; skipping");
                summary.failures += recs.len();
                continue;
            }
        };
        for rec in recs {
            let live_key = (
                rec.fqdn.to_lowercase(),
                rec.rtype.clone(),
                rec.value.clone(),
            );
            match live.get(&live_key) {
                Some(record) => {
                    let params = record.to_api_params();
                    match to_client.delete_record(&zone, &rec.fqdn, &params).await {
                        Ok(_) => summary.pruned += 1,
                        Err(e) => {
                            warn!(%zone, fqdn = %rec.fqdn, error = %e, "teardown delete failed");
                            summary.failures += 1;
                        }
                    }
                }
                None => summary.skipped_drift += 1,
            }
        }
    }

    // Clear the ledger regardless of drift skips — the job no longer owns these.
    ownership.ledger.forget_all(job_key)?;
    debug!(
        job_key,
        pruned = summary.pruned,
        skipped_drift = summary.skipped_drift,
        failures = summary.failures,
        "ownership teardown complete"
    );
    Ok(summary)
}

/// List a destination zone and index its writable records by
/// `(fqdn_lowercased, rtype, canonical_value)` so an owned record's identity
/// can be matched against the live state.
async fn list_destination<C>(
    to_client: &C,
    zone: &str,
) -> Result<HashMap<(String, String, String), RecordData>>
where
    C: ZoneRead + ?Sized,
{
    let list_opts = ListRecordsOptions {
        all_subdomains: true,
        ..ListRecordsOptions::default()
    };
    let dest = to_client
        .list_records(zone, Some(zone), list_opts)
        .await
        .map_err(|e| Error::api(format!("prune: listing destination zone '{zone}': {e}")))?;

    let (records, _) = collect_records(&dest, zone, None);
    let mut index = HashMap::new();
    for rec in records {
        index.insert(
            (
                rec.fqdn.to_lowercase(),
                rec.rtype.clone(),
                canonical(&rec.record),
            ),
            rec.record,
        );
    }
    Ok(index)
}
