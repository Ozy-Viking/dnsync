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
/// Ownership is *conservative*: the new snapshot is the records this job
/// actually wrote this run (the plans' `adds`) plus any previously-owned
/// records still present in the source. Records that merely happen to exist
/// identically on both sides — which this job never created — are never adopted,
/// so they are never pruned later. Records the ledger holds that are no longer
/// in the source are pruned from the destination (value-match gated) and
/// forgotten.
///
/// When `apply` is false this is a no-op preview: it returns the planned prune
/// count and touches neither the destination nor the ledger.
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

    // The full set of records present in the source this run, keyed for
    // identity comparison. Used to decide what is still "in source".
    let in_source: HashSet<_> = plans
        .iter()
        .flat_map(|p| {
            p.owned
                .iter()
                .map(|r| OwnedRecord::from_planned(&p.zone, r).key())
        })
        .collect();

    // Records this job actually wrote this run — the only records it newly owns.
    let written: Vec<OwnedRecord> = plans
        .iter()
        .flat_map(|p| p.adds.iter().map(|r| OwnedRecord::from_planned(&p.zone, r)))
        .collect();

    // Previously owned records that are no longer in the source are prune
    // candidates; those still in the source remain owned.
    let previous = ownership.ledger.load_owned(job_key)?;
    let (kept, candidates): (Vec<OwnedRecord>, Vec<OwnedRecord>) = previous
        .into_iter()
        .partition(|r| in_source.contains(&r.key()));

    // New ownership snapshot: records written this run + previously-owned
    // records still in source (deduplicated by identity).
    let mut new_owned = written;
    let mut new_keys: HashSet<_> = new_owned.iter().map(OwnedRecord::key).collect();
    for rec in kept {
        if new_keys.insert(rec.key()) {
            new_owned.push(rec);
        }
    }

    debug!(
        job_key,
        owned = new_owned.len(),
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
    ownership.ledger.record_owned(job_key, &new_owned)?;
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
    // Only forget records we actually handled (deleted or confirmed gone/drifted).
    // Records left behind by a failed list/delete stay in the ledger so a later
    // teardown can retry them instead of orphaning them.
    let mut forget: Vec<OwnedRecord> = Vec::new();
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
                        Ok(_) => {
                            summary.pruned += 1;
                            forget.push(rec);
                        }
                        Err(e) => {
                            warn!(%zone, fqdn = %rec.fqdn, error = %e, "teardown delete failed");
                            summary.failures += 1;
                        }
                    }
                }
                None => {
                    summary.skipped_drift += 1;
                    forget.push(rec);
                }
            }
        }
    }

    // Forget only the records we successfully handled; failures stay for retry.
    if !forget.is_empty() {
        ownership.ledger.forget_owned(job_key, &forget)?;
    }
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
