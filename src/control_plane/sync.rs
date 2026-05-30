//! Record-level sync between two configured DNS servers.
//!
//! `dns sync` reads records from a source server, optionally rewrites IP
//! addresses on A/AAAA records (e.g. external → internal), and writes the
//! difference to a destination server. It is vendor-neutral: it goes through
//! the shared `core::dns` traits, so any pair of supported vendors can sync.
//!
//! Sync is **additive** — it adds records the destination is missing and
//! updates record sets whose values differ, but never prunes whole names that
//! exist only on the destination. It is **dry-run by default**; `--apply`
//! commits the changes.

use std::collections::HashMap;
use std::net::IpAddr;

use tracing::{debug, instrument, trace};

use crate::control_plane::config::AppConfig;
use regex::Regex;
use crate::core::dns::records::RecordData;
use crate::core::dns::records::query::{extract_zone_names, resolve_fqdn};
use crate::core::dns::responses::{AnyRecordData, ListRecordsResponse};
use crate::core::dns::service::{ListRecordsOptions, RecordWrite, ZoneRead};
use crate::core::error::{Error, Result};
use crate::vendors::runtime::VendorClient;

/// Controls which categories of diff are applied during a record sync.
#[derive(Debug, Clone)]
pub struct SyncDiffOptions {
    /// Add records present in source but absent from destination (new name+type combos).
    pub create_missing: bool,
    /// Update records where name+type matches but value differs (source wins).
    pub overwrite_existing: bool,
    /// Delete destination records whose name+type has no counterpart in source.
    pub delete_destination_only: bool,
    /// FQDN patterns — source records matching any pattern are excluded before diffing.
    pub ignore: Vec<Regex>,
}

impl Default for SyncDiffOptions {
    fn default() -> Self {
        Self {
            create_missing: true,
            overwrite_existing: true,
            delete_destination_only: false,
            ignore: Vec::new(),
        }
    }
}

/// TTL used when a source record reports a TTL of 0 (some vendors do not
/// expose per-record TTLs).
const DEFAULT_TTL: u32 = 3600;

/// One record to be written to (or removed from) the destination.
#[derive(Debug, Clone)]
struct PlannedRecord {
    /// Fully-qualified record name.
    fqdn: String,
    /// Uppercase record type, e.g. `A`.
    rtype: String,
    ttl: u32,
    record: RecordData,
}

/// The computed difference for one zone.
#[derive(Debug, Default)]
struct Diff {
    /// Source records for name+type combos that don't exist in destination at all.
    missing_adds: Vec<PlannedRecord>,
    /// Source records for name+type combos that exist in destination but with a different value.
    update_adds: Vec<PlannedRecord>,
    /// Destination records being replaced by update_adds (stale values for the same name+type).
    update_deletes: Vec<PlannedRecord>,
    /// Destination records for name+type combos with no counterpart in source.
    destination_only: Vec<PlannedRecord>,
    /// Records identical in source and destination (same value + TTL).
    unchanged: usize,
}

/// The plan for one zone, ready to display or apply.
#[derive(Debug)]
struct ZonePlan {
    zone: String,
    adds: Vec<PlannedRecord>,
    deletes: Vec<PlannedRecord>,
    unchanged: usize,
    untouched: usize,
    /// Source records that cannot be synced (SOA, DNSSEC, disabled, unknown).
    skipped: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncApplySummary {
    pub applied: usize,
    pub failures: usize,
}

/// Run a record sync.
///
/// `profile` selects a named `[[sync]]` profile from the config; `from`, `to`,
/// `zones` and `maps` are CLI overrides that take precedence over the profile.
///
/// # Errors
///
/// Returns an error if the config, servers, zones, or IP mappings cannot be
/// resolved, or — when `apply` is set — if any record write fails.
#[allow(clippy::too_many_arguments)]
#[instrument(
    level = "debug",
    skip(app_config, zones, maps),
    fields(profile = ?profile, from = ?from, to = ?to, zone_count = zones.len(), apply, json)
)]
pub async fn run_sync(
    app_config: Option<&AppConfig>,
    profile: Option<&str>,
    from: Option<&str>,
    to: Option<&str>,
    zones: &[String],
    maps: &[String],
    apply: bool,
    json: bool,
) -> Result<()> {
    debug!("building sync plan");
    let (from_id, to_id, plans) =
        build_sync_plan(app_config, profile, from, to, zones, maps).await?;
    debug!(from = %from_id, to = %to_id, plan_count = plans.len(), "sync plan built");

    if json {
        let out = sync_plan_json(&from_id, &to_id, &plans, apply);
        let pretty = serde_json::to_string_pretty(&out)
            .map_err(|e| Error::parse(format!("could not serialise sync plan: {e}")))?;
        println!("{pretty}");
    } else {
        render_table(&from_id, &to_id, &plans, apply);
    }

    let has_changes = plans
        .iter()
        .any(|p| !p.adds.is_empty() || !p.deletes.is_empty());
    if !apply || !has_changes {
        return Ok(());
    }

    let summary = apply_plans(
        &VendorClient::from_server(
            app_config
                .and_then(|cfg| cfg.selected_server(Some(&to_id)).ok())
                .ok_or_else(|| Error::config("sync destination server disappeared"))?,
        )?,
        &plans,
    )
    .await?;
    println!("\nApplied {} change(s).", summary.applied);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[instrument(
    level = "debug",
    skip(app_config, zones, maps),
    fields(profile = ?profile, from = ?from, to = ?to, zone_count = zones.len(), apply)
)]
pub async fn run_sync_json(
    app_config: Option<&AppConfig>,
    profile: Option<&str>,
    from: Option<&str>,
    to: Option<&str>,
    zones: &[String],
    maps: &[String],
    apply: bool,
) -> Result<serde_json::Value> {
    let (from_id, to_id, plans) =
        build_sync_plan(app_config, profile, from, to, zones, maps).await?;
    let mut out = sync_plan_json(&from_id, &to_id, &plans, apply);

    let has_changes = plans
        .iter()
        .any(|p| !p.adds.is_empty() || !p.deletes.is_empty());
    if apply && has_changes {
        let cfg = app_config.expect("build_sync_plan already required config");
        let to_server = cfg.selected_server(Some(&to_id))?;
        let summary = apply_plans(&VendorClient::from_server(to_server)?, &plans).await?;
        out["apply_summary"] = serde_json::to_value(summary)
            .map_err(|e| Error::parse(format!("could not serialise sync summary: {e}")))?;
    }

    Ok(out)
}

#[allow(clippy::too_many_arguments)]
#[instrument(
    level = "debug",
    skip(app_config, zones, maps),
    fields(profile = ?profile, from = ?from, to = ?to)
)]
async fn build_sync_plan(
    app_config: Option<&AppConfig>,
    profile: Option<&str>,
    from: Option<&str>,
    to: Option<&str>,
    zones: &[String],
    maps: &[String],
) -> Result<(String, String, Vec<ZonePlan>)> {
    let Some(cfg) = app_config else {
        return Err(Error::config(
            "sync requires a config file defining the source and destination servers",
        ));
    };

    // Named sync profiles have been superseded by `[[jobs]]` in Phase 1.
    // Profile-based sync will be re-wired in a later phase.
    if profile.is_some() {
        return Err(Error::config(
            "named sync profiles are no longer supported; use [[jobs]] in the config file instead",
        ));
    }

    // From/to: CLI flags are required when no profile is given.
    let from_id = from.ok_or_else(|| {
        Error::parse("sync requires a source server: pass --from")
    })?;
    let to_id = to.ok_or_else(|| {
        Error::parse("sync requires a destination server: pass --to")
    })?;

    // IP map: CLI --map flags.
    let mut ip_map: HashMap<IpAddr, IpAddr> = HashMap::new();
    for spec in maps {
        let (s, d) = parse_ip_pair(spec)?;
        ip_map.insert(s, d);
    }

    debug!(from_id, to_id, "resolved sync endpoints");

    let from_server = cfg.selected_server(Some(from_id))?;
    let to_server = cfg.selected_server(Some(to_id))?;
    let from_client = VendorClient::from_server(from_server)?;
    let to_client = VendorClient::from_server(to_server)?;

    // Zones: CLI wins, then every zone on the source.
    let zone_list: Vec<String> = if !zones.is_empty() {
        zones.to_vec()
    } else {
        const PAGE_SIZE: u32 = 1000;
        let mut page = 1;
        let mut names = Vec::new();
        loop {
            let value = from_client.list_zones(page, PAGE_SIZE).await?;
            let batch = extract_zone_names(&value);
            let batch_len = batch.len();
            names.extend(batch);
            if batch_len < PAGE_SIZE as usize {
                break;
            }
            page += 1;
        }
        if names.is_empty() {
            return Err(Error::parse(format!(
                "no zones found on source server '{from_id}'; specify one with --zone"
            )));
        }
        names
    };

    debug!(zone_count = zone_list.len(), "resolved zone list");

    let sync_opts = SyncDiffOptions::default();
    let mut plans = Vec::with_capacity(zone_list.len());
    for zone in &zone_list {
        plans.push(plan_zone(&from_client, &to_client, zone, &ip_map, &sync_opts).await?);
    }

    Ok((from_id.to_string(), to_id.to_string(), plans))
}

/// Build the sync plan for a single zone.
#[instrument(level = "trace", skip(from_client, to_client, ip_map), fields(zone))]
async fn plan_zone(
    from_client: &VendorClient,
    to_client: &VendorClient,
    zone: &str,
    ip_map: &HashMap<IpAddr, IpAddr>,
    sync_opts: &SyncDiffOptions,
) -> Result<ZonePlan> {
    plan_zone_with_clients(from_client, to_client, zone, ip_map, sync_opts).await
}

#[instrument(
    level = "trace",
    skip(from_client, to_client, ip_map),
    fields(zone)
)]
async fn plan_zone_with_clients<F, T>(
    from_client: &F,
    to_client: &T,
    zone: &str,
    ip_map: &HashMap<IpAddr, IpAddr>,
    sync_opts: &SyncDiffOptions,
) -> Result<ZonePlan>
where
    F: ZoneRead + ?Sized,
    T: ZoneRead + ?Sized,
{
    let list_opts = ListRecordsOptions {
        all_subdomains: true,
        ..ListRecordsOptions::default()
    };

    let source = from_client
        .list_records(zone, Some(zone), list_opts)
        .await
        .map_err(|e| Error::parse(format!("source: listing records for zone '{zone}': {e}")))?;
    let dest = to_client
        .list_records(zone, Some(zone), list_opts)
        .await
        .map_err(|e| {
            Error::parse(format!(
                "destination: listing records for zone '{zone}' \
                 (does the zone exist on the destination?): {e}"
            ))
        })?;

    let (mut source_records, skipped) = collect_records(&source, zone, Some(ip_map));
    trace!(source_count = source_records.len(), skipped, "source records collected");
    let (dest_records, _) = collect_records(&dest, zone, None);

    // Filter out source records whose FQDN matches any ignore pattern.
    if !sync_opts.ignore.is_empty() {
        source_records.retain(|r| {
            !sync_opts.ignore.iter().any(|pat| pat.is_match(&r.fqdn))
        });
    }

    let diff = diff_records(source_records, dest_records);
    trace!(
        missing_adds = diff.missing_adds.len(),
        update_adds = diff.update_adds.len(),
        destination_only = diff.destination_only.len(),
        unchanged = diff.unchanged,
        "diff computed"
    );

    let mut adds: Vec<PlannedRecord> = Vec::new();
    let mut deletes: Vec<PlannedRecord> = Vec::new();

    if sync_opts.create_missing {
        adds.extend(diff.missing_adds);
    }
    if sync_opts.overwrite_existing {
        adds.extend(diff.update_adds);
        deletes.extend(diff.update_deletes);
    }
    if sync_opts.delete_destination_only {
        deletes.extend(diff.destination_only.iter().cloned());
    }

    let untouched = if sync_opts.delete_destination_only {
        0
    } else {
        diff.destination_only.len()
    };

    adds.sort_by_key(sort_key);
    deletes.sort_by_key(sort_key);

    Ok(ZonePlan {
        zone: zone.to_string(),
        adds,
        deletes,
        unchanged: diff.unchanged,
        untouched,
        skipped,
    })
}

/// Turn a vendor record-list response into syncable [`PlannedRecord`]s,
/// applying `ip_map` when one is supplied. Returns the records plus the count
/// of records skipped because they are disabled or not syncable.
fn collect_records(
    response: &ListRecordsResponse,
    zone: &str,
    ip_map: Option<&HashMap<IpAddr, IpAddr>>,
) -> (Vec<PlannedRecord>, usize) {
    let mut out = Vec::new();
    let mut skipped = 0;

    for zone_records in &response.zones {
        for record in &zone_records.records {
            if record.disabled {
                skipped += 1;
                continue;
            }
            // Server-managed records (SOA, DNSSEC) and unknown types cannot be
            // written through the record API.
            let Some(AnyRecordData::Writable(rd)) = record.typed() else {
                skipped += 1;
                continue;
            };
            let rd = match ip_map {
                Some(map) => apply_ip_map(rd, map),
                None => rd,
            };
            let fqdn = resolve_fqdn(&record.name, Some(zone));
            if fqdn.eq_ignore_ascii_case(zone) && rd.type_name() == "NS" {
                skipped += 1;
                continue;
            }
            out.push(PlannedRecord {
                fqdn,
                rtype: rd.type_name().to_string(),
                ttl: if record.ttl == 0 {
                    DEFAULT_TTL
                } else {
                    record.ttl
                },
                record: rd,
            });
        }
    }

    (out, skipped)
}

/// Compute the difference between source and destination records.
///
/// Records are grouped into sets by `(name, type)`. A set missing on the
/// destination goes to `missing_adds`; a set present on both with differing
/// values contributes to `update_adds` / `update_deletes`. Sets that exist
/// only on the destination go to `destination_only`.
fn diff_records(source: Vec<PlannedRecord>, dest: Vec<PlannedRecord>) -> Diff {
    let group = |records: Vec<PlannedRecord>| {
        let mut groups: HashMap<(String, String), Vec<PlannedRecord>> = HashMap::new();
        for r in records {
            groups
                .entry((r.fqdn.to_lowercase(), r.rtype.clone()))
                .or_default()
                .push(r);
        }
        groups
    };

    let source_groups = group(source);
    let dest_groups = group(dest);

    let mut diff = Diff::default();

    // A record is "unchanged" only when its value AND TTL match the destination;
    // otherwise it is added (and the stale destination value, if any, deleted)
    // so source TTLs propagate.
    let match_key = |r: &PlannedRecord| (canonical(&r.record), r.ttl);

    for (key, src_recs) in &source_groups {
        let dest_recs = dest_groups.get(key);
        let is_new = dest_recs.is_none();
        let dest_keys: Vec<(String, u32)> = dest_recs
            .map(|recs| recs.iter().map(match_key).collect())
            .unwrap_or_default();
        let src_keys: Vec<(String, u32)> = src_recs.iter().map(match_key).collect();

        for r in src_recs {
            if dest_keys.contains(&match_key(r)) {
                diff.unchanged += 1;
            } else if is_new {
                diff.missing_adds.push(r.clone());
            } else {
                diff.update_adds.push(r.clone());
            }
        }
        if let Some(dest_recs) = dest_recs {
            for r in dest_recs {
                if !src_keys.contains(&match_key(r)) {
                    diff.update_deletes.push(r.clone());
                }
            }
        }
    }

    for (key, recs) in &dest_groups {
        if !source_groups.contains_key(key) {
            diff.destination_only.extend(recs.iter().cloned());
        }
    }

    diff
}

/// Apply the planned changes to the destination, reporting per-record outcomes.
async fn apply_plans(to_client: &VendorClient, plans: &[ZonePlan]) -> Result<SyncApplySummary> {
    apply_plans_with_client(to_client, plans).await
}

#[instrument(
    level = "debug",
    skip(to_client, plans),
    fields(zone_count = plans.len())
)]
async fn apply_plans_with_client<C>(to_client: &C, plans: &[ZonePlan]) -> Result<SyncApplySummary>
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
fn apply_ip_map(record: RecordData, map: &HashMap<IpAddr, IpAddr>) -> RecordData {
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
fn parse_ip_pair(spec: &str) -> Result<(IpAddr, IpAddr)> {
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

/// A canonical string for a record's data, used to compare record values.
fn canonical(record: &RecordData) -> String {
    record
        .to_api_params()
        .into_iter()
        .map(|(key, value)| format!("{key}\u{1}{value}"))
        .collect::<Vec<_>>()
        .join("\u{2}")
}

/// A stable sort key so plan output is deterministic.
fn sort_key(record: &PlannedRecord) -> (String, String, String) {
    (
        record.fqdn.to_lowercase(),
        record.rtype.clone(),
        canonical(&record.record),
    )
}

/// A compact, human-readable rendering of a record's value.
fn value_display(record: &RecordData) -> String {
    record
        .to_api_params()
        .into_iter()
        .skip(1) // drop the leading ("type", ...) param
        .map(|(_, value)| value)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Print the sync plan as an aligned table.
fn render_table(from_id: &str, to_id: &str, plans: &[ZonePlan], apply: bool) {
    let mode = if apply { "apply" } else { "dry run" };
    println!("Sync plan: {from_id} -> {to_id}  ({mode})");

    let mut adds = 0;
    let mut deletes = 0;
    let mut unchanged = 0;
    let mut skipped = 0;
    let mut untouched = 0;

    for plan in plans {
        adds += plan.adds.len();
        deletes += plan.deletes.len();
        unchanged += plan.unchanged;
        skipped += plan.skipped;
        untouched += plan.untouched;

        if plan.adds.is_empty() && plan.deletes.is_empty() {
            continue;
        }
        println!("\nZone: {}", plan.zone);
        for rec in &plan.adds {
            println!(
                "  + {:<28} {:<6} {}",
                rec.fqdn,
                rec.rtype,
                value_display(&rec.record)
            );
        }
        for rec in &plan.deletes {
            println!(
                "  - {:<28} {:<6} {}",
                rec.fqdn,
                rec.rtype,
                value_display(&rec.record)
            );
        }
    }

    println!(
        "\n{adds} to add, {deletes} to remove, {unchanged} unchanged, \
         {skipped} skipped (not syncable)."
    );
    if untouched > 0 {
        println!("{untouched} destination record(s) absent from the source were left untouched.");
    }
    if adds + deletes == 0 {
        println!("Already in sync — nothing to do.");
    } else if !apply {
        println!("Dry run — no changes written. Re-run with --apply to commit.");
    }
}

/// Print the sync plan as JSON.
fn sync_plan_json(
    from_id: &str,
    to_id: &str,
    plans: &[ZonePlan],
    apply: bool,
) -> serde_json::Value {
    let rec_json = |rec: &PlannedRecord| {
        serde_json::json!({
            "name": rec.fqdn,
            "type": rec.rtype,
            "ttl": rec.ttl,
            "value": value_display(&rec.record),
        })
    };

    let zones: Vec<_> = plans
        .iter()
        .map(|plan| {
            serde_json::json!({
                "zone": plan.zone,
                "add": plan.adds.iter().map(rec_json).collect::<Vec<_>>(),
                "remove": plan.deletes.iter().map(rec_json).collect::<Vec<_>>(),
                "unchanged": plan.unchanged,
                "untouched": plan.untouched,
                "skipped": plan.skipped,
            })
        })
        .collect();

    serde_json::json!({
        "from": from_id,
        "to": to_id,
        "applied": apply,
        "zones": zones,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::dns::responses::{ZoneInfo, ZoneRecord, ZoneRecords};
    use rstest::rstest;
    use serde_json::{Value, json};
    use std::sync::{Arc, Mutex};

    fn ip_map(pairs: &[(&str, &str)]) -> HashMap<IpAddr, IpAddr> {
        pairs
            .iter()
            .map(|(s, d)| (s.parse().unwrap(), d.parse().unwrap()))
            .collect()
    }

    fn a(name: &str, ip: &str) -> PlannedRecord {
        PlannedRecord {
            fqdn: name.to_string(),
            rtype: "A".to_string(),
            ttl: 3600,
            record: RecordData::A {
                ip: ip.parse().unwrap(),
            },
        }
    }

    fn zone_info(name: &str) -> ZoneInfo {
        ZoneInfo {
            id: Some(name.to_string()),
            name: name.to_string(),
            zone_type: "Primary".to_string(),
            disabled: false,
            dnssec_status: None,
        }
    }

    fn zone_record(name: &str, record_type: &str, ttl: u32, data: Value) -> ZoneRecord {
        let mut record = ZoneRecord {
            name: name.to_string(),
            record_type: record_type.to_string(),
            ttl,
            disabled: false,
            comments: String::new(),
            expiry_ttl: 0,
            data,
            parsed: None,
        };
        record.parsed = record.typed();
        record
    }

    fn sync_test_response(zone: &str, records: Vec<ZoneRecord>) -> ListRecordsResponse {
        ListRecordsResponse {
            zones: vec![ZoneRecords {
                zone: zone_info(zone),
                records,
            }],
        }
    }

    #[derive(Clone)]
    struct FakeZoneRead {
        response: ListRecordsResponse,
        calls: Arc<Mutex<Vec<(String, Option<String>, ListRecordsOptions)>>>,
    }

    impl FakeZoneRead {
        fn new(response: ListRecordsResponse) -> Self {
            Self {
                response,
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl ZoneRead for FakeZoneRead {
        async fn list_zones(&self, _page: u32, _per_page: u32) -> Result<Value> {
            Ok(json!({ "response": { "zones": [] } }))
        }

        async fn list_records(
            &self,
            domain: &str,
            zone: Option<&str>,
            options: ListRecordsOptions,
        ) -> Result<ListRecordsResponse> {
            self.calls.lock().unwrap().push((
                domain.to_string(),
                zone.map(ToOwned::to_owned),
                options,
            ));
            Ok(self.response.clone())
        }
    }

    #[derive(Default)]
    struct FakeRecordWrite {
        adds: Mutex<Vec<(String, String, u32, RecordData)>>,
        deletes: Mutex<Vec<(String, String, Vec<(String, String)>)>>,
    }

    impl RecordWrite for FakeRecordWrite {
        async fn add_record(
            &self,
            zone: &str,
            domain: &str,
            ttl: u32,
            record: &RecordData,
        ) -> Result<Value> {
            self.adds.lock().unwrap().push((
                zone.to_string(),
                domain.to_string(),
                ttl,
                record.clone(),
            ));
            Ok(json!({ "status": "ok" }))
        }

        async fn delete_record(
            &self,
            zone: &str,
            domain: &str,
            type_params: &[(&str, String)],
        ) -> Result<Value> {
            self.deletes.lock().unwrap().push((
                zone.to_string(),
                domain.to_string(),
                type_params
                    .iter()
                    .map(|(key, value)| ((*key).to_string(), value.clone()))
                    .collect(),
            ));
            Ok(json!({ "status": "ok" }))
        }
    }

    // ── apply_ip_map ──────────────────────────────────────────────────────────

    #[test]
    fn ip_map_rewrites_mapped_a_record() {
        let map = ip_map(&[("203.0.113.10", "192.168.1.10")]);
        let mapped = apply_ip_map(
            RecordData::A {
                ip: "203.0.113.10".parse().unwrap(),
            },
            &map,
        );
        match mapped {
            RecordData::A { ip } => assert_eq!(ip.to_string(), "192.168.1.10"),
            other => panic!("expected A, got {other:?}"),
        }
    }

    #[test]
    fn ip_map_leaves_unmapped_a_record_untouched() {
        let map = ip_map(&[("203.0.113.10", "192.168.1.10")]);
        let mapped = apply_ip_map(
            RecordData::A {
                ip: "8.8.8.8".parse().unwrap(),
            },
            &map,
        );
        match mapped {
            RecordData::A { ip } => assert_eq!(ip.to_string(), "8.8.8.8"),
            other => panic!("expected A, got {other:?}"),
        }
    }

    #[test]
    fn ip_map_rewrites_mapped_aaaa_record() {
        let map = ip_map(&[("2001:db8::1", "fd00::1")]);
        let mapped = apply_ip_map(
            RecordData::Aaaa {
                ip: "2001:db8::1".parse().unwrap(),
            },
            &map,
        );
        match mapped {
            RecordData::Aaaa { ip } => assert_eq!(ip.to_string(), "fd00::1"),
            other => panic!("expected AAAA, got {other:?}"),
        }
    }

    #[test]
    fn ip_map_leaves_non_address_records_untouched() {
        let map = ip_map(&[("203.0.113.10", "192.168.1.10")]);
        let mapped = apply_ip_map(
            RecordData::Cname {
                target: "example.com".to_string(),
            },
            &map,
        );
        assert!(matches!(mapped, RecordData::Cname { .. }));
    }

    // ── plan/apply ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn plan_zone_lists_entire_zone_and_includes_child_records() {
        let zone = "dnsync-sync-test.example";
        let source = FakeZoneRead::new(sync_test_response(
            zone,
            vec![
                zone_record(zone, "SOA", 3600, json!({})),
                zone_record(zone, "NS", 3600, json!({ "nameServer": "dns1.hankin.io" })),
                zone_record(
                    &format!("www.{zone}"),
                    "A",
                    3600,
                    json!({ "ipAddress": "203.0.113.10" }),
                ),
                zone_record(
                    &format!("api.{zone}"),
                    "CNAME",
                    3600,
                    json!({ "cname": format!("www.{zone}") }),
                ),
            ],
        ));
        let dest = FakeZoneRead::new(sync_test_response(
            zone,
            vec![
                zone_record(zone, "SOA", 3600, json!({})),
                zone_record(zone, "NS", 3600, json!({ "nameServer": "dns2.hankin.io" })),
            ],
        ));

        let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &SyncDiffOptions::default())
            .await
            .unwrap();

        assert!(source.calls.lock().unwrap()[0].2.all_subdomains);
        assert!(dest.calls.lock().unwrap()[0].2.all_subdomains);
        assert_eq!(plan.adds.len(), 2);
        assert!(plan.adds.iter().any(|r| {
            r.fqdn == format!("www.{zone}")
                && r.rtype == "A"
                && value_display(&r.record) == "203.0.113.10"
        }));
        assert!(plan.adds.iter().any(|r| {
            r.fqdn == format!("api.{zone}")
                && r.rtype == "CNAME"
                && value_display(&r.record) == format!("www.{zone}")
        }));
        assert_eq!(plan.skipped, 2);
    }

    #[tokio::test]
    async fn apply_writes_missing_child_records_to_destination() {
        let zone = "dnsync-sync-test.example";
        let writer = FakeRecordWrite::default();
        let plan = ZonePlan {
            zone: zone.to_string(),
            adds: vec![
                PlannedRecord {
                    fqdn: format!("www.{zone}"),
                    rtype: "A".to_string(),
                    ttl: 3600,
                    record: RecordData::A {
                        ip: "203.0.113.10".parse().unwrap(),
                    },
                },
                PlannedRecord {
                    fqdn: format!("api.{zone}"),
                    rtype: "CNAME".to_string(),
                    ttl: 3600,
                    record: RecordData::Cname {
                        target: format!("www.{zone}"),
                    },
                },
            ],
            deletes: vec![],
            unchanged: 0,
            untouched: 0,
            skipped: 0,
        };

        apply_plans_with_client(&writer, &[plan]).await.unwrap();

        let adds = writer.adds.lock().unwrap();
        assert_eq!(adds.len(), 2);
        assert_eq!(adds[0].0, zone);
        assert_eq!(adds[0].1, format!("www.{zone}"));
        assert!(matches!(adds[0].3, RecordData::A { .. }));
        assert_eq!(adds[1].1, format!("api.{zone}"));
        assert!(matches!(adds[1].3, RecordData::Cname { .. }));
    }

    #[tokio::test]
    async fn plan_zone_applies_ip_mapping_to_child_address_records() {
        let zone = "dnsync-sync-test.example";
        let source = FakeZoneRead::new(sync_test_response(
            zone,
            vec![zone_record(
                &format!("www.{zone}"),
                "A",
                3600,
                json!({ "ipAddress": "203.0.113.10" }),
            )],
        ));
        let dest = FakeZoneRead::new(sync_test_response(zone, vec![]));
        let map = ip_map(&[("203.0.113.10", "192.0.2.10")]);

        let plan = plan_zone_with_clients(&source, &dest, zone, &map, &SyncDiffOptions::default())
            .await
            .unwrap();

        assert_eq!(plan.adds.len(), 1);
        assert_eq!(value_display(&plan.adds[0].record), "192.0.2.10");
    }

    // ── parse_ip_pair ─────────────────────────────────────────────────────────

    #[test]
    fn parse_ip_pair_accepts_valid_pair() {
        let (s, d) = parse_ip_pair("203.0.113.10 = 192.168.1.10").unwrap();
        assert_eq!(s.to_string(), "203.0.113.10");
        assert_eq!(d.to_string(), "192.168.1.10");
    }

    #[rstest]
    #[case::missing_separator("203.0.113.10")]
    #[case::bad_address("203.0.113.10=not-an-ip")]
    #[case::family_mismatch("203.0.113.10=fd00::1")]
    fn parse_ip_pair_rejects_bad_input(#[case] spec: &str) {
        assert!(parse_ip_pair(spec).is_err());
    }

    // ── canonical ─────────────────────────────────────────────────────────────

    #[test]
    fn canonical_equal_for_same_value_differs_for_others() {
        let one = RecordData::A {
            ip: "1.2.3.4".parse().unwrap(),
        };
        let same = RecordData::A {
            ip: "1.2.3.4".parse().unwrap(),
        };
        let other = RecordData::A {
            ip: "1.2.3.5".parse().unwrap(),
        };
        assert_eq!(canonical(&one), canonical(&same));
        assert_ne!(canonical(&one), canonical(&other));
    }

    // ── diff_records ──────────────────────────────────────────────────────────

    #[test]
    fn diff_adds_record_set_missing_on_destination() {
        let diff = diff_records(vec![a("www.example.com", "1.1.1.1")], vec![]);
        assert_eq!(diff.missing_adds.len(), 1);
        assert_eq!(diff.update_deletes.len(), 0);
        assert_eq!(diff.unchanged, 0);
    }

    #[test]
    fn diff_updates_changed_value_with_add_and_remove() {
        let diff = diff_records(
            vec![a("www.example.com", "2.2.2.2")],
            vec![a("www.example.com", "1.1.1.1")],
        );
        assert_eq!(diff.update_adds.len(), 1);
        assert_eq!(diff.update_deletes.len(), 1);
        assert_eq!(diff.unchanged, 0);
        match &diff.update_adds[0].record {
            RecordData::A { ip } => assert_eq!(ip.to_string(), "2.2.2.2"),
            other => panic!("expected A, got {other:?}"),
        }
    }

    #[test]
    fn diff_reports_identical_records_as_unchanged() {
        let diff = diff_records(
            vec![a("www.example.com", "1.1.1.1")],
            vec![a("www.example.com", "1.1.1.1")],
        );
        assert_eq!(diff.missing_adds.len(), 0);
        assert_eq!(diff.update_adds.len(), 0);
        assert_eq!(diff.update_deletes.len(), 0);
        assert_eq!(diff.unchanged, 1);
    }

    #[test]
    fn diff_treats_ttl_difference_as_update() {
        let mut src = a("www.example.com", "1.1.1.1");
        src.ttl = 300;
        let mut dst = a("www.example.com", "1.1.1.1");
        dst.ttl = 3600;
        let diff = diff_records(vec![src], vec![dst]);
        assert_eq!(diff.update_adds.len(), 1);
        assert_eq!(diff.update_deletes.len(), 1);
        assert_eq!(diff.unchanged, 0);
        assert_eq!(diff.update_adds[0].ttl, 300);
    }

    #[test]
    fn diff_never_prunes_destination_only_names() {
        let diff = diff_records(
            vec![a("a.example.com", "1.1.1.1")],
            vec![a("a.example.com", "1.1.1.1"), a("b.example.com", "2.2.2.2")],
        );
        assert_eq!(diff.missing_adds.len(), 0);
        assert_eq!(diff.update_adds.len(), 0);
        assert_eq!(diff.update_deletes.len(), 0);
        assert_eq!(diff.unchanged, 1);
        assert_eq!(diff.destination_only.len(), 1);
    }

    // ── SyncDiffOptions ────────────────────────────────────────────────────────

    fn make_source_dest_clients(
        zone: &str,
        src_records: Vec<ZoneRecord>,
        dst_records: Vec<ZoneRecord>,
    ) -> (FakeZoneRead, FakeZoneRead) {
        let source = FakeZoneRead::new(sync_test_response(zone, src_records));
        let dest = FakeZoneRead::new(sync_test_response(zone, dst_records));
        (source, dest)
    }

    #[tokio::test]
    async fn create_missing_false_does_not_add_new_name_types() {
        let zone = "example.com";
        let (source, dest) = make_source_dest_clients(
            zone,
            vec![zone_record("new-host.example.com", "A", 3600, json!({ "ipAddress": "1.1.1.1" }))],
            vec![],
        );
        let opts = SyncDiffOptions {
            create_missing: false,
            overwrite_existing: true,
            delete_destination_only: false,
            ignore: vec![],
        };
        let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
            .await
            .unwrap();
        assert_eq!(plan.adds.len(), 0);
        assert_eq!(plan.deletes.len(), 0);
    }

    #[tokio::test]
    async fn create_missing_true_adds_new_name_types() {
        let zone = "example.com";
        let (source, dest) = make_source_dest_clients(
            zone,
            vec![zone_record("new-host.example.com", "A", 3600, json!({ "ipAddress": "1.1.1.1" }))],
            vec![],
        );
        let opts = SyncDiffOptions {
            create_missing: true,
            overwrite_existing: false,
            delete_destination_only: false,
            ignore: vec![],
        };
        let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
            .await
            .unwrap();
        assert_eq!(plan.adds.len(), 1);
        assert_eq!(plan.deletes.len(), 0);
    }

    #[tokio::test]
    async fn overwrite_existing_false_leaves_changed_records_untouched() {
        let zone = "example.com";
        let (source, dest) = make_source_dest_clients(
            zone,
            vec![zone_record("www.example.com", "A", 3600, json!({ "ipAddress": "2.2.2.2" }))],
            vec![zone_record("www.example.com", "A", 3600, json!({ "ipAddress": "1.1.1.1" }))],
        );
        let opts = SyncDiffOptions {
            create_missing: true,
            overwrite_existing: false,
            delete_destination_only: false,
            ignore: vec![],
        };
        let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
            .await
            .unwrap();
        assert_eq!(plan.adds.len(), 0);
        assert_eq!(plan.deletes.len(), 0);
    }

    #[tokio::test]
    async fn overwrite_existing_true_replaces_changed_records() {
        let zone = "example.com";
        let (source, dest) = make_source_dest_clients(
            zone,
            vec![zone_record("www.example.com", "A", 3600, json!({ "ipAddress": "2.2.2.2" }))],
            vec![zone_record("www.example.com", "A", 3600, json!({ "ipAddress": "1.1.1.1" }))],
        );
        let opts = SyncDiffOptions {
            create_missing: false,
            overwrite_existing: true,
            delete_destination_only: false,
            ignore: vec![],
        };
        let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
            .await
            .unwrap();
        assert_eq!(plan.adds.len(), 1);
        assert_eq!(plan.deletes.len(), 1);
        match &plan.adds[0].record {
            RecordData::A { ip } => assert_eq!(ip.to_string(), "2.2.2.2"),
            other => panic!("expected A, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn delete_destination_only_false_leaves_destination_only_records() {
        let zone = "example.com";
        let (source, dest) = make_source_dest_clients(
            zone,
            vec![],
            vec![zone_record("www.example.com", "A", 3600, json!({ "ipAddress": "1.1.1.1" }))],
        );
        let opts = SyncDiffOptions {
            create_missing: true,
            overwrite_existing: true,
            delete_destination_only: false,
            ignore: vec![],
        };
        let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
            .await
            .unwrap();
        assert_eq!(plan.deletes.len(), 0);
        assert_eq!(plan.untouched, 1);
    }

    #[tokio::test]
    async fn delete_destination_only_true_removes_destination_only_records() {
        let zone = "example.com";
        let (source, dest) = make_source_dest_clients(
            zone,
            vec![],
            vec![zone_record("www.example.com", "A", 3600, json!({ "ipAddress": "1.1.1.1" }))],
        );
        let opts = SyncDiffOptions {
            create_missing: true,
            overwrite_existing: true,
            delete_destination_only: true,
            ignore: vec![],
        };
        let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
            .await
            .unwrap();
        assert_eq!(plan.deletes.len(), 1);
        assert_eq!(plan.untouched, 0);
    }

    #[tokio::test]
    async fn ignore_pattern_filters_source_records_by_fqdn() {
        let zone = "example.com";
        let (source, dest) = make_source_dest_clients(
            zone,
            vec![
                zone_record("web.example.com", "A", 3600, json!({ "ipAddress": "1.1.1.1" })),
                zone_record("internal.example.com", "A", 3600, json!({ "ipAddress": "10.0.0.1" })),
            ],
            vec![],
        );
        let opts = SyncDiffOptions {
            create_missing: true,
            overwrite_existing: true,
            delete_destination_only: false,
            ignore: vec![Regex::new(r"^internal\.").unwrap()],
        };
        let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
            .await
            .unwrap();
        assert_eq!(plan.adds.len(), 1);
        assert!(plan.adds.iter().any(|r| r.fqdn == "web.example.com"));
        assert!(!plan.adds.iter().any(|r| r.fqdn == "internal.example.com"));
    }

    #[tokio::test]
    async fn ignore_pattern_is_case_sensitive_by_default() {
        let zone = "example.com";
        let (source, dest) = make_source_dest_clients(
            zone,
            vec![
                zone_record("web.example.com", "A", 3600, json!({ "ipAddress": "1.1.1.1" })),
                zone_record("api.example.com", "A", 3600, json!({ "ipAddress": "2.2.2.2" })),
            ],
            vec![],
        );
        let opts = SyncDiffOptions {
            create_missing: true,
            overwrite_existing: true,
            delete_destination_only: false,
            ignore: vec![Regex::new(r"^web\.example").unwrap()],
        };
        let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
            .await
            .unwrap();
        // web.example.com should be filtered, api.example.com should remain
        assert_eq!(plan.adds.len(), 1);
        assert!(plan.adds.iter().any(|r| r.fqdn == "api.example.com"));
        assert!(!plan.adds.iter().any(|r| r.fqdn == "web.example.com"));
    }

    #[tokio::test]
    async fn all_flags_false_produces_no_ops() {
        let zone = "example.com";
        let (source, dest) = make_source_dest_clients(
            zone,
            vec![
                zone_record("new-host.example.com", "A", 3600, json!({ "ipAddress": "1.1.1.1" })),
                zone_record("www.example.com", "A", 3600, json!({ "ipAddress": "2.2.2.2" })),
            ],
            vec![zone_record("www.example.com", "A", 3600, json!({ "ipAddress": "1.1.1.1" }))],
        );
        let opts = SyncDiffOptions {
            create_missing: false,
            overwrite_existing: false,
            delete_destination_only: false,
            ignore: vec![],
        };
        let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
            .await
            .unwrap();
        assert_eq!(plan.adds.len(), 0);
        assert_eq!(plan.deletes.len(), 0);
    }

    #[tokio::test]
    async fn delete_destination_only_with_create_missing_is_full_mirror() {
        let zone = "example.com";
        let (source, dest) = make_source_dest_clients(
            zone,
            vec![zone_record("a.example.com", "A", 3600, json!({ "ipAddress": "1.1.1.1" }))],
            vec![zone_record("b.example.com", "A", 3600, json!({ "ipAddress": "2.2.2.2" }))],
        );
        let opts = SyncDiffOptions {
            create_missing: true,
            overwrite_existing: true,
            delete_destination_only: true,
            ignore: vec![],
        };
        let plan = plan_zone_with_clients(&source, &dest, zone, &HashMap::new(), &opts)
            .await
            .unwrap();
        assert_eq!(plan.adds.len(), 1);
        assert!(plan.adds.iter().any(|r| r.fqdn == "a.example.com"));
        assert_eq!(plan.deletes.len(), 1);
        assert!(plan.deletes.iter().any(|r| r.fqdn == "b.example.com"));
    }
}
