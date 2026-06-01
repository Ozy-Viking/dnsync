//! building the sync plan: zone listing, record collection, diffing.

use super::*;

/// Builds a per-zone synchronization plan between two configured DNS servers.
///
/// The returned tuple contains the selected source server id, the selected
/// destination server id, and a vector of per-zone `ZonePlan`s describing
/// additions, deletions, and counts needed to make the destination match the
/// source according to `diff_opts`.
///
/// # Errors
///
/// Returns an error when:
/// - `app_config` is `None` or the selected server ids are not present in the config.
/// - a `profile` is supplied (named sync profiles are not supported).
/// - `from` or `to` server ids are not provided.
/// - any `maps` entry fails to parse as an IP pair.
/// - listing zones on the source or planning any zone fails.
///
/// # Examples
///
/// ```text
/// # use tokio::runtime::Runtime;
/// # use std::sync::Arc;
/// # use crate::control_plane::sync::{build_sync_plan, SyncDiffOptions};
/// # use crate::config::AppConfig;
/// # // The following is a usage example — in real code supply a valid AppConfig and servers.
/// let rt = Runtime::new().unwrap();
/// let cfg: Arc<AppConfig> = Arc::new(AppConfig::default()); // placeholder
/// let diff_opts = SyncDiffOptions::default();
/// let result = rt.block_on(async {
///     build_sync_plan(
///         Some(&*cfg),
///         None,                 // profile (unsupported)
///         Some("source-id"),    // --from
///         Some("dest-id"),      // --to
///         &[],                  // zones (empty -> discover)
///         &[],                  // maps
///         diff_opts,
///     ).await
/// });
/// assert!(result.is_ok() || result.is_err()); // placeholder assertion for example
/// ```
#[allow(clippy::too_many_arguments)]
#[instrument(
    level = "debug",
    skip(app_config, zones, maps),
    fields(profile = ?profile, from = ?from, to = ?to)
)]
pub(crate) async fn build_sync_plan(
    app_config: Option<&AppConfig>,
    profile: Option<&str>,
    from: Option<&str>,
    to: Option<&str>,
    zones: &[String],
    maps: &[String],
    diff_opts: SyncDiffOptions,
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
    let from_id = from.ok_or_else(|| Error::parse("sync requires a source server: pass --from"))?;
    let to_id = to.ok_or_else(|| Error::parse("sync requires a destination server: pass --to"))?;

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
    let mut plans = Vec::with_capacity(zone_list.len());
    for zone in &zone_list {
        plans.push(plan_zone(&from_client, &to_client, zone, &ip_map, &diff_opts).await?);
    }

    Ok((from_id.to_string(), to_id.to_string(), plans))
}

/// Build the sync plan for a single zone.
#[instrument(level = "trace", skip(from_client, to_client, ip_map), fields(zone))]
pub(crate) async fn plan_zone(
    from_client: &VendorClient,
    to_client: &VendorClient,
    zone: &str,
    ip_map: &HashMap<IpAddr, IpAddr>,
    sync_opts: &SyncDiffOptions,
) -> Result<ZonePlan> {
    plan_zone_with_clients(from_client, to_client, zone, ip_map, sync_opts).await
}

/// Builds a per-zone plan by comparing source and destination records and
/// producing lists of planned additions and deletions along with counts.
///
/// The comparison reads all records (including subdomains) from both clients,
/// applies the optional `ip_map` rewrites to source A/AAAA records, and
/// filters source records whose FQDN matches any regex in `sync_opts.ignore`.
/// Which diff buckets become planned additions or deletions is controlled by
/// `sync_opts`:
/// - `create_missing` includes source-only record-sets as additions.
/// - `overwrite_existing` includes differing record-sets as additions and the
///   corresponding destination records as deletions.
/// - `delete_destination_only` includes destination-only record-sets as
///   deletions (when false, those are counted as `untouched`).
///
/// On success returns a `ZonePlan` containing sorted `adds` and `deletes`,
/// the number of `unchanged` records, `untouched` destination-only records (or
/// 0 when deletions are enabled), and `skipped` source records.
#[instrument(level = "trace", skip(from_client, to_client, ip_map), fields(zone))]
pub(crate) async fn plan_zone_with_clients<F, T>(
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
    trace!(
        source_count = source_records.len(),
        skipped, "source records collected"
    );
    let (dest_records, _) = collect_records(&dest, zone, None);

    // Filter out source records whose FQDN matches any ignore pattern.
    if !sync_opts.ignore.is_empty() {
        source_records.retain(|r| !sync_opts.ignore.iter().any(|pat| pat.is_match(&r.fqdn)));
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
        // Filter destination-only records through the same ignore patterns.
        let dest_only = diff
            .destination_only
            .iter()
            .filter(|r| !sync_opts.ignore.iter().any(|pat| pat.is_match(&r.fqdn)))
            .cloned()
            .collect::<Vec<_>>();
        deletes.extend(dest_only);
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

/// Convert a vendor record-list response into a list of syncable records.

///

/// This filters out records that are disabled or not writable by the record API,

/// optionally rewrites A/AAAA addresses using `ip_map`, and normalizes TTLs

/// where a vendor reports zero TTL.

///

/// # Parameters

///

/// - `response`: vendor `ListRecordsResponse` containing zones and records.

/// - `zone`: the zone name used to resolve record FQDNs.

/// - `ip_map`: optional mapping of source IP -> destination IP applied to A and AAAA records.

///

/// # Returns

///

/// A tuple where the first element is a vector of `PlannedRecord` ready for

/// planning/apply, and the second element is the count of records skipped

/// because they were disabled, server-managed, or otherwise not writable.

///

/// # Examples

///

/// ```text

/// // Construct a minimal ListRecordsResponse `resp` for the zone "example.com"

/// // and call `collect_records(&resp, "example.com", None)`.

/// // The returned vector contains PlannedRecord entries and the skipped count.

/// # use std::net::IpAddr;

/// # use std::collections::HashMap;

/// # // (omitted: build a ListRecordsResponse matching the crate's types)

/// # let resp = ListRecordsResponse { zones: vec![] };

/// let (records, skipped) = collect_records(&resp, "example.com", None);

/// assert!(skipped >= 0);

/// ```
pub(crate) fn collect_records(
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

/// Compute per-(name,type) differences between source and destination planned records.
///
/// The returned `Diff` contains these buckets:
/// - `missing_adds`: records present in `source` but absent on the destination (per (name,type)).
/// - `update_adds`: source records that differ from destination records for the same (name,type).
/// - `update_deletes`: destination records that must be removed to make way for `update_adds`.
/// - `destination_only`: records present only on the destination (no matching (name,type) in `source`).
/// - `unchanged`: count of source records whose canonical value and TTL exactly match a destination record.
///
/// A record is considered unchanged only when both its canonical value and its TTL match a destination record; TTL differences cause the record to be treated as an update (the source TTL will be used for adds).
///
/// # Examples
///
/// ```text
/// let diff = diff_records(Vec::new(), Vec::new());
/// assert_eq!(diff.missing_adds.len(), 0);
/// assert_eq!(diff.update_adds.len(), 0);
/// assert_eq!(diff.update_deletes.len(), 0);
/// assert_eq!(diff.destination_only.len(), 0);
/// assert_eq!(diff.unchanged, 0);
/// ```
pub(crate) fn diff_records(source: Vec<PlannedRecord>, dest: Vec<PlannedRecord>) -> Diff {
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

/// A canonical string for a record's data, used to compare record values.
pub(crate) fn canonical(record: &RecordData) -> String {
    record
        .to_api_params()
        .into_iter()
        .map(|(key, value)| format!("{key}\u{1}{value}"))
        .collect::<Vec<_>>()
        .join("\u{2}")
}

/// A stable sort key so plan output is deterministic.
pub(crate) fn sort_key(record: &PlannedRecord) -> (String, String, String) {
    (
        record.fqdn.to_lowercase(),
        record.rtype.clone(),
        canonical(&record.record),
    )
}
