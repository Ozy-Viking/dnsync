//! sync entry points (run_sync / run_sync_json).

use super::*;

/// Synchronise DNS records between a configured source and destination server.
///
/// Builds a zone-level plan of record additions and deletions (optionally applying IP mappings and ignore rules),
/// prints the plan as pretty JSON or a formatted table, and — when `apply` is true and there are changes — writes
/// the planned additions and deletions to the destination server. The function returns an error when configuration,
/// server/zone resolution, or IP mapping parsing fails, or when any record write fails while applying changes.
///
/// # Errors
///
/// Returns an error if the configuration is missing or invalid, if the selected source/destination servers or zones
/// cannot be resolved, if IP mapping specifications cannot be parsed, or — when `apply` is set — if any record write fails.
///
/// # Examples
///
/// ```rust,ignore
/// # use control_plane::sync::{run_sync, SyncDiffOptions};
/// // Example: dry-run sync from server "from-id" to "to-id" with default diff options.
/// let diff_opts = SyncDiffOptions::default();
/// // Run inside an async runtime:
/// tokio::runtime::Runtime::new().unwrap().block_on(async {
///     let _ = run_sync(None, None, Some("from-id"), Some("to-id"), &[], &[], false, false, diff_opts).await;
/// });
/// ```
#[allow(clippy::too_many_arguments)]
#[instrument(
    level = "debug",
    skip(app_config, zones, maps, ownership),
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
    diff_opts: SyncDiffOptions,
    ownership: Option<&Ownership<'_>>,
) -> Result<()> {
    debug!("building sync plan");
    let (from_id, to_id, plans) =
        build_sync_plan(app_config, profile, from, to, zones, maps, diff_opts).await?;
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
    let prune_enabled = ownership.is_some_and(|o| o.prune);
    if !apply || (!has_changes && !prune_enabled) {
        return Ok(());
    }

    let to_client = VendorClient::from_server(
        app_config
            .and_then(|cfg| cfg.selected_server(Some(&to_id)).ok())
            .ok_or_else(|| Error::config("sync destination server disappeared"))?,
    )?;

    let mut applied = 0;
    if has_changes {
        let summary = apply_plans(&to_client, &plans).await?;
        applied = summary.applied;
    }

    let mut pruned = 0;
    if let Some(ownership) = ownership {
        let prune = reconcile_ownership(&to_client, &plans, ownership, apply).await?;
        pruned = prune.pruned;
        if prune.skipped_drift > 0 {
            eprintln!(
                "  ! {} owned record(s) skipped: live value drifted from the recorded value",
                prune.skipped_drift
            );
        }
    }

    println!("\nApplied {applied} change(s); pruned {pruned} owned record(s).");
    Ok(())
}

/// Tear down every record a sync job created on its destination.
///
/// Resolves the destination server `to`, then removes (value-match gated) every
/// record the job's ledger says it owns and clears those ledger entries. When
/// `apply` is false this is a dry-run preview that writes nothing. Returns a
/// JSON summary including a `prune_summary` object.
#[instrument(level = "debug", skip(app_config, ownership), fields(to = ?to, apply))]
pub async fn run_sync_teardown(
    app_config: Option<&AppConfig>,
    to: &str,
    apply: bool,
    ownership: &Ownership<'_>,
) -> Result<serde_json::Value> {
    let cfg = app_config.ok_or_else(|| {
        Error::config("sync teardown requires a config file defining the destination server")
    })?;
    let to_server = cfg.selected_server(Some(to))?;
    let to_client = VendorClient::from_server(to_server)?;

    let summary = teardown_ownership(&to_client, ownership, apply).await?;
    let mut out = serde_json::json!({
        "action": "teardown",
        "to": to,
        "applied": apply,
    });
    out["prune_summary"] = serde_json::to_value(summary)
        .map_err(|e| Error::parse(format!("could not serialise teardown summary: {e}")))?;
    Ok(out)
}

/// Build and optionally apply a record-level synchronization plan between two configured DNS servers, returning a JSON representation of the plan and (when changes are applied) an application summary.
///
/// The returned JSON contains `from` and `to` server ids, a `zones` array with per-zone `add` and `remove` lists and counts (`unchanged`, `untouched`, `skipped`), and, when `apply` is true and changes were applied, an `apply_summary` object.
///
/// # Returns
///
/// A JSON value describing the computed sync plan. When `apply` is true and the plan contains changes, the JSON also contains an `apply_summary` object with `applied` and `failures` counts.
///
/// # Errors
///
/// Propagates errors from plan construction, server/client resolution, and record write operations. When `apply` is true, any write failures cause an error to be returned after attempting all operations.
///
/// # Examples
///
/// ```rust,ignore
/// # use std::sync::Arc;
/// # use regex::Regex;
/// # use crate::control_plane::sync::{run_sync_json, SyncDiffOptions};
/// # use crate::config::AppConfig;
/// # tokio::runtime::Runtime::new().unwrap().block_on(async {
/// let cfg: Arc<AppConfig> = Arc::new(AppConfig::load_default().unwrap());
/// let diff_opts = SyncDiffOptions { ignore: Vec::<Regex>::new(), ..Default::default() };
/// let json = run_sync_json(
///     Some(&cfg),
///     None,                 // profile (not used)
///     Some("source-id"),    // from server id
///     Some("dest-id"),      // to server id
///     &[],                  // zones (empty = discover from source)
///     &[],                  // ip maps
///     false,                // apply = dry run
///     diff_opts,
/// ).await.unwrap();
/// println!("{}", json);
/// # });
/// ```
#[allow(clippy::too_many_arguments)]
#[instrument(
    level = "debug",
    skip(app_config, zones, maps, ownership),
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
    diff_opts: SyncDiffOptions,
    ownership: Option<&Ownership<'_>>,
) -> Result<serde_json::Value> {
    let (from_id, to_id, plans) =
        build_sync_plan(app_config, profile, from, to, zones, maps, diff_opts).await?;
    let mut out = sync_plan_json(&from_id, &to_id, &plans, apply);

    let has_changes = plans
        .iter()
        .any(|p| !p.adds.is_empty() || !p.deletes.is_empty());
    let prune_enabled = ownership.is_some_and(|o| o.prune);

    if apply && (has_changes || prune_enabled) {
        let cfg = app_config.expect("build_sync_plan already required config");
        let to_server = cfg.selected_server(Some(&to_id))?;
        let to_client = VendorClient::from_server(to_server)?;

        if has_changes {
            let summary = apply_plans(&to_client, &plans).await?;
            out["apply_summary"] = serde_json::to_value(summary)
                .map_err(|e| Error::parse(format!("could not serialise sync summary: {e}")))?;
        }
        if let Some(ownership) = ownership {
            let prune = reconcile_ownership(&to_client, &plans, ownership, apply).await?;
            out["prune_summary"] = serde_json::to_value(prune)
                .map_err(|e| Error::parse(format!("could not serialise prune summary: {e}")))?;
        }
    }

    Ok(out)
}
