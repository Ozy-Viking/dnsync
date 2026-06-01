//! sync option/plan/summary types.

use super::*;

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
    /// Default synchronization options used when none are specified.
    ///
    /// The defaults enable creating destination-missing records and overwriting differing
    /// existing records, disable deletion of destination-only records, and use no ignore
    /// patterns.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let opts = crate::control_plane::sync::SyncDiffOptions::default();
    /// assert!(opts.create_missing);
    /// assert!(opts.overwrite_existing);
    /// assert!(!opts.delete_destination_only);
    /// assert!(opts.ignore.is_empty());
    /// ```
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
pub(crate) const DEFAULT_TTL: u32 = 3600;

/// One record to be written to (or removed from) the destination.
#[derive(Debug, Clone)]
pub(crate) struct PlannedRecord {
    /// Fully-qualified record name.
    pub(crate) fqdn: String,
    /// Uppercase record type, e.g. `A`.
    pub(crate) rtype: String,
    pub(crate) ttl: u32,
    pub(crate) record: RecordData,
}

/// The computed difference for one zone.
#[derive(Debug, Default)]
pub(crate) struct Diff {
    /// Source records for name+type combos that don't exist in destination at all.
    pub(crate) missing_adds: Vec<PlannedRecord>,
    /// Source records for name+type combos that exist in destination but with a different value.
    pub(crate) update_adds: Vec<PlannedRecord>,
    /// Destination records being replaced by update_adds (stale values for the same name+type).
    pub(crate) update_deletes: Vec<PlannedRecord>,
    /// Destination records for name+type combos with no counterpart in source.
    pub(crate) destination_only: Vec<PlannedRecord>,
    /// Records identical in source and destination (same value + TTL).
    pub(crate) unchanged: usize,
}

/// The plan for one zone, ready to display or apply.
#[derive(Debug)]
pub(crate) struct ZonePlan {
    pub(crate) zone: String,
    pub(crate) adds: Vec<PlannedRecord>,
    pub(crate) deletes: Vec<PlannedRecord>,
    pub(crate) unchanged: usize,
    pub(crate) untouched: usize,
    /// Source records that cannot be synced (SOA, DNSSEC, disabled, unknown).
    pub(crate) skipped: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncApplySummary {
    pub applied: usize,
    pub failures: usize,
}
