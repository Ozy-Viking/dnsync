//! Ownership ledger abstraction for record sync.
//!
//! A *ledger* records which records a sync job created on its destination, so a
//! later run can remove exactly those records once they disappear from the
//! source — without ever touching records the job did not create.
//!
//! The trait lives here in the control plane so the vendor-neutral sync logic
//! can reconcile ownership without depending on the daemon. The daemon's
//! SQLite-backed `DaemonStateStore` implements it; the CLI can open a pool and
//! do the same. When no ledger is supplied, ownership tracking is simply off.

use super::*;

/// One record a job owns on its destination.
///
/// `value` is the canonical record value (see [`canonical`]); together with
/// `zone`, `fqdn` and `rtype` it uniquely identifies an owned record within a
/// job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedRecord {
    pub zone: String,
    pub fqdn: String,
    pub rtype: String,
    pub value: String,
    pub ttl: u32,
}

impl OwnedRecord {
    /// Build an `OwnedRecord` from a planned record for the given zone.
    pub(crate) fn from_planned(zone: &str, rec: &PlannedRecord) -> Self {
        Self {
            zone: zone.to_string(),
            fqdn: rec.fqdn.clone(),
            rtype: rec.rtype.clone(),
            value: canonical(&rec.record),
            ttl: rec.ttl,
        }
    }

    /// The identity key used to compare records across runs, normalised so
    /// case differences in names do not split a record's identity.
    pub(crate) fn key(&self) -> (String, String, String, String) {
        (
            self.zone.to_lowercase(),
            self.fqdn.to_lowercase(),
            self.rtype.clone(),
            self.value.clone(),
        )
    }
}

/// Persistent record of what each sync job owns on its destination.
///
/// Implementations are keyed by an opaque `job_key` (the daemon uses the job
/// id; the CLI derives one from the `from→to` server pair). All methods are
/// synchronous — implementations are expected to be quick local state stores.
pub trait SyncLedger: Send + Sync {
    /// Load every record currently owned by `job_key`.
    fn load_owned(&self, job_key: &str) -> Result<Vec<OwnedRecord>>;

    /// Record (upsert) the set of records `job_key` now owns.
    fn record_owned(&self, job_key: &str, records: &[OwnedRecord]) -> Result<()>;

    /// Forget specific records previously owned by `job_key`.
    fn forget_owned(&self, job_key: &str, records: &[OwnedRecord]) -> Result<()>;

    /// Forget every record owned by `job_key` (full teardown).
    fn forget_all(&self, job_key: &str) -> Result<()>;
}

/// Ownership context threaded through a sync run.
///
/// Holds the ledger, the job's ownership key, and whether pruning of
/// no-longer-present owned records is enabled for this run.
pub struct Ownership<'a> {
    pub job_key: String,
    pub ledger: &'a dyn SyncLedger,
    pub prune: bool,
}
