use diesel::prelude::*;

use crate::daemon::db::schema::{daemon_health, job_runs, job_status, synced_records};

/// One row — the daemon's current health snapshot.
/// `id` is always 1 (enforced by CHECK constraint in DDL).
#[derive(Debug, Clone, Queryable, Selectable, Insertable, AsChangeset)]
#[diesel(table_name = daemon_health)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct DaemonHealthRow {
    pub id: i32,
    pub daemon_id: String,
    pub started_at: String,
    pub last_heartbeat_at: String,
    pub daemon_state: String,
    pub overall_health: String,
    pub last_health_change_at: String,
    pub last_error_summary: Option<String>,
    pub jobs_total: i32,
    pub jobs_enabled: i32,
    pub jobs_healthy: i32,
    pub jobs_degraded: i32,
    pub jobs_running: i32,
}

/// One row per job ID — current status snapshot.
#[derive(Debug, Clone, Queryable, Selectable, Insertable, AsChangeset)]
#[diesel(table_name = job_status)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct JobStatusRow {
    pub job_id: String,
    pub job_kind: String,
    pub enabled: i32,
    pub current_state: String,
    pub last_started_at: Option<String>,
    pub last_finished_at: Option<String>,
    pub last_success_at: Option<String>,
    pub last_failure_at: Option<String>,
    pub last_error_summary: Option<String>,
    pub consecutive_failures: i32,
    pub last_run_id: Option<String>,
}

/// One row per record a sync job owns on its destination.
///
/// The ownership ledger: records that a job (`job_key`) created on its
/// destination. Used by `prune_synced` to remove exactly the records a job
/// previously synced once they disappear from the source — and nothing else.
#[derive(Debug, Clone, Queryable, Selectable, Insertable, AsChangeset)]
#[diesel(table_name = synced_records)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct SyncedRecordRow {
    pub job_key: String,
    pub zone: String,
    pub fqdn: String,
    pub rtype: String,
    pub value: String,
    pub ttl: i32,
    pub first_synced_at: String,
    pub last_seen_at: String,
}

/// Append-only run history row.
#[derive(Debug, Clone, Queryable, Selectable, Insertable)]
#[diesel(table_name = job_runs)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct JobRunRow {
    pub run_id: String,
    pub job_id: String,
    pub job_kind: String,
    pub trigger_kind: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub outcome: Option<String>,
    pub error_summary: Option<String>,
    pub duration_ms: Option<i32>,
}
