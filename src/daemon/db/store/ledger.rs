//! Ownership-ledger persistence for [`DaemonStateStore`].
//!
//! Implements the control-plane [`SyncLedger`] trait over the `synced_records`
//! table, recording which records each sync job owns on its destination so
//! `prune_synced` can remove exactly those records when they leave the source.

use chrono::Utc;
use diesel::prelude::*;
use diesel::upsert::excluded;
use tracing::{debug, instrument};

use super::DaemonStateStore;
use crate::control_plane::sync::{OwnedRecord, SyncLedger};
use crate::core::error::{Error, Result};
use crate::daemon::db::models::SyncedRecordRow;
use crate::daemon::db::schema::synced_records;

impl DaemonStateStore {
    /// Load every owned-record row for `job_key`.
    #[instrument(level = "debug", skip(self), fields(job_key))]
    pub fn load_synced_records(
        &self,
        job_key: &str,
    ) -> std::result::Result<Vec<SyncedRecordRow>, String> {
        let mut conn = self.pool.get().map_err(|e| format!("db pool error: {e}"))?;
        let rows = synced_records::table
            .filter(synced_records::job_key.eq(job_key))
            .load::<SyncedRecordRow>(&mut conn)
            .map_err(|e| format!("load_synced_records failed: {e}"))?;
        debug!(
            job_key,
            row_count = rows.len(),
            "DB read: load_synced_records"
        );
        Ok(rows)
    }

    /// Upsert owned-record rows, preserving `first_synced_at` and refreshing
    /// `last_seen_at` on conflict.
    #[instrument(level = "debug", skip(self, rows), fields(job_key, count = rows.len()))]
    pub fn upsert_synced_records(
        &self,
        job_key: &str,
        rows: &[SyncedRecordRow],
    ) -> std::result::Result<(), String> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut conn = self.pool.get().map_err(|e| format!("db pool error: {e}"))?;
        // SQLite + Diesel does not support a multi-row INSERT … ON CONFLICT …
        // DO UPDATE, so upsert one row at a time. `first_synced_at` is
        // preserved on conflict; only `last_seen_at` is refreshed.
        for row in rows {
            diesel::insert_into(synced_records::table)
                .values(row)
                .on_conflict((
                    synced_records::job_key,
                    synced_records::zone,
                    synced_records::fqdn,
                    synced_records::rtype,
                    synced_records::value,
                ))
                .do_update()
                .set(synced_records::last_seen_at.eq(excluded(synced_records::last_seen_at)))
                .execute(&mut conn)
                .map_err(|e| format!("upsert_synced_records failed: {e}"))?;
        }
        debug!(
            job_key,
            count = rows.len(),
            "DB write: upsert_synced_records"
        );
        Ok(())
    }

    /// Delete specific owned-record rows for `job_key`.
    #[instrument(level = "debug", skip(self, rows), fields(job_key, count = rows.len()))]
    pub fn delete_synced_records(
        &self,
        job_key: &str,
        rows: &[SyncedRecordRow],
    ) -> std::result::Result<(), String> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut conn = self.pool.get().map_err(|e| format!("db pool error: {e}"))?;
        for row in rows {
            diesel::delete(
                synced_records::table.filter(
                    synced_records::job_key
                        .eq(job_key)
                        .and(synced_records::zone.eq(&row.zone))
                        .and(synced_records::fqdn.eq(&row.fqdn))
                        .and(synced_records::rtype.eq(&row.rtype))
                        .and(synced_records::value.eq(&row.value)),
                ),
            )
            .execute(&mut conn)
            .map_err(|e| format!("delete_synced_records failed: {e}"))?;
        }
        debug!(
            job_key,
            count = rows.len(),
            "DB write: delete_synced_records"
        );
        Ok(())
    }

    /// Delete every owned-record row for `job_key` (full teardown).
    #[instrument(level = "debug", skip(self), fields(job_key))]
    pub fn delete_all_synced_records(&self, job_key: &str) -> std::result::Result<usize, String> {
        let mut conn = self.pool.get().map_err(|e| format!("db pool error: {e}"))?;
        let deleted =
            diesel::delete(synced_records::table.filter(synced_records::job_key.eq(job_key)))
                .execute(&mut conn)
                .map_err(|e| format!("delete_all_synced_records failed: {e}"))?;
        debug!(job_key, deleted, "DB write: delete_all_synced_records");
        Ok(deleted)
    }
}

/// Convert a domain `OwnedRecord` into a storable row, stamping timestamps.
fn to_row(job_key: &str, rec: &OwnedRecord, now: &str) -> SyncedRecordRow {
    SyncedRecordRow {
        job_key: job_key.to_string(),
        zone: rec.zone.clone(),
        fqdn: rec.fqdn.clone(),
        rtype: rec.rtype.clone(),
        value: rec.value.clone(),
        ttl: rec.ttl as i32,
        first_synced_at: now.to_string(),
        last_seen_at: now.to_string(),
    }
}

/// Convert a stored row back into a domain `OwnedRecord`.
fn from_row(row: SyncedRecordRow) -> OwnedRecord {
    OwnedRecord {
        zone: row.zone,
        fqdn: row.fqdn,
        rtype: row.rtype,
        value: row.value,
        ttl: row.ttl.max(0) as u32,
    }
}

impl SyncLedger for DaemonStateStore {
    fn load_owned(&self, job_key: &str) -> Result<Vec<OwnedRecord>> {
        let rows = self.load_synced_records(job_key).map_err(Error::api)?;
        Ok(rows.into_iter().map(from_row).collect())
    }

    fn record_owned(&self, job_key: &str, records: &[OwnedRecord]) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let rows: Vec<SyncedRecordRow> = records.iter().map(|r| to_row(job_key, r, &now)).collect();
        self.upsert_synced_records(job_key, &rows)
            .map_err(Error::api)
    }

    fn forget_owned(&self, job_key: &str, records: &[OwnedRecord]) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let rows: Vec<SyncedRecordRow> = records.iter().map(|r| to_row(job_key, r, &now)).collect();
        self.delete_synced_records(job_key, &rows)
            .map_err(Error::api)
    }

    fn forget_all(&self, job_key: &str) -> Result<()> {
        self.delete_all_synced_records(job_key)
            .map(|_| ())
            .map_err(Error::api)
    }
}
