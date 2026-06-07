//! Tests for ownership reconciliation (`prune_synced`) and teardown.

use super::*;

/// An in-memory [`SyncLedger`] for tests.
#[derive(Default)]
struct InMemoryLedger {
    owned: Mutex<Vec<OwnedRecord>>,
}

impl InMemoryLedger {
    fn with(records: Vec<OwnedRecord>) -> Self {
        Self {
            owned: Mutex::new(records),
        }
    }

    fn snapshot(&self) -> Vec<OwnedRecord> {
        self.owned.lock().unwrap().clone()
    }
}

impl SyncLedger for InMemoryLedger {
    fn load_owned(&self, _job_key: &str) -> Result<Vec<OwnedRecord>> {
        Ok(self.owned.lock().unwrap().clone())
    }

    fn record_owned(&self, _job_key: &str, records: &[OwnedRecord]) -> Result<()> {
        let mut owned = self.owned.lock().unwrap();
        for rec in records {
            if !owned.iter().any(|r| r.key() == rec.key()) {
                owned.push(rec.clone());
            }
        }
        Ok(())
    }

    fn forget_owned(&self, _job_key: &str, records: &[OwnedRecord]) -> Result<()> {
        let forget: Vec<_> = records.iter().map(|r| r.key()).collect();
        self.owned
            .lock()
            .unwrap()
            .retain(|r| !forget.contains(&r.key()));
        Ok(())
    }

    fn forget_all(&self, _job_key: &str) -> Result<()> {
        self.owned.lock().unwrap().clear();
        Ok(())
    }
}

/// A destination fake that both lists records (live state) and records deletes.
struct FakeDestination {
    live: ListRecordsResponse,
    deletes: Mutex<Vec<(String, String)>>,
}

impl FakeDestination {
    fn new(zone: &str, records: Vec<ZoneRecord>) -> Self {
        Self {
            live: sync_test_response(zone, records),
            deletes: Mutex::new(Vec::new()),
        }
    }

    fn delete_count(&self) -> usize {
        self.deletes.lock().unwrap().len()
    }
}

impl ZoneRead for FakeDestination {
    async fn list_zones(&self, _page: u32, _per_page: u32) -> Result<Value> {
        Ok(json!({ "response": { "zones": [] } }))
    }

    async fn list_records(
        &self,
        _domain: &str,
        _zone: Option<&str>,
        _options: ListRecordsOptions,
    ) -> Result<ListRecordsResponse> {
        Ok(self.live.clone())
    }
}

impl RecordWrite for FakeDestination {
    async fn add_record(
        &self,
        _zone: &str,
        _domain: &str,
        _ttl: u32,
        _record: &RecordData,
    ) -> Result<Value> {
        Ok(json!({ "status": "ok" }))
    }

    async fn delete_record(
        &self,
        _zone: &str,
        domain: &str,
        type_params: &[(&str, String)],
    ) -> Result<Value> {
        self.deletes
            .lock()
            .unwrap()
            .push((domain.to_string(), format!("{type_params:?}")));
        Ok(json!({ "status": "ok" }))
    }
}

const ZONE: &str = "example.com";

fn owned_a(fqdn: &str, ip: &str) -> OwnedRecord {
    OwnedRecord::from_planned(ZONE, &a(fqdn, ip))
}

/// A zone plan whose source set is `owned` but which writes nothing this run
/// (records present in source but not created by this job — e.g. unchanged).
fn plan_owning(owned: Vec<PlannedRecord>) -> ZonePlan {
    ZonePlan {
        zone: ZONE.to_string(),
        adds: vec![],
        deletes: vec![],
        unchanged: 0,
        untouched: 0,
        skipped: 0,
        owned,
    }
}

/// A zone plan that writes `recs` this run (they are both in source and added).
fn plan_written(recs: Vec<PlannedRecord>) -> ZonePlan {
    ZonePlan {
        zone: ZONE.to_string(),
        adds: recs.clone(),
        deletes: vec![],
        unchanged: 0,
        untouched: 0,
        skipped: 0,
        owned: recs,
    }
}

fn ownership<'a>(ledger: &'a dyn SyncLedger, prune: bool) -> Ownership<'a> {
    Ownership {
        job_key: "test-job".to_string(),
        ledger,
        prune,
    }
}

#[tokio::test]
async fn prune_removes_owned_record_gone_from_source() {
    // Previously owned www; source no longer has it (desired empty).
    let ledger = InMemoryLedger::with(vec![owned_a("www.example.com", "203.0.113.10")]);
    // Destination still holds the record at the value we recorded.
    let dest = FakeDestination::new(
        ZONE,
        vec![zone_record(
            "www",
            "A",
            3600,
            json!({ "ipAddress": "203.0.113.10" }),
        )],
    );
    let plans = vec![plan_owning(vec![])];

    let summary = reconcile_ownership(&dest, &plans, &ownership(&ledger, true), true)
        .await
        .unwrap();

    assert_eq!(summary.pruned, 1);
    assert_eq!(summary.skipped_drift, 0);
    assert_eq!(dest.delete_count(), 1);
    assert!(ledger.snapshot().is_empty(), "pruned record forgotten");
}

#[tokio::test]
async fn prune_skips_drifted_record() {
    let ledger = InMemoryLedger::with(vec![owned_a("www.example.com", "203.0.113.10")]);
    // Destination value has drifted from what we recorded — don't clobber it.
    let dest = FakeDestination::new(
        ZONE,
        vec![zone_record(
            "www",
            "A",
            3600,
            json!({ "ipAddress": "203.0.113.99" }),
        )],
    );
    let plans = vec![plan_owning(vec![])];

    let summary = reconcile_ownership(&dest, &plans, &ownership(&ledger, true), true)
        .await
        .unwrap();

    assert_eq!(summary.pruned, 0);
    assert_eq!(summary.skipped_drift, 1);
    assert_eq!(dest.delete_count(), 0, "drifted record left untouched");
    assert!(ledger.snapshot().is_empty(), "drifted record relinquished");
}

#[tokio::test]
async fn prune_keeps_records_still_in_source() {
    // www is still desired; api is gone — only api should be pruned.
    let ledger = InMemoryLedger::with(vec![
        owned_a("www.example.com", "203.0.113.10"),
        owned_a("api.example.com", "203.0.113.20"),
    ]);
    let dest = FakeDestination::new(
        ZONE,
        vec![
            zone_record("www", "A", 3600, json!({ "ipAddress": "203.0.113.10" })),
            zone_record("api", "A", 3600, json!({ "ipAddress": "203.0.113.20" })),
        ],
    );
    let plans = vec![plan_owning(vec![a("www.example.com", "203.0.113.10")])];

    let summary = reconcile_ownership(&dest, &plans, &ownership(&ledger, true), true)
        .await
        .unwrap();

    assert_eq!(summary.pruned, 1);
    let remaining = ledger.snapshot();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].fqdn, "www.example.com");
}

#[tokio::test]
async fn prune_dry_run_writes_nothing() {
    let ledger = InMemoryLedger::with(vec![owned_a("www.example.com", "203.0.113.10")]);
    let dest = FakeDestination::new(
        ZONE,
        vec![zone_record(
            "www",
            "A",
            3600,
            json!({ "ipAddress": "203.0.113.10" }),
        )],
    );
    let plans = vec![plan_owning(vec![])];

    let summary = reconcile_ownership(&dest, &plans, &ownership(&ledger, true), false)
        .await
        .unwrap();

    assert_eq!(summary.pruned, 1, "preview reports intended prune");
    assert_eq!(dest.delete_count(), 0, "dry-run deletes nothing");
    assert_eq!(ledger.snapshot().len(), 1, "dry-run leaves ledger intact");
}

#[tokio::test]
async fn prune_disabled_is_noop() {
    let ledger = InMemoryLedger::with(vec![owned_a("www.example.com", "203.0.113.10")]);
    let dest = FakeDestination::new(ZONE, vec![]);
    let plans = vec![plan_owning(vec![])];

    let summary = reconcile_ownership(&dest, &plans, &ownership(&ledger, false), true)
        .await
        .unwrap();

    assert_eq!(summary.pruned, 0);
    assert_eq!(dest.delete_count(), 0);
    assert_eq!(ledger.snapshot().len(), 1);
}

#[tokio::test]
async fn records_written_this_run_are_adopted() {
    // Empty ledger; www is actually written this run — it becomes owned.
    let ledger = InMemoryLedger::default();
    let dest = FakeDestination::new(
        ZONE,
        vec![zone_record(
            "www",
            "A",
            3600,
            json!({ "ipAddress": "203.0.113.10" }),
        )],
    );
    let plans = vec![plan_written(vec![a("www.example.com", "203.0.113.10")])];

    let summary = reconcile_ownership(&dest, &plans, &ownership(&ledger, true), true)
        .await
        .unwrap();

    assert_eq!(summary.pruned, 0);
    assert_eq!(dest.delete_count(), 0);
    let owned = ledger.snapshot();
    assert_eq!(owned.len(), 1, "written record adopted into ledger");
    assert_eq!(owned[0].fqdn, "www.example.com");
}

#[tokio::test]
async fn unchanged_records_not_written_are_not_adopted() {
    // www exists identically on both sides but this job never wrote it (adds
    // empty). Ownership must NOT adopt it, so it can never be pruned later.
    let ledger = InMemoryLedger::default();
    let dest = FakeDestination::new(
        ZONE,
        vec![zone_record(
            "www",
            "A",
            3600,
            json!({ "ipAddress": "203.0.113.10" }),
        )],
    );
    let plans = vec![plan_owning(vec![a("www.example.com", "203.0.113.10")])];

    let summary = reconcile_ownership(&dest, &plans, &ownership(&ledger, true), true)
        .await
        .unwrap();

    assert_eq!(summary.pruned, 0);
    assert_eq!(dest.delete_count(), 0);
    assert!(
        ledger.snapshot().is_empty(),
        "pre-existing record this job did not create is never adopted"
    );
}

#[tokio::test]
async fn teardown_removes_all_owned_and_clears_ledger() {
    let ledger = InMemoryLedger::with(vec![
        owned_a("www.example.com", "203.0.113.10"),
        owned_a("api.example.com", "203.0.113.20"),
    ]);
    let dest = FakeDestination::new(
        ZONE,
        vec![
            zone_record("www", "A", 3600, json!({ "ipAddress": "203.0.113.10" })),
            zone_record("api", "A", 3600, json!({ "ipAddress": "203.0.113.20" })),
        ],
    );

    let summary = teardown_ownership(&dest, &ownership(&ledger, true), true)
        .await
        .unwrap();

    assert_eq!(summary.pruned, 2);
    assert_eq!(dest.delete_count(), 2);
    assert!(
        ledger.snapshot().is_empty(),
        "ledger cleared after teardown"
    );
}

#[tokio::test]
async fn teardown_dry_run_previews_without_writing() {
    let ledger = InMemoryLedger::with(vec![owned_a("www.example.com", "203.0.113.10")]);
    let dest = FakeDestination::new(
        ZONE,
        vec![zone_record(
            "www",
            "A",
            3600,
            json!({ "ipAddress": "203.0.113.10" }),
        )],
    );

    let summary = teardown_ownership(&dest, &ownership(&ledger, true), false)
        .await
        .unwrap();

    assert_eq!(summary.pruned, 1);
    assert_eq!(dest.delete_count(), 0);
    assert_eq!(ledger.snapshot().len(), 1);
}
