//! Tests for `control_plane::sync`.

pub(crate) use super::*;
pub(crate) use crate::core::dns::responses::{ZoneInfo, ZoneRecord, ZoneRecords};
pub(crate) use rstest::rstest;
pub(crate) use serde_json::{Value, json};
pub(crate) use std::sync::{Arc, Mutex};

mod apply;
mod diff;

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
        self.calls
            .lock()
            .unwrap()
            .push((domain.to_string(), zone.map(ToOwned::to_owned), options));
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
        self.adds
            .lock()
            .unwrap()
            .push((zone.to_string(), domain.to_string(), ttl, record.clone()));
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

// ── SyncDiffOptions ────────────────────────────────────────────────────────

/// Create paired `FakeZoneRead` clients for a zone using the provided source and destination records.

///

/// The returned tuple is `(source_client, dest_client)`, each initialized with a `ListRecordsResponse` for

/// `zone` containing the corresponding records. Intended for use in unit tests that exercise planning and diffing.

///

/// # Examples

///

/// ```rust,ignore

/// let zone = "example.com";

/// let src = vec![/* ZoneRecord fixtures for source */];

/// let dst = vec![/* ZoneRecord fixtures for destination */];

/// let (source_client, dest_client) = make_source_dest_clients(zone, src, dst);

/// // `source_client` and `dest_client` can now be passed to functions that list records.

/// ```
fn make_source_dest_clients(
    zone: &str,
    src_records: Vec<ZoneRecord>,
    dst_records: Vec<ZoneRecord>,
) -> (FakeZoneRead, FakeZoneRead) {
    let source = FakeZoneRead::new(sync_test_response(zone, src_records));
    let dest = FakeZoneRead::new(sync_test_response(zone, dst_records));
    (source, dest)
}
