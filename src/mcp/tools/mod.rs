pub mod access_lists;
pub mod cache;
pub mod logs;
pub mod records;
pub mod resolve;
pub mod settings;
pub mod stats;
pub mod sync;
pub mod zones;

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared in-memory DNS service double for MCP tool-handler tests.
    //!
    //! Implements every `DnsService` sub-trait, returning trivial `Ok` values.
    //! Combined with a restrictive [`Policy`], it lets each handler test assert
    //! the policy gate independently of any real vendor backend.

    use serde_json::{Value, json};

    use crate::control_plane::config::VendorKind;
    use crate::core::dns::capabilities::VendorCapabilities;
    use crate::core::dns::logs::{LogLine, LogsOptions, LogsRead};
    use crate::core::dns::records::RecordData;
    use crate::core::dns::responses::ListRecordsResponse;
    use crate::core::dns::service::*;
    use crate::core::error::Result;

    pub(crate) struct FakeService;

    impl DnsVendor for FakeService {
        fn kind(&self) -> VendorKind {
            VendorKind::Technitium
        }
        fn capabilities(&self) -> VendorCapabilities {
            // Advertise everything so capability gating never masks the
            // policy behaviour under test.
            VendorCapabilities {
                zones: true,
                records: true,
                cache: true,
                access_lists: true,
                settings: true,
                zone_import: true,
                zone_export: true,
                logs: true,
                zone_options: true,
                settings_write: true,
            }
        }
    }

    impl ZoneRead for FakeService {
        async fn list_zones(&self, _page: u32, _per_page: u32) -> Result<Value> {
            Ok(json!({"zones": []}))
        }
        async fn list_records(
            &self,
            _domain: &str,
            _zone: Option<&str>,
            _options: ListRecordsOptions,
        ) -> Result<ListRecordsResponse> {
            Ok(ListRecordsResponse { zones: vec![] })
        }
    }

    impl ZoneWrite for FakeService {
        async fn create_zone(&self, _zone: &str, _zone_type: &str) -> Result<Value> {
            Ok(json!({"ok": true}))
        }
        async fn delete_zone(&self, _zone: &str) -> Result<Value> {
            Ok(json!({"ok": true}))
        }
        async fn enable_zone(&self, _zone: &str) -> Result<Value> {
            Ok(json!({"ok": true}))
        }
        async fn disable_zone(&self, _zone: &str) -> Result<Value> {
            Ok(json!({"ok": true}))
        }
    }

    impl RecordWrite for FakeService {
        async fn add_record(
            &self,
            _zone: &str,
            _domain: &str,
            _ttl: u32,
            _record: &RecordData,
        ) -> Result<Value> {
            Ok(json!({"added": true}))
        }
        async fn delete_record(
            &self,
            _zone: &str,
            _domain: &str,
            _type_params: &[(&str, String)],
        ) -> Result<Value> {
            Ok(json!({"deleted": true}))
        }
    }

    impl CacheRead for FakeService {
        async fn list_cache(&self, _domain: &str) -> Result<Value> {
            Ok(json!({"entries": []}))
        }
    }
    impl CacheWrite for FakeService {
        async fn delete_cache_zone(&self, _domain: &str) -> Result<Value> {
            Ok(json!({"ok": true}))
        }
        async fn flush_cache(&self) -> Result<Value> {
            Ok(json!({"flushed": true}))
        }
    }

    impl StatsRead for FakeService {
        async fn get_stats(&self, _stats_type: &str) -> Result<Value> {
            Ok(json!({"queries": 0}))
        }
    }

    impl AccessListRead for FakeService {
        async fn list_blocked(&self) -> Result<Value> {
            Ok(json!({"blocked": []}))
        }
        async fn list_allowed(&self) -> Result<Value> {
            Ok(json!({"allowed": []}))
        }
    }
    impl AccessListWrite for FakeService {
        async fn add_blocked(&self, _domain: &str) -> Result<Value> {
            Ok(json!({"ok": true}))
        }
        async fn delete_blocked(&self, _domain: &str) -> Result<Value> {
            Ok(json!({"ok": true}))
        }
        async fn add_allowed(&self, _domain: &str) -> Result<Value> {
            Ok(json!({"ok": true}))
        }
        async fn delete_allowed(&self, _domain: &str) -> Result<Value> {
            Ok(json!({"ok": true}))
        }
    }

    impl ZoneImport for FakeService {
        async fn import_zone_file(
            &self,
            _zone: &str,
            _file_name: String,
            _file_bytes: Vec<u8>,
            _overwrite: bool,
            _overwrite_zone: bool,
            _overwrite_soa_serial: bool,
        ) -> Result<Value> {
            Ok(json!({"imported": true}))
        }
    }
    impl ZoneExport for FakeService {
        async fn export_zone_file(&self, _zone: &str) -> Result<String> {
            Ok(String::from("$ORIGIN example.com.\n"))
        }
    }

    impl SettingsRead for FakeService {
        async fn get_settings(&self) -> Result<Value> {
            Ok(json!({}))
        }
    }
    impl SettingsWrite for FakeService {
        async fn set_settings(&self, settings: &Value) -> Result<Value> {
            Ok(settings.clone())
        }
    }

    impl ZoneOptionsRead for FakeService {
        async fn get_zone_options(&self, zone: &str) -> Result<Value> {
            Ok(json!({"zone": zone}))
        }
    }
    impl ZoneOptionsWrite for FakeService {
        async fn set_zone_options(&self, _zone: &str, options: &Value) -> Result<Value> {
            Ok(options.clone())
        }
    }

    impl LogsRead for FakeService {
        async fn get_logs(&self, _options: LogsOptions) -> Result<Vec<LogLine>> {
            Ok(vec![])
        }
    }
}
