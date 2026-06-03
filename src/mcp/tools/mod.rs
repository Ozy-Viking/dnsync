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
        /// Exposes the DNS vendor kind for this fake service.
        ///
        /// # Examples
        ///
        /// ```
        /// let svc = test_support::FakeService;
        /// assert_eq!(svc.kind(), crate::mcp::tools::VendorKind::Technitium);
        /// ```
        fn kind(&self) -> VendorKind {
            VendorKind::Technitium
        }
        /// Report vendor capabilities with every capability flag enabled.
        ///
        /// This implementation advertises all available features so capability gating does
        /// not interfere with tests that exercise policy behavior.
        ///
        /// # Returns
        ///
        /// A `VendorCapabilities` value with every capability flag set to `true`.
        ///
        /// # Examples
        ///
        /// ```
        /// let svc = crate::test_support::FakeService;
        /// let caps = svc.capabilities();
        /// assert!(caps.zones && caps.records && caps.cache && caps.access_lists);
        /// assert!(caps.settings && caps.zone_import && caps.zone_export && caps.logs);
        /// assert!(caps.zone_options && caps.settings_write);
        /// ```
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
        /// Provide a stubbed response for listing zones used in tests.
        ///
        /// The method ignores pagination parameters and returns a JSON object with a `zones` array.
        ///
        /// # Examples
        ///
        /// ```
        /// use serde_json::Value;
        /// # use crate::test_support::FakeService;
        /// let svc = FakeService;
        /// let res: Value = futures::executor::block_on(svc.list_zones(1, 10)).unwrap();
        /// assert_eq!(res["zones"].as_array().unwrap().len(), 0);
        /// ```
        async fn list_zones(&self, _page: u32, _per_page: u32) -> Result<Value> {
            Ok(json!({"zones": []}))
        }
        /// Produce an empty `ListRecordsResponse` for tests.
        ///
        /// This test-only implementation ignores all inputs and always returns a response
        /// containing an empty `zones` vector.
        ///
        /// # Examples
        ///
        /// ```
        /// use futures::executor::block_on;
        /// let svc = crate::test_support::FakeService;
        /// let resp = block_on(svc.list_records("example.com", None, Default::default())).unwrap();
        /// assert!(resp.zones.is_empty());
        /// ```
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
        /// Creates a zone and returns a JSON value indicating success.
        ///
        /// # Examples
        ///
        /// ```no_run
        /// # use crate::test_support::FakeService;
        /// # async fn _example() {
        /// let svc = FakeService;
        /// let res = svc.create_zone("example.com", "master").await.unwrap();
        /// assert_eq!(res["ok"], true);
        /// # }
        /// ```
        ///
        /// # Returns
        ///
        /// `Ok(Value)` containing `{"ok": true}`.
        async fn create_zone(&self, _zone: &str, _zone_type: &str) -> Result<Value> {
            Ok(json!({"ok": true}))
        }
        /// Simulates deleting a DNS zone and returns a success object for tests.
        ///
        /// On success returns a JSON value confirming the operation.
        ///
        /// # Examples
        ///
        /// ```
        /// use serde_json::json;
        /// # use crate::test_support::FakeService;
        /// let svc = FakeService;
        /// let res = futures::executor::block_on(svc.delete_zone("example")).unwrap();
        /// assert_eq!(res, json!({"ok": true}));
        /// ```
        async fn delete_zone(&self, _zone: &str) -> Result<Value> {
            Ok(json!({"ok": true}))
        }
        /// Stub implementation that marks the given zone as enabled for tests.
        ///
        /// Returns a JSON object indicating success: `{"ok": true}`.
        ///
        /// # Examples
        ///
        /// ```
        /// use serde_json::json;
        /// use futures::executor::block_on;
        ///
        /// let svc = crate::test_support::FakeService;
        /// let res = block_on(svc.enable_zone("example.com")).unwrap();
        /// assert_eq!(res, json!({"ok": true}));
        /// ```
        async fn enable_zone(&self, _zone: &str) -> Result<Value> {
            Ok(json!({"ok": true}))
        }
        /// Disable a DNS zone and return an acknowledgement.
        ///
        /// Returns `Ok` with a JSON object that acknowledges the operation (`{"ok": true}`) on success.
        ///
        /// # Examples
        ///
        /// ```no_run
        /// use futures::executor::block_on;
        /// // `FakeService` is the test service provided by the test_support module.
        /// let svc = test_support::FakeService;
        /// let res = block_on(svc.disable_zone("example.com"));
        /// assert_eq!(res.unwrap(), serde_json::json!({"ok": true}));
        /// ```
        async fn disable_zone(&self, _zone: &str) -> Result<Value> {
            Ok(json!({"ok": true}))
        }
    }

    impl RecordWrite for FakeService {
        /// Simulates adding a DNS record for tests by returning a fixed success payload.
        ///
        /// Always returns a JSON object indicating the record was added: `{"added": true}`.
        ///
        /// # Examples
        ///
        /// ```
        /// use crate::mcp::tools::test_support::FakeService;
        /// use serde_json::json;
        /// use futures::executor::block_on;
        ///
        /// let svc = FakeService;
        /// // `RecordData` must be constructed according to the crate's definition; here we
        /// // assume a default instance for demonstration.
        /// let record = Default::default();
        /// let res = block_on(svc.add_record("example.com", "www", 3600, &record)).unwrap();
        /// assert_eq!(res, json!({"added": true}));
        /// ```
        async fn add_record(
            &self,
            _zone: &str,
            _domain: &str,
            _ttl: u32,
            _record: &RecordData,
        ) -> Result<Value> {
            Ok(json!({"added": true}))
        }
        /// Deletes a DNS record for the given domain within the specified zone.
        ///
        /// Returns a JSON value indicating whether the deletion succeeded.
        /// In this implementation the call always returns `{"deleted": true}`.
        ///
        /// # Examples
        ///
        /// ```
        /// use serde_json::json;
        /// use futures::executor::block_on;
        ///
        /// // `svc` is a `FakeService` instance provided by the test support module.
        /// let svc = crate::test_support::FakeService;
        /// let res = block_on(svc.delete_record("example.com", "www.example.com", &[])).unwrap();
        /// assert_eq!(res, json!({"deleted": true}));
        /// ```
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
        /// Produce a cache list response containing no entries.
        ///
        /// The `domain` parameter is ignored; the function always returns a JSON object with an empty `entries` array.
        ///
        /// # Returns
        ///
        /// A `serde_json::Value` equal to `{"entries": []}`.
        ///
        /// # Examples
        ///
        /// ```
        /// use serde_json::json;
        /// # async fn run() {
        /// let svc = crate::test_support::FakeService;
        /// let v = svc.list_cache("example.com").await.unwrap();
        /// assert_eq!(v, json!({"entries": []}));
        /// # }
        /// ```
        async fn list_cache(&self, _domain: &str) -> Result<Value> {
            Ok(json!({"entries": []}))
        }
    }
    impl CacheWrite for FakeService {
        /// Delete cached entries for the given domain from the cache service.
        ///
        /// Returns a JSON object indicating success.
        ///
        /// # Examples
        ///
        /// ```
        /// # use serde_json::json;
        /// # use crate::mcp::tools::test_support::FakeService;
        /// # tokio_test::block_on(async {
        /// let svc = FakeService;
        /// let res = svc.delete_cache_zone("example.com").await.unwrap();
        /// assert_eq!(res, json!({"ok": true}));
        /// # });
        /// ```
        async fn delete_cache_zone(&self, _domain: &str) -> Result<Value> {
            Ok(json!({"ok": true}))
        }
        /// Simulates flushing the DNS cache and reports success.
        ///
        /// Returns an `Ok(Value)` containing the JSON object `{"flushed": true}`.
        ///
        /// # Examples
        ///
        /// ```
        /// use serde_json::json;
        /// // `svc` is an instance of the test `FakeService`.
        /// let svc = crate::test_support::FakeService;
        /// let val = futures::executor::block_on(svc.flush_cache()).unwrap();
        /// assert_eq!(val, json!({"flushed": true}));
        /// ```
        async fn flush_cache(&self) -> Result<Value> {
            Ok(json!({"flushed": true}))
        }
    }

    impl StatsRead for FakeService {
        /// Returns a JSON object with a fixed `queries` count for testing.
        ///
        /// The `stats_type` argument is ignored by this fake implementation.
        ///
        /// # Parameters
        ///
        /// - `stats_type`: requested statistics category (ignored).
        ///
        /// # Returns
        ///
        /// A JSON object with the field `queries` set to `0`.
        ///
        /// # Examples
        ///
        /// ```
        /// use futures::executor::block_on;
        ///
        /// let svc = FakeService;
        /// let value = block_on(svc.get_stats("any")).unwrap();
        /// assert_eq!(value["queries"], 0);
        /// ```
        async fn get_stats(&self, _stats_type: &str) -> Result<Value> {
            Ok(json!({"queries": 0}))
        }
    }

    impl AccessListRead for FakeService {
        /// Returns a JSON value containing an empty list of blocked entries.
        ///
        /// The returned `Value` is an object with a single key `"blocked"` whose value is an empty array.
        ///
        /// # Examples
        ///
        /// ```
        /// # use serde_json::Value;
        /// # use futures::executor;
        /// # use crate::test_support::FakeService;
        /// # fn main() {
        /// let svc = FakeService;
        /// let val: Value = executor::block_on(svc.list_blocked()).unwrap();
        /// assert_eq!(val["blocked"], serde_json::json!([]));
        /// # }
        /// ```
        async fn list_blocked(&self) -> Result<Value> {
            Ok(json!({"blocked": []}))
        }
        /// Returns a JSON object containing an empty "allowed" list for use in tests.
        ///
        /// # Examples
        ///
        /// ```
        /// use serde_json::json;
        /// let svc = crate::test_support::FakeService;
        /// let val = futures::executor::block_on(svc.list_allowed()).unwrap();
        /// assert_eq!(val, json!({"allowed": []}));
        /// ```
        async fn list_allowed(&self) -> Result<Value> {
            Ok(json!({"allowed": []}))
        }
    }
    impl AccessListWrite for FakeService {
        /// Adds a domain to the blocked access list for the fake service.
        ///
        /// # Examples
        ///
        /// ```
        /// use crate::test_support::FakeService;
        /// let svc = FakeService;
        /// let res = futures::executor::block_on(svc.add_blocked("example.com")).unwrap();
        /// assert_eq!(res["ok"], true);
        /// ```
        ///
        /// # Returns
        ///
        /// An `Ok` JSON value `json!({"ok": true})`.
        async fn add_blocked(&self, _domain: &str) -> Result<Value> {
            Ok(json!({"ok": true}))
        }
        /// Removes a domain from the blocked access list in the fake service and reports success.
        ///
        /// This test stub always returns `{"ok": true}` as the operation result.
        ///
        /// # Examples
        ///
        /// ```
        /// use serde_json::json;
        /// use futures::executor::block_on;
        /// use crate::mcp::test_support::FakeService;
        ///
        /// let svc = FakeService;
        /// let res = block_on(svc.delete_blocked("example.com")).unwrap();
        /// assert_eq!(res, json!({"ok": true}));
        /// ```
        async fn delete_blocked(&self, _domain: &str) -> Result<Value> {
            Ok(json!({"ok": true}))
        }
        /// Adds a domain to the allowed access list (test stub).
        ///
        /// Returns a JSON value `{"ok": true}` on success.
        ///
        /// # Examples
        ///
        /// ```
        /// use crate::mcp::tools::test_support::FakeService;
        /// use serde_json::json;
        ///
        /// #[tokio::test]
        /// async fn add_allowed_example() {
        ///     let svc = FakeService;
        ///     let res = svc.add_allowed("example.com").await.unwrap();
        ///     assert_eq!(res, json!({"ok": true}));
        /// }
        /// ```
        async fn add_allowed(&self, _domain: &str) -> Result<Value> {
            Ok(json!({"ok": true}))
        }
        /// Simulates deleting a domain from the allowed access list for tests.
        ///
        /// Returns `Ok` containing a JSON object `{ "ok": true }` to indicate success.
        ///
        /// # Examples
        ///
        /// ```
        /// use serde_json::json;
        /// use crate::test_support::FakeService;
        /// let svc = FakeService;
        /// let res = futures::executor::block_on(svc.delete_allowed("example.com")).unwrap();
        /// assert_eq!(res, json!({"ok": true}));
        /// ```
        async fn delete_allowed(&self, _domain: &str) -> Result<Value> {
            Ok(json!({"ok": true}))
        }
    }

    impl ZoneImport for FakeService {
        /// Simulates importing a DNS zone file and reports success.
        ///
        /// This test stub ignores all parameters and always returns a JSON object indicating the import succeeded.
        ///
        /// # Examples
        ///
        /// ```
        /// use serde_json::Value;
        /// use futures::executor::block_on;
        ///
        /// let svc = FakeService;
        /// let res: Value = block_on(svc.import_zone_file("example.com", "zone.txt".into(), vec![], false, false, false)).unwrap();
        /// assert_eq!(res["imported"], true);
        /// ```
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
        /// Produce a minimal example zone file for the specified zone.
        ///
        /// # Examples
        ///
        /// ```
        /// let svc = test_support::FakeService;
        /// let zone_file = futures::executor::block_on(svc.export_zone_file("example.com")).unwrap();
        /// assert!(zone_file.starts_with("$ORIGIN"));
        /// ```
        async fn export_zone_file(&self, _zone: &str) -> Result<String> {
            Ok(String::from("$ORIGIN example.com.\n"))
        }
    }

    impl SettingsRead for FakeService {
        /// Returns an empty JSON object representing current settings.
        ///
        /// # Examples
        ///
        /// ```
        /// use serde_json::json;
        /// use futures::executor::block_on;
        /// // Construct the fake service and call the async method.
        /// let svc = crate::test_support::FakeService;
        /// let res = block_on(svc.get_settings()).unwrap();
        /// assert_eq!(res, json!({}));
        /// ```
        async fn get_settings(&self) -> Result<Value> {
            Ok(json!({}))
        }
    }
    impl SettingsWrite for FakeService {
        /// Stores the provided settings and returns the same JSON value.
        ///
        /// Returns the cloned `Value` that was passed in on success.
        ///
        /// # Examples
        ///
        /// ```
        /// use serde_json::json;
        /// use futures::executor::block_on;
        /// let svc = crate::test_support::FakeService;
        /// let settings = json!({"example": true});
        /// let result = block_on(svc.set_settings(&settings)).unwrap();
        /// assert_eq!(result, settings);
        /// ```
        async fn set_settings(&self, settings: &Value) -> Result<Value> {
            Ok(settings.clone())
        }
    }

    impl ZoneOptionsRead for FakeService {
        /// Provide zone options as a JSON object containing the requested zone.
        ///
        /// On success returns a JSON object with a single key `"zone"` whose value is the provided zone name.
        ///
        /// # Examples
        ///
        /// ```
        /// use serde_json::json;
        /// use futures::executor::block_on;
        ///
        /// let svc = crate::test_support::FakeService;
        /// let val = block_on(svc.get_zone_options("example.com")).unwrap();
        /// assert_eq!(val, json!({"zone": "example.com"}));
        /// ```
        async fn get_zone_options(&self, zone: &str) -> Result<Value> {
            Ok(json!({"zone": zone}))
        }
    }
    impl ZoneOptionsWrite for FakeService {
        /// Store zone-specific options and return the stored options.
        ///
        /// Sets the options for the given zone and returns the options that were stored.
        ///
        /// # Parameters
        ///
        /// - `zone`: the zone name to set options for.
        /// - `options`: JSON object containing zone option values to store.
        ///
        /// # Returns
        ///
        /// The `options` value that was stored, returned as a cloned JSON `Value`.
        ///
        /// # Examples
        ///
        /// ```
        /// # use serde_json::json;
        /// # use crate::test_support::FakeService;
        /// #[tokio::test]
        /// async fn example_set_zone_options() {
        ///     let svc = FakeService;
        ///     let opts = json!({"ttl": 3600});
        ///     let res = svc.set_zone_options("example.com", &opts).await.unwrap();
        ///     assert_eq!(res, opts);
        /// }
        /// ```
        async fn set_zone_options(&self, _zone: &str, options: &Value) -> Result<Value> {
            Ok(options.clone())
        }
    }

    impl LogsRead for FakeService {
        /// Retrieve log lines that match the supplied options.
        ///
        /// # Returns
        ///
        /// A `Vec<LogLine>` containing the matching log entries; empty if there are no matches.
        ///
        /// # Examples
        ///
        /// ```
        /// // Demonstrates the simplest call pattern for `get_logs`.
        /// use crate::mcp::tools::test_support::FakeService;
        /// use crate::mcp::logs::LogsOptions;
        ///
        /// // This example runs the async call synchronously for demonstration.
        /// let svc = FakeService;
        /// let opts = LogsOptions::default();
        /// let logs = futures::executor::block_on(svc.get_logs(opts)).unwrap();
        /// assert!(logs.is_empty());
        /// ```
        async fn get_logs(&self, _options: LogsOptions) -> Result<Vec<LogLine>> {
            Ok(vec![])
        }
    }
}
