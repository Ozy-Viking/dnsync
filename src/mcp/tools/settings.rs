use rmcp::{ErrorData as McpError, model::*};

use crate::{
    control_plane::policy::Policy, core::dns::service::DnsService, core::dns::settings,
    mcp::helpers::run_json,
};

pub async fn handle_set_settings<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    settings: &serde_json::Value,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_set_settings",
        policy.check_write(),
        settings::set_settings(client, settings),
    )
    .await)
}

pub async fn handle_get_settings<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    show_secrets: bool,
) -> Result<CallToolResult, McpError> {
    Ok(
        run_json("dns_get_settings", policy.check_read(), async move {
            if show_secrets {
                settings::get_settings_unredacted(client).await
            } else {
                settings::get_settings(client).await
            }
        })
        .await,
    )
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::{
        control_plane::{
            config::VendorKind,
            policy::{Policy, PolicyRule},
        },
        core::{
            dns::{
                capabilities::VendorCapabilities,
                logs::{LogLine, LogsOptions, LogsRead},
                records::RecordData,
                responses::ListRecordsResponse,
                service::{
                    AccessListRead, AccessListWrite, CacheRead, CacheWrite, DnsVendor,
                    ListRecordsOptions, RecordWrite, SettingsRead, SettingsWrite, StatsRead,
                    ZoneExport, ZoneImport, ZoneOptionsRead, ZoneOptionsWrite, ZoneRead, ZoneWrite,
                },
            },
            error::Result,
            redaction::REDACTED_MARKER,
        },
    };

    /// Minimal test double for `handle_get_settings`.
    ///
    /// `FakeDnsService` exists only to satisfy the handler's `DnsService`
    /// bound in settings-handler tests. The tests should exercise only
    /// `SettingsRead::get_settings`, which returns a clone of the stored
    /// settings payload. All other DNS trait methods are intentionally stubbed
    /// with `unreachable!()` so an accidental call outside the settings path
    /// fails immediately.
    struct FakeDnsService {
        settings: Value,
    }

    impl DnsVendor for FakeDnsService {
        fn kind(&self) -> VendorKind {
            VendorKind::Technitium
        }

        fn capabilities(&self) -> VendorCapabilities {
            VendorCapabilities {
                settings: true,
                ..VendorCapabilities::default()
            }
        }
    }

    impl ZoneRead for FakeDnsService {
        async fn list_zones(&self, _page: u32, _per_page: u32) -> Result<Value> {
            unreachable!("not used by settings handler")
        }

        async fn list_records(
            &self,
            _domain: &str,
            _zone: Option<&str>,
            _options: ListRecordsOptions,
        ) -> Result<ListRecordsResponse> {
            unreachable!("not used by settings handler")
        }
    }

    impl ZoneWrite for FakeDnsService {
        async fn create_zone(&self, _zone: &str, _zone_type: &str) -> Result<Value> {
            unreachable!("not used by settings handler")
        }

        async fn delete_zone(&self, _zone: &str) -> Result<Value> {
            unreachable!("not used by settings handler")
        }

        async fn enable_zone(&self, _zone: &str) -> Result<Value> {
            unreachable!("not used by settings handler")
        }

        async fn disable_zone(&self, _zone: &str) -> Result<Value> {
            unreachable!("not used by settings handler")
        }
    }

    impl RecordWrite for FakeDnsService {
        async fn add_record(
            &self,
            _zone: &str,
            _domain: &str,
            _ttl: u32,
            _record: &RecordData,
        ) -> Result<Value> {
            unreachable!("not used by settings handler")
        }

        async fn delete_record(
            &self,
            _zone: &str,
            _domain: &str,
            _type_params: &[(&str, String)],
        ) -> Result<Value> {
            unreachable!("not used by settings handler")
        }
    }

    impl CacheRead for FakeDnsService {
        async fn list_cache(&self, _domain: &str) -> Result<Value> {
            unreachable!("not used by settings handler")
        }
    }

    impl CacheWrite for FakeDnsService {
        async fn delete_cache_zone(&self, _domain: &str) -> Result<Value> {
            unreachable!("not used by settings handler")
        }

        async fn flush_cache(&self) -> Result<Value> {
            unreachable!("not used by settings handler")
        }
    }

    impl AccessListRead for FakeDnsService {
        async fn list_blocked(&self) -> Result<Value> {
            unreachable!("not used by settings handler")
        }

        async fn list_allowed(&self) -> Result<Value> {
            unreachable!("not used by settings handler")
        }
    }

    impl AccessListWrite for FakeDnsService {
        async fn add_blocked(&self, _domain: &str) -> Result<Value> {
            unreachable!("not used by settings handler")
        }

        async fn delete_blocked(&self, _domain: &str) -> Result<Value> {
            unreachable!("not used by settings handler")
        }

        async fn add_allowed(&self, _domain: &str) -> Result<Value> {
            unreachable!("not used by settings handler")
        }

        async fn delete_allowed(&self, _domain: &str) -> Result<Value> {
            unreachable!("not used by settings handler")
        }
    }

    impl StatsRead for FakeDnsService {
        async fn get_stats(&self, _stats_type: &str) -> Result<Value> {
            unreachable!("not used by settings handler")
        }
    }

    impl ZoneImport for FakeDnsService {
        async fn import_zone_file(
            &self,
            _zone: &str,
            _file_name: String,
            _file_bytes: Vec<u8>,
            _overwrite: bool,
            _overwrite_zone: bool,
            _overwrite_soa_serial: bool,
        ) -> Result<Value> {
            unreachable!("not used by settings handler")
        }
    }

    impl ZoneExport for FakeDnsService {
        async fn export_zone_file(&self, _zone: &str) -> Result<String> {
            unreachable!("not used by settings handler")
        }
    }

    impl SettingsRead for FakeDnsService {
        async fn get_settings(&self) -> Result<Value> {
            Ok(self.settings.clone())
        }
    }

    impl SettingsWrite for FakeDnsService {
        async fn set_settings(&self, settings: &Value) -> Result<Value> {
            Ok(settings.clone())
        }
    }

    impl ZoneOptionsRead for FakeDnsService {
        async fn get_zone_options(&self, _zone: &str) -> Result<Value> {
            unreachable!("not used by settings handler")
        }
    }

    impl ZoneOptionsWrite for FakeDnsService {
        async fn set_zone_options(&self, _zone: &str, _options: &Value) -> Result<Value> {
            unreachable!("not used by settings handler")
        }
    }

    impl LogsRead for FakeDnsService {
        async fn get_logs(&self, _options: LogsOptions) -> Result<Vec<LogLine>> {
            unreachable!("not used by settings handler")
        }
    }

    #[tokio::test]
    async fn handle_get_settings_returns_redacted_json() {
        let client = FakeDnsService {
            settings: json!({
                "version": "13.4.1",
                "tsigKeys": [{ "sharedSecret": "actual-secret" }]
            }),
        };
        let policy = Policy::new([PolicyRule::Read], None);

        let result = handle_get_settings(&client, &policy, false).await.unwrap();
        let text = result.content[0]
            .as_text()
            .expect("settings result should be text JSON");
        let value: Value = serde_json::from_str(&text.text).unwrap();

        assert_eq!(value["version"], "13.4.1");
        assert_eq!(value["tsigKeys"][0]["sharedSecret"], REDACTED_MARKER);
    }

    #[tokio::test]
    async fn handle_get_settings_can_return_unredacted_json() {
        let client = FakeDnsService {
            settings: json!({
                "version": "13.4.1",
                "tsigKeys": [{ "sharedSecret": "actual-secret" }]
            }),
        };
        let policy = Policy::new([PolicyRule::Read], None);

        let result = handle_get_settings(&client, &policy, true).await.unwrap();
        let text = result.content[0]
            .as_text()
            .expect("settings result should be text JSON");
        let value: Value = serde_json::from_str(&text.text).unwrap();

        assert_eq!(value["version"], "13.4.1");
        assert_eq!(value["tsigKeys"][0]["sharedSecret"], "actual-secret");
    }

    #[tokio::test]
    async fn handle_set_settings_requires_write_policy() {
        let client = FakeDnsService {
            settings: json!({"version": "13.4.1"}),
        };
        let policy = Policy::new([PolicyRule::Read], None);

        let result = handle_set_settings(&client, &policy, &json!({"key": "val"}))
            .await
            .unwrap();

        assert_eq!(result.is_error, Some(true));
        let text = result.content[0].as_text().unwrap();
        assert!(text.text.contains("does not permit write operations"));
    }

    #[tokio::test]
    async fn handle_set_settings_succeeds_with_write_policy() {
        let client = FakeDnsService {
            settings: json!({"version": "13.4.1"}),
        };
        let policy = Policy::new([PolicyRule::Write], None);
        let payload = json!({"zoneTransferAllowedNetworks": ["10.0.0.0/8"]});

        let result = handle_set_settings(&client, &policy, &payload)
            .await
            .unwrap();

        assert_eq!(result.is_error, Some(false));
    }

    #[tokio::test]
    async fn handle_get_settings_denies_without_read_policy() {
        let client = FakeDnsService {
            settings: json!({
                "version": "13.4.1",
                "tsigKeys": [{ "sharedSecret": "actual-secret" }]
            }),
        };
        let policy = Policy::new([PolicyRule::Write], None);

        let result = handle_get_settings(&client, &policy, false).await.unwrap();
        let text = result.content[0]
            .as_text()
            .expect("policy denial should be returned as text JSON");

        assert_eq!(result.is_error, Some(true));
        assert!(!text.text.contains("actual-secret"));
        assert!(!text.text.contains("tsigKeys"));
        assert!(text.text.contains("does not permit read operations"));
    }
}
