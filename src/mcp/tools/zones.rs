use rmcp::{ErrorData as McpError, model::*};

use crate::{
    control_plane::policy::Policy,
    core::dns::service::DnsService,
    core::dns::zones,
    mcp::{
        helpers::{run_json, run_text},
        params::*,
    },
};

pub async fn handle_list_zones<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ListZonesParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_list_zones",
        policy.check_read(),
        zones::list_zones(
            client,
            p.page_number.unwrap_or(1),
            p.zones_per_page.unwrap_or(50),
        ),
    )
    .await)
}

pub async fn handle_create_zone<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: CreateZoneParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_create_zone",
        policy.check_write().and(policy.check_zone(&p.zone)),
        zones::create_zone(client, &p.zone, &p.zone_type),
    )
    .await)
}

pub async fn handle_delete_zone<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ZoneParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_delete_zone",
        policy.check_delete().and(policy.check_zone(&p.zone)),
        zones::delete_zone(client, &p.zone),
    )
    .await)
}

pub async fn handle_enable_zone<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ZoneParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_enable_zone",
        policy.check_write().and(policy.check_zone(&p.zone)),
        zones::enable_zone(client, &p.zone),
    )
    .await)
}

pub async fn handle_disable_zone<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ZoneParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_disable_zone",
        policy.check_write().and(policy.check_zone(&p.zone)),
        zones::disable_zone(client, &p.zone),
    )
    .await)
}

pub async fn handle_import_zone_file<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ImportZoneFileParams,
) -> Result<CallToolResult, McpError> {
    let file_name = p.file_name.unwrap_or_else(|| format!("{}.txt", p.zone));
    Ok(run_json(
        "dns_import_zone_file",
        policy.check_write().and(policy.check_zone(&p.zone)),
        zones::import_zone_file(
            client,
            &p.zone,
            file_name,
            p.content.into_bytes(),
            p.options.overwrite,
            p.options.overwrite_zone,
            p.options.overwrite_soa_serial,
        ),
    )
    .await)
}

pub async fn handle_export_zone_file<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ExportZoneFileParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_text(
        "dns_export_zone_file",
        policy.check_read().and(policy.check_zone(&p.zone)),
        zones::export_zone_file(client, &p.zone),
    )
    .await)
}

pub async fn handle_get_zone_options<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: ZoneParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_get_zone_options",
        policy.check_read().and(policy.check_zone(&p.zone)),
        zones::get_zone_options(client, &p.zone),
    )
    .await)
}

pub async fn handle_set_zone_options<C: DnsService + Send + Sync>(
    client: &C,
    policy: &Policy,
    p: SetZoneOptionsParams,
) -> Result<CallToolResult, McpError> {
    Ok(run_json(
        "dns_set_zone_options",
        policy.check_write().and(policy.check_zone(&p.zone)),
        zones::set_zone_options(client, &p.zone, &p.options),
    )
    .await)
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
        },
    };

    struct FakeZoneService;

    impl DnsVendor for FakeZoneService {
        fn kind(&self) -> VendorKind {
            VendorKind::Technitium
        }
        fn capabilities(&self) -> VendorCapabilities {
            VendorCapabilities {
                zones: true,
                zone_options: true,
                ..VendorCapabilities::default()
            }
        }
    }

    impl ZoneRead for FakeZoneService {
        async fn list_zones(&self, _page: u32, _per_page: u32) -> Result<Value> {
            unreachable!()
        }
        async fn list_records(
            &self,
            _domain: &str,
            _zone: Option<&str>,
            _options: ListRecordsOptions,
        ) -> Result<ListRecordsResponse> {
            unreachable!()
        }
    }
    impl ZoneWrite for FakeZoneService {
        async fn create_zone(&self, _zone: &str, _zone_type: &str) -> Result<Value> {
            unreachable!()
        }
        async fn delete_zone(&self, _zone: &str) -> Result<Value> {
            unreachable!()
        }
        async fn enable_zone(&self, _zone: &str) -> Result<Value> {
            unreachable!()
        }
        async fn disable_zone(&self, _zone: &str) -> Result<Value> {
            unreachable!()
        }
    }
    impl RecordWrite for FakeZoneService {
        async fn add_record(
            &self,
            _zone: &str,
            _domain: &str,
            _ttl: u32,
            _record: &RecordData,
        ) -> Result<Value> {
            unreachable!()
        }
        async fn delete_record(
            &self,
            _zone: &str,
            _domain: &str,
            _type_params: &[(&str, String)],
        ) -> Result<Value> {
            unreachable!()
        }
    }
    impl CacheRead for FakeZoneService {
        async fn list_cache(&self, _domain: &str) -> Result<Value> {
            unreachable!()
        }
    }
    impl CacheWrite for FakeZoneService {
        async fn delete_cache_zone(&self, _domain: &str) -> Result<Value> {
            unreachable!()
        }
        async fn flush_cache(&self) -> Result<Value> {
            unreachable!()
        }
    }
    impl StatsRead for FakeZoneService {
        async fn get_stats(&self, _stats_type: &str) -> Result<Value> {
            unreachable!()
        }
    }
    impl AccessListRead for FakeZoneService {
        async fn list_blocked(&self) -> Result<Value> {
            unreachable!()
        }
        async fn list_allowed(&self) -> Result<Value> {
            unreachable!()
        }
    }
    impl AccessListWrite for FakeZoneService {
        async fn add_blocked(&self, _domain: &str) -> Result<Value> {
            unreachable!()
        }
        async fn delete_blocked(&self, _domain: &str) -> Result<Value> {
            unreachable!()
        }
        async fn add_allowed(&self, _domain: &str) -> Result<Value> {
            unreachable!()
        }
        async fn delete_allowed(&self, _domain: &str) -> Result<Value> {
            unreachable!()
        }
    }
    impl ZoneImport for FakeZoneService {
        async fn import_zone_file(
            &self,
            _zone: &str,
            _file_name: String,
            _file_bytes: Vec<u8>,
            _overwrite: bool,
            _overwrite_zone: bool,
            _overwrite_soa_serial: bool,
        ) -> Result<Value> {
            unreachable!()
        }
    }
    impl ZoneExport for FakeZoneService {
        async fn export_zone_file(&self, _zone: &str) -> Result<String> {
            unreachable!()
        }
    }
    impl SettingsRead for FakeZoneService {
        async fn get_settings(&self) -> Result<Value> {
            unreachable!()
        }
    }
    impl SettingsWrite for FakeZoneService {
        async fn set_settings(&self, _settings: &Value) -> Result<Value> {
            unreachable!()
        }
    }
    impl ZoneOptionsRead for FakeZoneService {
        async fn get_zone_options(&self, zone: &str) -> Result<Value> {
            Ok(json!({"zone": zone, "type": "Primary"}))
        }
    }
    impl ZoneOptionsWrite for FakeZoneService {
        async fn set_zone_options(&self, _zone: &str, options: &Value) -> Result<Value> {
            Ok(options.clone())
        }
    }
    impl LogsRead for FakeZoneService {
        async fn get_logs(&self, _options: LogsOptions) -> Result<Vec<LogLine>> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn handle_get_zone_options_requires_read_policy() {
        let client = FakeZoneService;
        let policy = Policy::new([PolicyRule::Write], None);
        let p = ZoneParams {
            server_id: "s".into(),
            zone: "example.com".into(),
        };
        let result = handle_get_zone_options(&client, &policy, p).await.unwrap();
        assert_eq!(result.is_error, Some(true));
        let text = result.content[0].as_text().unwrap();
        assert!(text.text.contains("does not permit read operations"));
    }

    #[tokio::test]
    async fn handle_get_zone_options_succeeds_with_read_policy() {
        let client = FakeZoneService;
        let policy = Policy::new([PolicyRule::Read], None);
        let p = ZoneParams {
            server_id: "s".into(),
            zone: "example.com".into(),
        };
        let result = handle_get_zone_options(&client, &policy, p).await.unwrap();
        assert_eq!(result.is_error, Some(false));
    }

    #[tokio::test]
    async fn handle_set_zone_options_requires_write_policy() {
        let client = FakeZoneService;
        let policy = Policy::new([PolicyRule::Read], None);
        let p = SetZoneOptionsParams {
            server_id: "s".into(),
            zone: "example.com".into(),
            options: json!({"type": "Secondary"}),
        };
        let result = handle_set_zone_options(&client, &policy, p).await.unwrap();
        assert_eq!(result.is_error, Some(true));
        let text = result.content[0].as_text().unwrap();
        assert!(text.text.contains("does not permit write operations"));
    }

    #[tokio::test]
    async fn handle_set_zone_options_succeeds_with_write_policy() {
        let client = FakeZoneService;
        let policy = Policy::new([PolicyRule::Write], None);
        let p = SetZoneOptionsParams {
            server_id: "s".into(),
            zone: "example.com".into(),
            options: json!({"type": "Secondary"}),
        };
        let result = handle_set_zone_options(&client, &policy, p).await.unwrap();
        assert_eq!(result.is_error, Some(false));
    }
}
