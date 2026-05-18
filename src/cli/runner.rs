use serde_json::Value;

use crate::{
    cli::{AllowedCmd, BlockedCmd, CacheCmd, Command, RecordCmd, ZoneCmd, records},
    core::dns::responses::ListRecordsResponse,
    core::dns::service::{DnsService, ListRecordsOptions, ZoneRead},
    core::error::{Error, Result},
};

/// Build the fully-qualified domain name from a possibly-relative label and an optional zone.
///
/// Examples:
/// - `("huly", Some("hankin.io"))` → `"huly.hankin.io"`
/// - `("huly.hankin.io", Some("hankin.io"))` → `"huly.hankin.io"` (already qualified)
/// - `("@", Some("hankin.io"))` → `"hankin.io"` (zone apex)
/// - `("huly.hankin.io", None)` → `"huly.hankin.io"` (passed through)
pub fn resolve_fqdn(domain: &str, zone: Option<&str>) -> String {
    let Some(zone) = zone else {
        return domain.trim_end_matches('.').to_string();
    };
    let domain = domain.trim_end_matches('.');
    let zone = zone.trim_end_matches('.');
    if domain == "@" {
        return zone.to_string();
    }
    let d_lower = domain.to_lowercase();
    let z_lower = zone.to_lowercase();
    if d_lower == z_lower || d_lower.ends_with(&format!(".{z_lower}")) {
        domain.to_string()
    } else {
        format!("{domain}.{zone}")
    }
}

/// Strip the leftmost DNS label to get the likely parent zone name.
/// Returns `None` for single-label names (e.g. `"hankin"`).
pub fn infer_zone(fqdn: &str) -> Option<String> {
    let fqdn = fqdn.trim_end_matches('.');
    fqdn.find('.').map(|pos| fqdn[pos + 1..].to_string())
}

/// Extract zone/domain names from a `list_zones` response.
/// Handles the three known vendor formats:
/// - Technitium: `{"response": {"zones": [{"name": "..."}]}}`
/// - Pangolin:   `{"domains": [{"baseDomain": "..."}]}`
/// - Cloudflare: `[{"name": "..."}]`  (array at root after envelope unwrap)
pub fn extract_zone_names(value: &Value) -> Vec<String> {
    // Technitium
    if let Some(arr) = value
        .get("response")
        .and_then(|r| r.get("zones"))
        .and_then(|z| z.as_array())
    {
        let names: Vec<_> = arr
            .iter()
            .filter_map(|z| z.get("name").and_then(|n| n.as_str()).map(str::to_string))
            .collect();
        if !names.is_empty() {
            return names;
        }
    }
    // Pangolin
    if let Some(arr) = value.get("domains").and_then(|d| d.as_array()) {
        let names: Vec<_> = arr
            .iter()
            .filter_map(|d| d.get("baseDomain").and_then(|n| n.as_str()).map(str::to_string))
            .collect();
        if !names.is_empty() {
            return names;
        }
    }
    // Cloudflare (array at root)
    if let Some(arr) = value.as_array() {
        let names: Vec<_> = arr
            .iter()
            .filter_map(|z| z.get("name").and_then(|n| n.as_str()).map(str::to_string))
            .collect();
        if !names.is_empty() {
            return names;
        }
    }
    Vec::new()
}

/// Query every hosted zone for records whose DNS name equals `label`.
/// When `all_subdomains` is true, records beneath `label` in each zone are also included.
/// Zones where the label does not exist are silently skipped.
pub async fn search_bare_label_in_zones<C: ZoneRead + Send + Sync>(
    client: &C,
    label: &str,
    all_subdomains: bool,
    options: ListRecordsOptions,
) -> Result<ListRecordsResponse> {
    let zones_value = client.list_zones(1, 1000).await?;
    let zone_names = extract_zone_names(&zones_value);

    let mut all_zone_records = Vec::new();
    for zone_name in &zone_names {
        let target_fqdn = format!("{label}.{zone_name}");
        if all_subdomains {
            let mut resp = match client
                .list_records(zone_name, Some(zone_name.as_str()), options)
                .await
            {
                Ok(r) => r,
                Err(_) => continue,
            };
            filter_records_by_domain(&mut resp, &target_fqdn, true);
            all_zone_records.extend(resp.zones);
        } else {
            match client
                .list_records(&target_fqdn, Some(zone_name.as_str()), options)
                .await
            {
                Ok(resp) => all_zone_records.extend(resp.zones),
                Err(_) => {} // label doesn't exist in this zone
            }
        }
    }
    Ok(ListRecordsResponse { zones: all_zone_records })
}

/// Retain only records whose FQDN matches `target_fqdn` (or, when `all_subdomains`
/// is true, any record at or under `target_fqdn`). Zones that become empty are dropped.
pub fn filter_records_by_domain(
    response: &mut ListRecordsResponse,
    target_fqdn: &str,
    all_subdomains: bool,
) {
    let target = target_fqdn.trim_end_matches('.').to_lowercase();
    for zone_records in &mut response.zones {
        let zone = zone_records.zone.name.to_lowercase();
        zone_records.records.retain(|r| {
            let record_fqdn = if r.name == "@" {
                zone.clone()
            } else {
                format!("{}.{}", r.name.to_lowercase(), zone)
            };
            if all_subdomains {
                record_fqdn == target || record_fqdn.ends_with(&format!(".{target}"))
            } else {
                record_fqdn == target
            }
        });
    }
    response.zones.retain(|z| !z.records.is_empty());
}

#[tracing::instrument(skip(client, command), fields(command = tracing::field::Empty))]
pub async fn run<C: DnsService>(client: &C, command: Command) -> Result<()> {
    let cmd_name = match &command {
        Command::Zone(z) => match z {
            ZoneCmd::List { .. } => "zone list",
            ZoneCmd::Create { .. } => "zone create",
            ZoneCmd::Delete { .. } => "zone delete",
            ZoneCmd::Enable { .. } => "zone enable",
            ZoneCmd::Disable { .. } => "zone disable",
            ZoneCmd::Import { .. } => "zone import",
        },
        Command::Record(r) => match r {
            RecordCmd::List { .. } => "record list",
            RecordCmd::Add { .. } => "record add",
            RecordCmd::Delete { .. } => "record delete",
        },
        Command::Cache(c) => match c {
            CacheCmd::List { .. } => "cache list",
            CacheCmd::Delete { .. } => "cache delete",
            CacheCmd::Flush => "cache flush",
        },
        Command::Stats { .. } => "stats",
        Command::Blocked(b) => match b {
            BlockedCmd::List => "blocked list",
            BlockedCmd::Add { .. } => "blocked add",
            BlockedCmd::Delete { .. } => "blocked delete",
        },
        Command::Allowed(a) => match a {
            AllowedCmd::List => "allowed list",
            AllowedCmd::Add { .. } => "allowed add",
            AllowedCmd::Delete { .. } => "allowed delete",
        },
        Command::Settings => "settings",
        Command::Mcp | Command::Config(_) => unreachable!(),
    };
    tracing::Span::current().record("command", cmd_name);
    tracing::info!(command = cmd_name, "running CLI command");
    // Record list has its own output format logic — handle it before the
    // generic JSON path.
    if let Command::Record(RecordCmd::List {
        domain,
        zone,
        all_subdomains,
        use_local_ip,
        json,
        servers: _,
    }) = command
    {
        let effective_fqdn = resolve_fqdn(&domain, zone.as_deref());
        let is_bare_label = zone.is_none() && !effective_fqdn.contains('.');
        let options = ListRecordsOptions { use_local_ip, all_subdomains };

        let response = if is_bare_label {
            // No zone given and no dots — search every hosted zone for this label.
            search_bare_label_in_zones(client, &effective_fqdn, all_subdomains, options).await?
        } else {
            // For --all-subdomains we need every record in the zone, so we query
            // the zone apex and let filter_records_by_domain narrow the results.
            let (query_domain, query_zone) = if all_subdomains {
                // Use the zone from --zone if given, otherwise try to infer it by
                // stripping the leftmost label.  If inference would produce a TLD
                // (no dot in the result), the effective_fqdn IS the zone apex, so
                // use it directly — e.g. `example.com --all-subdomains` stays as
                // `example.com`, not the bogus `com`.
                let zone_name = zone
                    .clone()
                    .or_else(|| infer_zone(&effective_fqdn).filter(|z| z.contains('.')))
                    .unwrap_or_else(|| effective_fqdn.clone());
                (zone_name.clone(), Some(zone_name))
            } else {
                (effective_fqdn.clone(), zone)
            };

            let mut resp = client
                .list_records(&query_domain, query_zone.as_deref(), options)
                .await?;

            if all_subdomains {
                filter_records_by_domain(&mut resp, &effective_fqdn, true);
            }
            resp
        };

        if json {
            let value = serde_json::to_value(&response).map_err(|e| Error::parse(e.to_string()))?;
            print_result(&value)?;
        } else {
            records::print_records_table(&response);
        }
        return Ok(());
    }

    let result = match command {
        Command::Mcp => unreachable!("handled in main"),
        Command::Config(_) => unreachable!("handled in main"),
        Command::Record(RecordCmd::List { .. }) => unreachable!("handled above"),

        Command::Zone(cmd) => match cmd {
            ZoneCmd::List { page, per_page } => client.list_zones(page, per_page).await?,
            ZoneCmd::Create { zone, r#type } => client.create_zone(&zone, &r#type).await?,
            ZoneCmd::Delete { zone } => client.delete_zone(&zone).await?,
            ZoneCmd::Enable { zone } => client.enable_zone(&zone).await?,
            ZoneCmd::Disable { zone } => client.disable_zone(&zone).await?,
            ZoneCmd::Import {
                zone,
                file,
                overwrite,
                overwrite_zone,
                overwrite_soa_serial,
            } => {
                let file_name = file
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "zone.txt".into());
                let file_bytes = std::fs::read(&file)
                    .map_err(|e| Error::io(format!("reading zone file '{}'", file.display()), e))?;
                client
                    .import_zone_file(
                        &zone,
                        file_name,
                        file_bytes,
                        overwrite,
                        overwrite_zone,
                        overwrite_soa_serial,
                    )
                    .await?
            }
        },

        Command::Record(cmd) => match cmd {
            RecordCmd::List { .. } => unreachable!("handled above"),
            RecordCmd::Add {
                zone,
                domain,
                ttl,
                record,
            } => {
                let record_data = record.into();
                client.add_record(&zone, &domain, ttl, &record_data).await?
            }
            RecordCmd::Delete {
                zone,
                domain,
                record,
            } => {
                let type_params = record.to_api_params();
                client.delete_record(&zone, &domain, &type_params).await?
            }
        },

        Command::Cache(cmd) => match cmd {
            CacheCmd::List { domain } => client.list_cache(&domain).await?,
            CacheCmd::Delete { domain } => client.delete_cache_zone(&domain).await?,
            CacheCmd::Flush => client.flush_cache().await?,
        },

        Command::Stats { r#type } => client.get_stats(&r#type).await?,

        Command::Blocked(cmd) => match cmd {
            BlockedCmd::List => client.list_blocked().await?,
            BlockedCmd::Add { domain } => client.add_blocked(&domain).await?,
            BlockedCmd::Delete { domain } => client.delete_blocked(&domain).await?,
        },

        Command::Allowed(cmd) => match cmd {
            AllowedCmd::List => client.list_allowed().await?,
            AllowedCmd::Add { domain } => client.add_allowed(&domain).await?,
            AllowedCmd::Delete { domain } => client.delete_allowed(&domain).await?,
        },

        Command::Settings => client.get_settings().await?,
    };

    print_result(&result)?;
    Ok(())
}

fn print_result(value: &Value) -> Result<()> {
    let display = value.get("response").unwrap_or(value);
    let out = serde_json::to_string_pretty(display)
        .map_err(|e| Error::parse(format!("could not serialise response: {e}")))?;
    println!("{out}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::dns::responses::{ListRecordsResponse, ZoneInfo, ZoneRecord, ZoneRecords};
    use serde_json::json;

    fn make_zone(name: &str) -> ZoneInfo {
        ZoneInfo { name: name.to_string(), zone_type: "Primary".to_string(), disabled: false, dnssec_status: None }
    }

    fn make_record(name: &str) -> ZoneRecord {
        ZoneRecord {
            name: name.to_string(),
            record_type: "A".to_string(),
            ttl: 300,
            disabled: false,
            comments: String::new(),
            expiry_ttl: 0,
            data: json!({"ipAddress": "1.2.3.4"}),
            parsed: None,
        }
    }

    // ── infer_zone TLD guard ─────────────────────────────────────────────────

    #[test]
    fn infer_zone_tld_falls_back_to_apex_for_all_subdomains() {
        // example.com → infer_zone gives "com" (no dot) → should not be used as zone
        let z = infer_zone("example.com");
        let filtered = z.filter(|z| z.contains('.'));
        assert!(filtered.is_none(), "TLD result should be filtered out");
    }

    #[test]
    fn infer_zone_subdomain_is_usable_as_zone() {
        let z = infer_zone("huly.hankin.io");
        let filtered = z.filter(|z| z.contains('.'));
        assert_eq!(filtered.as_deref(), Some("hankin.io"));
    }

    // ── extract_zone_names ────────────────────────────────────────────────────

    #[test]
    fn extract_technitium_zones() {
        let v = json!({"response": {"zones": [{"name": "hankin.io"}, {"name": "example.com"}]}});
        assert_eq!(extract_zone_names(&v), vec!["hankin.io", "example.com"]);
    }

    #[test]
    fn extract_pangolin_zones() {
        let v = json!({"domains": [{"baseDomain": "app.hankin.io"}, {"baseDomain": "other.io"}]});
        assert_eq!(extract_zone_names(&v), vec!["app.hankin.io", "other.io"]);
    }

    #[test]
    fn extract_cloudflare_zones() {
        let v = json!([{"id": "abc", "name": "hankin.io"}, {"id": "def", "name": "example.com"}]);
        assert_eq!(extract_zone_names(&v), vec!["hankin.io", "example.com"]);
    }

    #[test]
    fn extract_zone_names_returns_empty_for_unknown_format() {
        assert!(extract_zone_names(&json!({"other": "stuff"})).is_empty());
    }

    // ── resolve_fqdn ──────────────────────────────────────────────────────────

    #[test]
    fn relative_label_is_qualified_with_zone() {
        assert_eq!(resolve_fqdn("huly", Some("hankin.io")), "huly.hankin.io");
    }

    #[test]
    fn already_qualified_fqdn_is_unchanged() {
        assert_eq!(resolve_fqdn("huly.hankin.io", Some("hankin.io")), "huly.hankin.io");
    }

    #[test]
    fn at_symbol_resolves_to_zone_apex() {
        assert_eq!(resolve_fqdn("@", Some("hankin.io")), "hankin.io");
    }

    #[test]
    fn no_zone_passes_domain_through() {
        assert_eq!(resolve_fqdn("huly.hankin.io", None), "huly.hankin.io");
    }

    #[test]
    fn domain_equal_to_zone_is_unchanged() {
        assert_eq!(resolve_fqdn("hankin.io", Some("hankin.io")), "hankin.io");
    }

    #[test]
    fn trailing_dots_are_stripped() {
        assert_eq!(resolve_fqdn("huly.", Some("hankin.io.")), "huly.hankin.io");
    }

    #[test]
    fn case_insensitive_fqdn_detection() {
        assert_eq!(resolve_fqdn("Huly.Hankin.IO", Some("hankin.io")), "Huly.Hankin.IO");
    }

    // ── infer_zone ────────────────────────────────────────────────────────────

    #[test]
    fn infer_zone_strips_first_label() {
        assert_eq!(infer_zone("huly.hankin.io"), Some("hankin.io".to_string()));
    }

    #[test]
    fn infer_zone_returns_none_for_single_label() {
        assert_eq!(infer_zone("hankin"), None);
    }

    #[test]
    fn infer_zone_handles_trailing_dot() {
        assert_eq!(infer_zone("huly.hankin.io."), Some("hankin.io".to_string()));
    }

    // ── filter_records_by_domain ─────────────────────────────────────────────

    #[test]
    fn filter_exact_keeps_matching_record() {
        let mut resp = ListRecordsResponse {
            zones: vec![ZoneRecords {
                zone: make_zone("hankin.io"),
                records: vec![make_record("huly"), make_record("other")],
            }],
        };
        filter_records_by_domain(&mut resp, "huly.hankin.io", false);
        assert_eq!(resp.zones[0].records.len(), 1);
        assert_eq!(resp.zones[0].records[0].name, "huly");
    }

    #[test]
    fn filter_exact_removes_non_matching_record() {
        let mut resp = ListRecordsResponse {
            zones: vec![ZoneRecords {
                zone: make_zone("hankin.io"),
                records: vec![make_record("other")],
            }],
        };
        filter_records_by_domain(&mut resp, "huly.hankin.io", false);
        assert!(resp.zones.is_empty());
    }

    #[test]
    fn filter_all_subdomains_includes_target_and_children() {
        let mut resp = ListRecordsResponse {
            zones: vec![ZoneRecords {
                zone: make_zone("hankin.io"),
                records: vec![
                    make_record("huly"),
                    make_record("sub.huly"),
                    make_record("other"),
                    make_record("@"),
                ],
            }],
        };
        filter_records_by_domain(&mut resp, "huly.hankin.io", true);
        let names: Vec<&str> = resp.zones[0].records.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"huly"), "should include huly");
        assert!(names.contains(&"sub.huly"), "should include sub.huly");
        assert!(!names.contains(&"other"), "should exclude other");
        assert!(!names.contains(&"@"), "should exclude zone apex");
    }

    #[test]
    fn filter_at_record_matches_zone_apex() {
        let mut resp = ListRecordsResponse {
            zones: vec![ZoneRecords {
                zone: make_zone("hankin.io"),
                records: vec![make_record("@"), make_record("www")],
            }],
        };
        filter_records_by_domain(&mut resp, "hankin.io", false);
        assert_eq!(resp.zones[0].records.len(), 1);
        assert_eq!(resp.zones[0].records[0].name, "@");
    }
}
