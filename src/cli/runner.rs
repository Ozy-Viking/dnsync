use miette::Report;
use rmcp::ServiceExt;
use serde_json::Value;

use crate::{
    cli::{self, AllowedCmd, BlockedCmd, CacheCmd, Command, RecordCmd, ZoneCmd, records},
    control_plane::{
        app,
        config::{self as config, AppConfig, McpPermissions},
        policy::Policy,
    },
    core::{
        dns::service::{DnsService, ListRecordsOptions},
        error::{Error, Result},
    },
    mcp::server::DnsServer,
    vendors::runtime::{ClientOverrides, VendorClient},
};

// ─── Entry point ─────────────────────────────────────────────────────────────

pub async fn execute(cli: cli::Cli) -> i32 {
    if let Command::Completions { shell } = cli.command {
        cli::completions::generate_completions(shell);
        return 0;
    }

    if let Command::ServerIds = cli.command {
        let config = config::AppConfig::load_if_exists(cli.config).ok().flatten();
        if let Some(cfg) = config {
            for server in &cfg.servers {
                println!("{}", server.id);
            }
        }
        return 0;
    }

    if let Command::Config(config_cmd) = cli.command {
        return match config_cmd {
            cli::ConfigCmd::Init { force } => match config::init_config(cli.config, force) {
                Ok(path) => {
                    println!("Wrote config file: {}", path.display());
                    0
                }
                Err(e) => render_error(e),
            },

            cli::ConfigCmd::Print => {
                let toml = match config::AppConfig::load_if_exists(cli.config.clone()) {
                    Ok(Some(cfg)) => cfg.redact().render_toml(),
                    Ok(None) => config::AppConfig::render_starter_toml(),
                    Err(e) => return render_error(e),
                };
                match toml {
                    Ok(s) => {
                        print!("{s}");
                        0
                    }
                    Err(e) => render_error(e),
                }
            }

            cli::ConfigCmd::Add {
                id,
                vendor,
                location,
                base_url,
                token_env,
                token,
                org_id,
                readonly,
                allow_zone,
            } => {
                let server = if id.is_none() {
                    match cli::interactive::run_add_wizard() {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("Error: {e:?}");
                            return 1;
                        }
                    }
                } else {
                    config::DnsServerConfig {
                        id: id.unwrap(),
                        vendor,
                        location,
                        base_url,
                        token,
                        token_env,
                        org_id,
                        mcp: config::McpPermissions {
                            readonly,
                            allowed_zones: allow_zone,
                        },
                    }
                };
                match config::add_server(cli.config, server) {
                    Ok(path) => {
                        println!("Updated config file: {}", path.display());
                        0
                    }
                    Err(e) => render_error(e),
                }
            }
        };
    }

    let app_config = match config::AppConfig::load(cli.config.clone()) {
        Ok(config) => config,
        Err(e) => return render_error(e),
    };

    if let Command::Record(RecordCmd::List {
        domain,
        zone,
        all_subdomains,
        servers: subcmd_servers,
        use_local_ip,
        json,
    }) = &cli.command
    {
        let effective_servers: &[String] = if !subcmd_servers.is_empty() {
            subcmd_servers
        } else {
            &cli.servers
        };
        let bare_label_without_zone = zone.is_none()
            && domain
                .as_deref()
                .is_some_and(|domain| !domain.contains('.'));
        let default_all_servers = (domain.is_none() || bare_label_without_zone)
            && effective_servers.is_empty()
            && app_config.as_ref().is_some_and(|c| c.servers.len() > 1);
        if cli.all || !effective_servers.is_empty() || default_all_servers {
            return run_record_list_across_servers(
                &cli,
                app_config.as_ref(),
                domain.as_deref(),
                zone.as_deref(),
                *all_subdomains,
                effective_servers,
                *use_local_ip,
                *json,
            )
            .await;
        }
    }

    if let Command::Zone(ZoneCmd::Transfer {
        zone,
        from,
        to,
        overwrite,
        overwrite_zone,
    }) = &cli.command
    {
        if cli.token.is_some() || cli.base_url.is_some() {
            return render_error(Error::parse(
                "zone transfer does not accept --token/--base-url; \
                 configure credentials per server via config file or environment variables",
            ));
        }
        return run_zone_transfer(app_config.as_ref(), zone, from, to, *overwrite, *overwrite_zone)
            .await;
    }

    if cli.servers.len() > 1 {
        return render_error(Error::parse(
            "multiple --server flags are only valid with `record list`; \
             use a single --server for all other commands",
        ));
    }

    let policy = match cli_policy(&cli, app_config.as_ref()) {
        Ok(p) => p,
        Err(e) => return render_error(e),
    };

    let client = match VendorClient::from_cli_options(
        app_config.as_ref(),
        ClientOverrides {
            selected_server: cli.servers.first().map(|s| s.as_str()),
            base_url: cli.base_url.as_deref(),
            token: cli.token.as_deref(),
        },
    ) {
        Ok(client) => client,
        Err(e) => return render_error(e),
    };

    run_with_client(cli, client, policy).await
}

pub fn render_error(e: Error) -> i32 {
    let code = e.exit_code();
    eprintln!("{:?}", Report::from(e));
    code
}

// ─── Policy helpers ───────────────────────────────────────────────────────────

pub fn cli_policy(cli: &cli::Cli, config: Option<&AppConfig>) -> Result<Policy> {
    let mcp = config
        .and_then(|c| {
            c.selected_server(cli.servers.first().map(|s| s.as_str()))
                .ok()
        })
        .map(|s| &s.mcp);

    let readonly = cli.readonly || mcp.is_some_and(|p| p.readonly);
    let allowed_zones = cli_allowed_zones(cli, mcp)?;
    Ok(Policy::new(readonly, allowed_zones))
}

fn cli_allowed_zones(
    cli: &cli::Cli,
    mcp: Option<&McpPermissions>,
) -> Result<Option<Vec<String>>> {
    let configured = mcp.and_then(|permissions| {
        (!permissions.allowed_zones.is_empty()).then_some(&permissions.allowed_zones)
    });

    if cli.allow_zone.is_empty() {
        return Ok(configured.cloned());
    }

    let Some(configured) = configured else {
        return Ok(Some(cli.allow_zone.clone()));
    };

    let configured_policy = Policy::new(false, Some(configured.clone()));
    for zone in &cli.allow_zone {
        configured_policy.check_zone(zone).map_err(|_| {
            Error::policy_violation(
                format!(
                    "--allow-zone '{zone}' is outside this server's configured MCP allowed zones"
                ),
                "Remove the override or choose a zone already permitted by this server's config.",
            )
        })?;
    }

    Ok(Some(cli.allow_zone.clone()))
}

// ─── Client dispatch ──────────────────────────────────────────────────────────

async fn run_with_client<C: DnsService + Clone + Send + Sync + 'static>(
    cli: cli::Cli,
    client: C,
    policy: Policy,
) -> i32 {
    match cli.command {
        Command::Mcp => {
            if policy.readonly {
                tracing::info!("MCP server starting in read-only mode");
            }
            if let Some(ref zones) = policy.allowed_zones {
                tracing::info!("MCP server zone restriction: {}", zones.join(", "));
            }
            tracing::info!("Starting MCP server (stdio)");

            let dns_server = DnsServer::new(client, policy);
            let transport = (tokio::io::stdin(), tokio::io::stdout());
            match dns_server.serve(transport).await {
                Ok(service) => match service.waiting().await {
                    Ok(_) => 0,
                    Err(e) => {
                        eprintln!("error: MCP transport error: {e}");
                        1
                    }
                },
                Err(e) => {
                    eprintln!("error: failed to start MCP server: {e}");
                    1
                }
            }
        }
        other => match run(&client, other).await {
            Ok(_) => 0,
            Err(e) => render_error(e),
        },
    }
}

// ─── Multi-server record list ─────────────────────────────────────────────────

async fn run_record_list_across_servers(
    cli: &cli::Cli,
    app_config: Option<&AppConfig>,
    domain: Option<&str>,
    zone: Option<&str>,
    all_subdomains: bool,
    servers: &[String],
    use_local_ip: bool,
    json: bool,
) -> i32 {
    if cli.token.is_some() || cli.base_url.is_some() {
        return render_error(Error::parse(
            "cross-server record list does not accept --token/--base-url; configure credentials per server via config file or environment variables",
        ));
    }

    let Some(cfg) = app_config else {
        return render_error(Error::parse(
            "--all/--server for record list requires a config file with server entries",
        ));
    };

    let query_all_servers = cli.all || servers.is_empty();
    let selected: Vec<&config::DnsServerConfig> = if query_all_servers {
        cfg.servers.iter().collect()
    } else {
        match app::select_servers(cfg, servers) {
            Ok(s) => s,
            Err(e) => return render_error(e),
        }
    };

    if selected.is_empty() {
        return render_error(Error::parse(
            "--all requested, but no servers are configured; add at least one server in the config file",
        ));
    }

    let options = ListRecordsOptions {
        use_local_ip,
        all_subdomains,
    };

    let results =
        app::query_records_across_servers(&selected, domain, zone, all_subdomains, options).await;

    let mut json_zones = Vec::new();
    let mut printed_servers = 0usize;

    for (server_id, vendor_kind, result) in results {
        let server = cfg.servers.iter().find(|s| s.id == server_id).unwrap();
        match result {
            Ok(response) => {
                if json {
                    for mut zone_records in response.zones {
                        if zone_records.zone.id.is_none() {
                            zone_records.zone.id = Some(zone_records.zone.name.clone());
                        }
                        json_zones.push(serde_json::json!({
                            "serverName": server.id,
                            "serverId": server.id,
                            "vendor": format!("{:?}", vendor_kind),
                            "zone": zone_records.zone,
                            "records": zone_records.records,
                        }));
                    }
                } else if !response.zones.is_empty() {
                    if printed_servers > 0 {
                        println!();
                    }
                    println!("=== Server: {} ({:?}) ===", server.id, server.vendor);
                    records::print_records_table(&response);
                    printed_servers += 1;
                }
            }
            Err(e) => return render_error(e),
        }
    }

    if json {
        match serde_json::to_string_pretty(&json_zones) {
            Ok(pretty) => println!("{pretty}"),
            Err(e) => {
                return render_error(Error::parse(format!(
                    "could not serialise record list response: {e}"
                )));
            }
        }
    }

    0
}

// ─── Zone transfer ────────────────────────────────────────────────────────────

async fn run_zone_transfer(
    app_config: Option<&AppConfig>,
    zone: &str,
    from_id: &str,
    to_id: &str,
    overwrite: bool,
    overwrite_zone: bool,
) -> i32 {
    let Some(cfg) = app_config else {
        return render_error(Error::parse(
            "zone transfer requires a config file with --from and --to server entries",
        ));
    };

    let from_vendor = match cfg.selected_server(Some(from_id)) {
        Ok(s) => s.vendor,
        Err(e) => return render_error(e),
    };
    let to_vendor = match cfg.selected_server(Some(to_id)) {
        Ok(s) => s.vendor,
        Err(e) => return render_error(e),
    };

    eprintln!("Exporting '{zone}' from '{from_id}' ({from_vendor:?})…");
    eprintln!("Importing into '{to_id}' ({to_vendor:?})…");

    match app::transfer_zone(cfg, zone, from_id, to_id, overwrite, overwrite_zone).await {
        Ok(Some(result)) => match serde_json::to_string_pretty(&result) {
            Ok(pretty) => {
                println!("{pretty}");
                0
            }
            Err(e) => render_error(Error::parse(format!("serialise error: {e}"))),
        },
        Ok(None) => 0,
        Err(e) => render_error(e),
    }
}

// ─── Command dispatch ─────────────────────────────────────────────────────────

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
            ZoneCmd::Export { .. } => "zone export",
            ZoneCmd::Transfer { .. } => "zone transfer",
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
        Command::Mcp | Command::Config(_) | Command::Completions { .. } | Command::ServerIds => {
            unreachable!()
        }
    };
    tracing::Span::current().record("command", cmd_name);
    tracing::info!(command = cmd_name, "running CLI command");

    if let Command::Record(RecordCmd::List {
        domain,
        zone,
        all_subdomains,
        use_local_ip,
        json,
        servers: _,
    }) = command
    {
        use crate::core::dns::util::{infer_zone, resolve_fqdn};

        let options = ListRecordsOptions {
            use_local_ip,
            all_subdomains,
        };

        let response = if let Some(domain) = domain {
            let effective_fqdn = resolve_fqdn(&domain, zone.as_deref());
            let is_bare_label = zone.is_none() && !effective_fqdn.contains('.');

            if is_bare_label {
                app::search_bare_label_in_zones(client, &effective_fqdn, all_subdomains, options)
                    .await?
            } else {
                let (query_domain, query_zone) = if all_subdomains {
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
                    app::filter_records_by_domain(&mut resp, &effective_fqdn, true);
                }
                resp
            }
        } else {
            app::list_records_for_all_zones(client, options).await?
        };

        if json {
            let value = serde_json::to_value(&response).map_err(|e| Error::parse(e.to_string()))?;
            print_result(&value)?;
        } else {
            records::print_records_table(&response);
        }
        return Ok(());
    }

    if let Command::Zone(ZoneCmd::Export { zone, output }) = command {
        let zone_text = client.export_zone_file(&zone).await?;
        if let Some(path) = output {
            std::fs::write(&path, &zone_text)
                .map_err(|e| Error::io(format!("writing zone file '{}'", path.display()), e))?;
        } else {
            print!("{zone_text}");
        }
        return Ok(());
    }

    let result = match command {
        Command::Mcp => unreachable!("handled in execute"),
        Command::Config(_) => unreachable!("handled in execute"),
        Command::Record(RecordCmd::List { .. }) => unreachable!("handled above"),

        Command::Zone(cmd) => match cmd {
            ZoneCmd::List { page, per_page } => client.list_zones(page, per_page).await?,
            ZoneCmd::Create { zone, r#type } => client.create_zone(&zone, &r#type).await?,
            ZoneCmd::Delete { zone } => client.delete_zone(&zone).await?,
            ZoneCmd::Enable { zone } => client.enable_zone(&zone).await?,
            ZoneCmd::Disable { zone } => client.disable_zone(&zone).await?,
            ZoneCmd::Export { .. } => unreachable!("handled above"),
            ZoneCmd::Transfer { .. } => unreachable!("handled in execute"),
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

        Command::Completions { .. } | Command::ServerIds => {
            unreachable!("handled in execute")
        }
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
    use crate::core::dns::service::ZoneRead;
    use serde_json::{Value, json};
    use std::sync::Mutex;
    use crate::control_plane::app::{extract_zone_names, filter_records_by_domain, list_records_for_all_zones};
    use crate::core::dns::util::{infer_zone, resolve_fqdn};

    fn make_zone(name: &str) -> ZoneInfo {
        ZoneInfo {
            id: None,
            name: name.to_string(),
            zone_type: "Primary".to_string(),
            disabled: false,
            dnssec_status: None,
        }
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

    struct FakeZoneRead {
        zones: Value,
        calls: Mutex<Vec<(String, Option<String>)>>,
    }

    impl FakeZoneRead {
        fn new(zones: Value) -> Self {
            Self {
                zones,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(String, Option<String>)> {
            self.calls
                .lock()
                .expect("calls mutex should not be poisoned")
                .clone()
        }
    }

    impl ZoneRead for FakeZoneRead {
        async fn list_zones(&self, _page: u32, _per_page: u32) -> Result<Value> {
            Ok(self.zones.clone())
        }

        async fn list_records<'a>(
            &'a self,
            domain: &'a str,
            zone: Option<&'a str>,
            _options: ListRecordsOptions,
        ) -> Result<ListRecordsResponse> {
            self.calls
                .lock()
                .expect("calls mutex should not be poisoned")
                .push((domain.to_string(), zone.map(str::to_string)));
            Ok(ListRecordsResponse::single(
                make_zone(zone.unwrap_or(domain)),
                vec![make_record("@")],
            ))
        }
    }

    // ── infer_zone TLD guard ─────────────────────────────────────────────────

    #[test]
    fn infer_zone_tld_falls_back_to_apex_for_all_subdomains() {
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

    #[tokio::test]
    async fn list_records_for_all_zones_queries_each_zone_apex() {
        let client = FakeZoneRead::new(json!({
            "response": {
                "zones": [{"name": "hankin.io"}, {"name": "example.com"}]
            }
        }));

        let response = list_records_for_all_zones(&client, ListRecordsOptions::default())
            .await
            .expect("all zones should list");

        assert_eq!(
            client.calls(),
            vec![
                ("hankin.io".to_string(), Some("hankin.io".to_string())),
                ("example.com".to_string(), Some("example.com".to_string())),
            ]
        );
        let zone_names: Vec<&str> = response
            .zones
            .iter()
            .map(|z| z.zone.name.as_str())
            .collect();
        assert_eq!(zone_names, vec!["hankin.io", "example.com"]);
    }

    // ── resolve_fqdn ──────────────────────────────────────────────────────────

    #[test]
    fn relative_label_is_qualified_with_zone() {
        assert_eq!(resolve_fqdn("huly", Some("hankin.io")), "huly.hankin.io");
    }

    #[test]
    fn already_qualified_fqdn_is_unchanged() {
        assert_eq!(
            resolve_fqdn("huly.hankin.io", Some("hankin.io")),
            "huly.hankin.io"
        );
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
        assert_eq!(
            resolve_fqdn("Huly.Hankin.IO", Some("hankin.io")),
            "Huly.Hankin.IO"
        );
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
    fn filter_exact_keeps_fully_qualified_record_name() {
        let mut resp = ListRecordsResponse {
            zones: vec![ZoneRecords {
                zone: make_zone("hankin.io"),
                records: vec![
                    make_record("huly.hankin.io"),
                    make_record("other.hankin.io"),
                ],
            }],
        };
        filter_records_by_domain(&mut resp, "huly.hankin.io", false);
        assert_eq!(resp.zones[0].records.len(), 1);
        assert_eq!(resp.zones[0].records[0].name, "huly.hankin.io");
    }

    #[test]
    fn filter_exact_keeps_fully_qualified_record_with_trailing_dot() {
        let mut resp = ListRecordsResponse {
            zones: vec![ZoneRecords {
                zone: make_zone("hankin.io"),
                records: vec![make_record("huly.hankin.io.")],
            }],
        };
        filter_records_by_domain(&mut resp, "huly.hankin.io", false);
        assert_eq!(resp.zones[0].records.len(), 1);
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
        let names: Vec<&str> = resp.zones[0]
            .records
            .iter()
            .map(|r| r.name.as_str())
            .collect();
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
