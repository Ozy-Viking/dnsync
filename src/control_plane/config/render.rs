//! TOML rendering helpers (transport tables, server/daemon/job/cluster entries).

use super::*;

pub(crate) fn default_base_url(vendor: VendorKind) -> &'static str {
    match vendor {
        VendorKind::Technitium => TECHNITIUM_DEFAULT_BASE_URL,
        VendorKind::Pangolin => PANGOLIN_DEFAULT_BASE_URL,
        VendorKind::Cloudflare => CLOUDFLARE_DEFAULT_BASE_URL,
        VendorKind::Unifi => UNIFI_DEFAULT_BASE_URL,
        VendorKind::Pihole => PIHOLE_DEFAULT_BASE_URL,
    }
}

pub(crate) fn vendor_name(vendor: VendorKind) -> &'static str {
    match vendor {
        VendorKind::Technitium => "technitium",
        VendorKind::Pangolin => "pangolin",
        VendorKind::Cloudflare => "cloudflare",
        VendorKind::Unifi => "unifi",
        VendorKind::Pihole => "pihole",
    }
}

pub(crate) fn policy_rule_name(rule: PolicyRule) -> &'static str {
    match rule {
        PolicyRule::Read => "read",
        PolicyRule::Write => "write",
        PolicyRule::Delete => "delete",
    }
}

pub(crate) fn dns_transport_table(cfg: &DnsTransportConfig) -> toml_edit::Table {
    use toml_edit::{Table, value};

    let mut tbl = Table::new();
    tbl["enabled"] = value(cfg.enabled);
    if let Some(ref addr) = cfg.addr {
        tbl["addr"] = value(addr.as_str());
    }
    if let Some(ms) = cfg.timeout_ms {
        tbl["timeout_ms"] = value(ms as i64);
    }
    tbl
}

pub(crate) fn dot_transport_table(cfg: &DotTransportConfig) -> toml_edit::Table {
    use toml_edit::{Table, value};

    let mut tbl = Table::new();
    tbl["enabled"] = value(cfg.enabled);
    if let Some(ref addr) = cfg.addr {
        tbl["addr"] = value(addr.as_str());
    }
    if let Some(ref sn) = cfg.server_name {
        tbl["server_name"] = value(sn.as_str());
    }
    if let Some(ms) = cfg.timeout_ms {
        tbl["timeout_ms"] = value(ms as i64);
    }
    tbl
}

pub(crate) fn doh_transport_table(cfg: &DohTransportConfig) -> toml_edit::Table {
    use toml_edit::{Table, value};

    let mut tbl = Table::new();
    tbl["enabled"] = value(cfg.enabled);
    if let Some(ref url) = cfg.url {
        tbl["url"] = value(url.as_str());
    }
    if let Some(ref addr) = cfg.addr {
        tbl["addr"] = value(addr.as_str());
    }
    if let Some(ref sn) = cfg.server_name {
        tbl["server_name"] = value(sn.as_str());
    }
    if let Some(ms) = cfg.timeout_ms {
        tbl["timeout_ms"] = value(ms as i64);
    }
    tbl
}

pub(crate) fn doq_transport_table(cfg: &DoqTransportConfig) -> toml_edit::Table {
    use toml_edit::{Table, value};

    let mut tbl = Table::new();
    tbl["enabled"] = value(cfg.enabled);
    if let Some(ref addr) = cfg.addr {
        tbl["addr"] = value(addr.as_str());
    }
    if let Some(ref sn) = cfg.server_name {
        tbl["server_name"] = value(sn.as_str());
    }
    if let Some(ms) = cfg.timeout_ms {
        tbl["timeout_ms"] = value(ms as i64);
    }
    tbl
}

/// Append a new `[[servers]]` table to a `toml_edit::DocumentMut` without modifying any
/// existing tables or other content in the document.
///
/// The function writes a complete server table derived from `server` and either pushes it
/// onto an existing `servers` array-of-tables or creates that array if it does not exist.
///
/// # Examples
///
/// ```text
/// let mut doc = toml_edit::DocumentMut::new();
/// // `AppConfig::starter()` provides a minimal starter server suitable for examples/tests.
/// let server = crate::control_plane::config::AppConfig::starter().servers.into_iter().next().unwrap();
/// crate::control_plane::config::append_server_entry(&mut doc, &server);
/// assert!(doc.to_string().contains("[[servers]]"));
/// ```
pub(crate) fn append_server_entry(doc: &mut toml_edit::DocumentMut, server: &DnsServerConfig) {
    use toml_edit::{Array, ArrayOfTables, Item, Table, value};

    let mut tbl = Table::new();
    // Blank line before each [[servers]] header for readability.
    tbl.decor_mut().set_prefix("\n");

    tbl["id"] = value(server.id.as_str());
    tbl["vendor"] = value(match server.vendor {
        VendorKind::Technitium => "technitium",
        VendorKind::Pangolin => "pangolin",
        VendorKind::Cloudflare => "cloudflare",
        VendorKind::Unifi => "unifi",
        VendorKind::Pihole => "pihole",
    });
    if let Some(loc) = server.location {
        tbl["location"] = value(match loc {
            ServerLocation::Local => "local",
            ServerLocation::External => "external",
        });
    }
    if let Some(ref v) = server.base_url {
        tbl["base_url"] = value(v.as_str());
    }
    if let Some(ref v) = server.base_url_env {
        tbl["base_url_env"] = value(v.as_str());
    }
    if let Some(ref v) = server.token_env {
        tbl["token_env"] = value(v.as_str());
    }
    match server.token.as_ref().map(ApiToken::expose_for_auth) {
        Some(t) => tbl["token"] = value(t),
        // Write an empty placeholder so the field is visible in the config file.
        None if server.token_env.is_none() => tbl["token"] = value(""),
        None => {}
    }
    if let Some(ref v) = server.org_id {
        tbl["org_id"] = value(v.as_str());
    }

    let mut access_arr = Array::new();
    for rule in &server.mcp.access {
        access_arr.push(match rule {
            PolicyRule::Read => "read",
            PolicyRule::Write => "write",
            PolicyRule::Delete => "delete",
        });
    }
    tbl["mcp_access"] = value(access_arr);
    let mut zones = Array::new();
    for zone in &server.mcp.allowed_zones {
        zones.push(zone.as_str());
    }
    tbl["mcp_allowed_zones"] = value(zones);

    if !server.validation_endpoints.is_empty() {
        let mut endpoints = ArrayOfTables::new();
        for endpoint in &server.validation_endpoints {
            let mut endpoint_tbl = Table::new();
            endpoint_tbl["name"] = value(endpoint.name.as_str());
            endpoint_tbl["transport"] = value(match endpoint.transport {
                ValidationTransport::Dns => "dns",
                ValidationTransport::Doh => "doh",
                ValidationTransport::Dot => "dot",
                ValidationTransport::Doq => "doq",
            });
            if !endpoint.address.is_empty() {
                endpoint_tbl["address"] = value(endpoint.address.as_str());
            }
            if let Some(port) = endpoint.port {
                endpoint_tbl["port"] = value(i64::from(port));
            }
            if let Some(ref url) = endpoint.url {
                endpoint_tbl["url"] = value(url.as_str());
            }
            if let Some(ref tls_server_name) = endpoint.tls_server_name {
                endpoint_tbl["tls_server_name"] = value(tls_server_name.as_str());
            }
            endpoint_tbl["enabled"] = value(endpoint.enabled);
            if let Some(timeout_ms) = endpoint.timeout_ms {
                endpoint_tbl["timeout_ms"] = value(timeout_ms as i64);
            }
            endpoints.push(endpoint_tbl);
        }
        tbl["validation_endpoints"] = Item::ArrayOfTables(endpoints);
    }

    if let Some(ref cluster) = server.cluster {
        tbl["cluster"] = value(cluster.as_str());
    }
    if let Some(ref dns) = server.dns {
        let mut dns_tbl = Table::new();
        dns_tbl["enabled"] = value(dns.enabled);
        if let Some(ref addr) = dns.addr {
            dns_tbl["addr"] = value(addr.as_str());
        }
        if let Some(timeout_ms) = dns.timeout_ms {
            dns_tbl["timeout_ms"] = value(timeout_ms as i64);
        }
        tbl["dns"] = Item::Table(dns_tbl);
    }
    if let Some(ref dot) = server.dot {
        let mut dot_tbl = Table::new();
        dot_tbl["enabled"] = value(dot.enabled);
        if let Some(ref addr) = dot.addr {
            dot_tbl["addr"] = value(addr.as_str());
        }
        if let Some(ref server_name) = dot.server_name {
            dot_tbl["server_name"] = value(server_name.as_str());
        }
        if let Some(timeout_ms) = dot.timeout_ms {
            dot_tbl["timeout_ms"] = value(timeout_ms as i64);
        }
        tbl["dot"] = Item::Table(dot_tbl);
    }
    if let Some(ref doh) = server.doh {
        let mut doh_tbl = Table::new();
        doh_tbl["enabled"] = value(doh.enabled);
        if let Some(ref url) = doh.url {
            doh_tbl["url"] = value(url.as_str());
        }
        if let Some(ref addr) = doh.addr {
            doh_tbl["addr"] = value(addr.as_str());
        }
        if let Some(ref server_name) = doh.server_name {
            doh_tbl["server_name"] = value(server_name.as_str());
        }
        if let Some(timeout_ms) = doh.timeout_ms {
            doh_tbl["timeout_ms"] = value(timeout_ms as i64);
        }
        tbl["doh"] = Item::Table(doh_tbl);
    }
    if let Some(ref doq) = server.doq {
        let mut doq_tbl = Table::new();
        doq_tbl["enabled"] = value(doq.enabled);
        if let Some(ref addr) = doq.addr {
            doq_tbl["addr"] = value(addr.as_str());
        }
        if let Some(ref server_name) = doq.server_name {
            doq_tbl["server_name"] = value(server_name.as_str());
        }
        if let Some(timeout_ms) = doq.timeout_ms {
            doq_tbl["timeout_ms"] = value(timeout_ms as i64);
        }
        tbl["doq"] = Item::Table(doq_tbl);
    }

    match doc.entry("servers") {
        toml_edit::Entry::Occupied(mut e) => {
            if let Some(aot) = e.get_mut().as_array_of_tables_mut() {
                aot.push(tbl);
            }
        }
        toml_edit::Entry::Vacant(e) => {
            let mut aot = ArrayOfTables::new();
            aot.push(tbl);
            e.insert(Item::ArrayOfTables(aot));
        }
    }
}

/// Append a `[daemon]` table containing daemon runtime settings to the given TOML document.
///
/// The table will include `state_db` (if present), `heartbeat_interval`, `heartbeat_timeout`,
/// `shutdown_timeout`, `worker_threads`, and `critical_failure_threshold`.
///
/// # Examples
///
/// ```text
/// use toml_edit::Document;
/// use std::str::FromStr;
/// // Construct a DaemonConfig by deserializing a small TOML snippet.
/// let daemon: DaemonConfig = toml::from_str(r#"
/// state_db = "/tmp/state.db"
/// heartbeat_interval = "5s"
/// heartbeat_timeout = "20s"
/// shutdown_timeout = "5s"
/// worker_threads = 4
/// critical_failure_threshold = 5
/// "#).unwrap();
///
/// let mut doc = Document::new();
/// append_daemon_entry(&mut doc, &daemon);
/// assert!(doc.to_string().contains("[daemon]"));
/// ```
pub(crate) fn append_daemon_entry(doc: &mut toml_edit::DocumentMut, daemon: &DaemonConfig) {
    use toml_edit::{Item, Table, value};

    let mut tbl = Table::new();
    tbl.decor_mut().set_prefix("\n");

    if let Some(ref p) = daemon.state_db {
        tbl["state_db"] = value(p.to_string_lossy().as_ref());
    }
    tbl["heartbeat_interval"] = value(daemon.heartbeat_interval.as_str());
    tbl["heartbeat_timeout"] = value(daemon.heartbeat_timeout.as_str());
    tbl["shutdown_timeout"] = value(daemon.shutdown_timeout.as_str());
    tbl["worker_threads"] = value(daemon.worker_threads as i64);
    tbl["critical_failure_threshold"] = value(daemon.critical_failure_threshold as i64);

    doc["daemon"] = Item::Table(tbl);
}

/// Append a `[[jobs]]` entry to a toml_edit document.
pub(crate) fn append_job_entry(doc: &mut toml_edit::DocumentMut, job: &JobConfig) {
    use toml_edit::{Array, ArrayOfTables, Item, Table, value};

    let mut tbl = Table::new();
    tbl.decor_mut().set_prefix("\n");

    tbl["id"] = value(job.id.as_str());
    tbl["kind"] = value(match job.kind {
        JobKind::RecordSync => "record_sync",
        JobKind::ZoneSync => "zone_sync",
        JobKind::ZoneExport => "zone_export",
    });
    tbl["enabled"] = value(job.enabled);
    tbl["critical"] = value(job.critical);

    if let Some(ref s) = job.schedule {
        tbl["schedule"] = value(s.as_str());
    }
    if let Some(ref i) = job.interval {
        tbl["interval"] = value(i.as_str());
    }
    if let Some(ref tz) = job.timezone {
        tbl["timezone"] = value(tz.as_str());
    }
    tbl["run_immediately"] = value(job.run_immediately);
    if let Some(ref j) = job.jitter {
        tbl["jitter"] = value(j.as_str());
    }
    tbl["dry_run"] = value(job.dry_run);

    if let Some(ref f) = job.from {
        tbl["from"] = value(f.as_str());
    }
    if let Some(ref t) = job.to {
        tbl["to"] = value(t.as_str());
    }
    if !job.zones.is_empty() {
        let mut zones = Array::new();
        for z in &job.zones {
            zones.push(z.as_str());
        }
        tbl["zones"] = value(zones);
    }
    if !job.ip_map.is_empty() {
        let mut map_tbl = Table::new();
        for (src, dst) in &job.ip_map {
            map_tbl[src.as_str()] = value(dst.as_str());
        }
        tbl["ip_map"] = Item::Table(map_tbl);
    }
    tbl["create_missing"] = value(job.create_missing);
    tbl["overwrite_existing"] = value(job.overwrite_existing);
    tbl["delete_destination_only"] = value(job.delete_destination_only);
    if !job.ignore.is_empty() {
        let mut ignore = Array::new();
        for p in &job.ignore {
            ignore.push(p.as_str());
        }
        tbl["ignore"] = value(ignore);
    }
    if let Some(ref out) = job.output_dir {
        tbl["output_dir"] = value(out.as_str());
    }

    match doc.entry("jobs") {
        toml_edit::Entry::Occupied(mut e) => {
            if let Some(aot) = e.get_mut().as_array_of_tables_mut() {
                aot.push(tbl);
            }
        }
        toml_edit::Entry::Vacant(e) => {
            let mut aot = ArrayOfTables::new();
            aot.push(tbl);
            e.insert(Item::ArrayOfTables(aot));
        }
    }
}

pub(crate) fn append_cluster_entries(
    doc: &mut toml_edit::DocumentMut,
    clusters: &BTreeMap<String, ClusterConfig>,
) {
    use toml_edit::{Array, Item, Table, value};

    if clusters.is_empty() {
        return;
    }

    let mut clusters_tbl = Table::new();
    clusters_tbl.decor_mut().set_prefix("\n");

    for (id, cluster) in clusters {
        let mut tbl = Table::new();
        tbl["vendor"] = value(match cluster.vendor {
            VendorKind::Technitium => "technitium",
            VendorKind::Pangolin => "pangolin",
            VendorKind::Cloudflare => "cloudflare",
            VendorKind::Unifi => "unifi",
            VendorKind::Pihole => "pihole",
        });
        let mut members = Array::new();
        for member in &cluster.members {
            members.push(member.as_str());
        }
        tbl["members"] = value(members);
        tbl["write_policy"] = value(match cluster.write_policy {
            ClusterWritePolicy::PrimaryOnly => "primary_only",
        });
        if let Some(ref primary) = cluster.primary {
            tbl["primary"] = value(primary.as_str());
        }
        if let Some(ref catalog_zone) = cluster.catalog_zone {
            tbl["catalog_zone"] = value(catalog_zone.as_str());
        }
        if let Some(ref preferred_writer) = cluster.preferred_writer {
            tbl["preferred_writer"] = value(preferred_writer.as_str());
        }
        clusters_tbl[id] = Item::Table(tbl);
    }

    doc["clusters"] = Item::Table(clusters_tbl);
}
