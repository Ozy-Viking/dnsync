use crate::control_plane::config::{AppConfig, DnsServerConfig};
use crate::core::error::{Error, Result};

/// Select the configured DNS servers that should be queried by a cross-server command.
pub fn select_record_list_servers<'a>(
    app_config: Option<&'a AppConfig>,
    domain: Option<&str>,
    zone: Option<&str>,
    servers: &[String],
) -> Result<Vec<&'a DnsServerConfig>> {
    let Some(cfg) = app_config else {
        return Err(Error::parse(
            "--all/--server for record list requires a config file with server entries",
        ));
    };

    let bare_label_without_zone =
        zone.is_none() && domain.is_some_and(|domain| !domain.contains('.'));
    let query_all_servers = servers.is_empty() && (domain.is_none() || bare_label_without_zone);
    let selected: Vec<&DnsServerConfig> = if query_all_servers {
        cfg.servers.iter().collect()
    } else {
        let mut picked = Vec::with_capacity(servers.len());
        for server_id in servers {
            picked.push(cfg.selected_server(Some(server_id.as_str()))?);
        }
        picked
    };

    if selected.is_empty() {
        return Err(Error::parse(
            "--all requested, but no servers are configured; add at least one server in the config file",
        ));
    }

    Ok(selected)
}

/// Resolve the servers a `dns query` should target, expanding cluster
/// IDs to their members.
///
/// With `all_servers`, every configured `[[servers]]` entry is returned.
/// Otherwise each identifier in `ids` is resolved: a cluster id expands
/// to its `members`, any other id resolves to a single server. Results
/// preserve first-seen order and are de-duplicated by server id, so
/// `--server cluster --server member-of-cluster` runs each server once.
pub fn select_query_servers<'a>(
    cfg: &'a AppConfig,
    ids: &[String],
    all_servers: bool,
) -> Result<Vec<&'a DnsServerConfig>> {
    if all_servers {
        if cfg.servers.is_empty() {
            return Err(Error::parse(
                "`--all-servers` was given but the config defines no `[[servers]]`",
            ));
        }
        return Ok(cfg.servers.iter().collect());
    }

    fn push_unique<'a>(out: &mut Vec<&'a DnsServerConfig>, server: &'a DnsServerConfig) {
        if !out.iter().any(|existing| existing.id == server.id) {
            out.push(server);
        }
    }

    let mut out: Vec<&DnsServerConfig> = Vec::new();
    for id in ids {
        if let Some(cluster) = cfg.clusters.get(id) {
            for member in &cluster.members {
                let server = cfg.selected_server(Some(member.as_str())).map_err(|_| {
                    Error::config(format!(
                        "cluster '{id}' lists member '{member}', but no such server is defined",
                    ))
                })?;
                push_unique(&mut out, server);
            }
        } else {
            let server = cfg.selected_server(Some(id.as_str()))?;
            push_unique(&mut out, server);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> AppConfig {
        toml::from_str(
            r#"
                [[servers]]
                id = "dns1"
                vendor = "technitium"
                base_url = "http://dns1.local:5380"
                token = "t1"
                cluster = "home-dns"

                [[servers]]
                id = "dns2"
                vendor = "technitium"
                base_url = "http://dns2.local:5380"
                token = "t2"
                cluster = "home-dns"

                [[servers]]
                id = "edge"
                vendor = "cloudflare"
                token = "t3"

                [clusters.home-dns]
                members = ["dns1", "dns2"]
            "#,
        )
        .expect("config parses")
    }

    fn ids(servers: &[&DnsServerConfig]) -> Vec<String> {
        servers.iter().map(|s| s.id.clone()).collect()
    }

    #[test]
    fn all_servers_returns_every_entry() {
        let cfg = config();
        let got = select_query_servers(&cfg, &[], true).unwrap();
        assert_eq!(ids(&got), ["dns1", "dns2", "edge"]);
    }

    #[test]
    fn cluster_id_expands_to_members() {
        let cfg = config();
        let got = select_query_servers(&cfg, &["home-dns".to_string()], false).unwrap();
        assert_eq!(ids(&got), ["dns1", "dns2"]);
    }

    #[test]
    fn cluster_and_member_dedup_to_single_run() {
        let cfg = config();
        let got = select_query_servers(&cfg, &["home-dns".to_string(), "dns1".to_string()], false)
            .unwrap();
        assert_eq!(ids(&got), ["dns1", "dns2"]);
    }

    #[test]
    fn explicit_servers_preserve_order() {
        let cfg = config();
        let got =
            select_query_servers(&cfg, &["edge".to_string(), "dns1".to_string()], false).unwrap();
        assert_eq!(ids(&got), ["edge", "dns1"]);
    }

    #[test]
    fn unknown_id_errors() {
        let cfg = config();
        assert!(select_query_servers(&cfg, &["nope".to_string()], false).is_err());
    }

    #[test]
    fn all_servers_on_empty_config_errors() {
        let cfg: AppConfig = toml::from_str("").expect("empty config parses");
        assert!(select_query_servers(&cfg, &[], true).is_err());
    }
}
