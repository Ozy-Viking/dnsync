//! `AppConfig` inherent methods: load/save/redact/validate/render orchestration.

use super::*;

impl AppConfig {
    /// Create a starter `AppConfig` populated with one default server for bootstrapping.
    ///
    /// The returned configuration contains:
    /// - a single `DnsServerConfig` with `id = "default"`, vendor `Technitium`,
    ///   `base_url` set to the Technitium default, `token_env = "DNSYNC_TECHNITIUM_API_TOKEN"`,
    ///   and default MCP permissions;
    /// - empty `clusters`;
    /// - no `daemon`;
    /// - no `jobs`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let cfg = AppConfig::starter();
    /// assert_eq!(cfg.servers.len(), 1);
    /// let srv = &cfg.servers[0];
    /// assert_eq!(srv.id, "default");
    /// assert_eq!(srv.vendor, VendorKind::Technitium);
    /// assert_eq!(srv.token_env.as_deref(), Some("DNSYNC_TECHNITIUM_API_TOKEN"));
    /// ```
    pub fn starter() -> Self {
        AppConfig {
            servers: vec![DnsServerConfig {
                id: "default".to_string(),
                vendor: VendorKind::Technitium,
                location: None,
                base_url: Some(TECHNITIUM_DEFAULT_BASE_URL.to_string()),
                base_url_env: None,
                token: None,
                token_env: Some("DNSYNC_TECHNITIUM_API_TOKEN".to_string()),
                org_id: None,
                cluster: None,
                dns: None,
                dot: None,
                doh: None,
                doq: None,
                mcp: McpPermissions::default(),
                validation_endpoints: Vec::new(),
            }],
            clusters: BTreeMap::new(),
            daemon: None,
            jobs: Vec::new(),
        }
    }

    pub fn render_starter_toml() -> Result<String> {
        Self::starter().render_toml()
    }

    /// Render the configuration as a TOML document string.
    ///
    /// The output includes serialized `servers` (`[[servers]]` entries), a `[clusters]` table
    /// (when clusters exist), an optional `[daemon]` table, and `[[jobs]]` entries in that order.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let cfg = AppConfig::starter();
    /// let toml = cfg.render_toml().unwrap();
    /// assert!(toml.contains("[[servers]]"));
    /// assert!(toml.contains("token_env"));
    /// ```
    pub fn render_toml(&self) -> Result<String> {
        let mut doc = toml_edit::DocumentMut::new();
        for server in &self.servers {
            append_server_entry(&mut doc, server);
        }
        append_cluster_entries(&mut doc, &self.clusters);
        if let Some(ref daemon) = self.daemon {
            append_daemon_entry(&mut doc, daemon);
        }
        for job in &self.jobs {
            append_job_entry(&mut doc, job);
        }
        Ok(doc.to_string())
    }

    /// Create a copy of the configuration with any literal server `token` values replaced by `"[redacted]"`.
    ///
    /// Literal `token` fields are replaced; `token_env` (environment variable names) are preserved unchanged.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let cfg = AppConfig {
    ///     servers: vec![DnsServerConfig { id: "s".into(), token: Some("secret".into()), token_env: None, ..Default::default() }],
    ///     ..Default::default()
    /// };
    /// let redacted = cfg.redact();
    /// assert_eq!(redacted.servers[0].token.as_deref(), Some("[redacted]"));
    /// assert_eq!(redacted.servers[0].token_env, cfg.servers[0].token_env);
    /// ```
    pub fn redact(&self) -> Self {
        AppConfig {
            servers: self
                .servers
                .iter()
                .map(|s| DnsServerConfig {
                    token: s.token.as_ref().map(|_| ApiToken::new("[redacted]")),
                    ..s.clone()
                })
                .collect(),
            clusters: self.clusters.clone(),
            daemon: self.daemon.clone(),
            jobs: self.jobs.clone(),
        }
    }

    /// Load the config file if it already exists; return `Ok(None)` if it does
    /// not. Unlike `load`, this never creates the file.
    pub fn load_if_exists(path: Option<PathBuf>) -> Result<Option<Self>> {
        let Some(path) = path.or_else(default_config_path) else {
            return Ok(None);
        };
        if !path.exists() {
            return Ok(None);
        }
        load_from_path(&path).map(Some)
    }

    /// Load the config file, creating it with starter defaults if it does not
    /// exist yet.
    pub fn load(path: Option<PathBuf>) -> Result<Option<Self>> {
        let Some(path) = path.or_else(default_config_path) else {
            return Ok(None);
        };

        if !path.exists() {
            write_default_config(&path, false)?;
        }

        load_from_path(&path).map(Some)
    }

    pub fn selected_server(&self, selected_id: Option<&str>) -> Result<&DnsServerConfig> {
        if let Some(id) = selected_id {
            return self
                .servers
                .iter()
                .find(|server| server.id.eq_ignore_ascii_case(id))
                .ok_or_else(|| {
                    Error::config(format!("config does not define a DNS server named '{id}'"))
                });
        }

        match self.servers.as_slice() {
            [server] => Ok(server),
            [] => Err(Error::config("config file does not define any DNS servers")),
            _ => Err(Error::config(
                "config file defines multiple DNS servers; select one with --server or DNSYNC_SERVER",
            )),
        }
    }

    /// Performs semantic validation of the configuration.
    ///
    /// This checks each server for a non-empty, unique (case-insensitive) id; verifies any
    /// server `cluster` references exist; validates configured transport endpoints and
    /// validation endpoints for each server; validates cluster definitions and job entries
    /// (including job id uniqueness, scheduling rules, server references, IP-map consistency,
    /// and regex compilation).
    ///
    /// Returns `Ok(())` when all checks pass, or an `Error::config(...)` describing the first
    /// validation failure encountered.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let cfg = AppConfig::default();
    /// // starter/default config should validate
    /// cfg.validate().unwrap();
    /// ```
    pub(crate) fn validate(&self) -> Result<()> {
        let mut ids = std::collections::HashSet::new();
        for server in &self.servers {
            if server.id.trim().is_empty() {
                return Err(Error::config(
                    "config contains a DNS server with an empty id",
                ));
            }
            if !ids.insert(server.id.to_lowercase()) {
                return Err(Error::config(format!(
                    "config contains duplicate DNS server id '{}'",
                    server.id
                )));
            }
            if let Some(cluster_id) = &server.cluster
                && !self.clusters.contains_key(cluster_id)
            {
                return Err(Error::config(format!(
                    "DNS server '{}' references unknown cluster '{}'",
                    server.id, cluster_id
                )));
            }
            validate_server_transports(server)?;
            validate_validation_endpoints(server)?;
        }
        validate_clusters(&self.clusters, &ids)?;
        validate_jobs(&self.jobs, &ids)?;

        Ok(())
    }
}
