use std::{
    env,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::core::error::{Error, Result};
use crate::core::secret::ApiToken;

/// Supported DNS vendor backends.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum VendorKind {
    #[default]
    Technitium,
    Pangolin,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    #[serde(default)]
    pub servers: Vec<DnsServerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsServerConfig {
    pub id: String,

    #[serde(default)]
    pub vendor: VendorKind,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,

    #[serde(default)]
    pub mcp: McpPermissions,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpPermissions {
    #[serde(default)]
    pub readonly: bool,

    #[serde(default)]
    pub allowed_zones: Vec<String>,
}

impl AppConfig {
    pub fn starter() -> Self {
        AppConfig {
            servers: vec![DnsServerConfig {
                id: "default".to_string(),
                vendor: VendorKind::Technitium,
                base_url: Some("http://localhost:5380".to_string()),
                token: None,
                token_env: Some("DNSYNC_TECHNITIUM_API_TOKEN".to_string()),
                org_id: None,
                mcp: McpPermissions::default(),
            }],
        }
    }

    pub fn render_starter_toml() -> Result<String> {
        toml::to_string_pretty(&Self::starter())
            .map_err(|e| Error::parse(format!("failed to serialize starter config: {e}")))
    }

    pub fn render_toml(&self) -> Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| Error::parse(format!("failed to serialize config: {e}")))
    }

    /// Returns a copy of the config with every literal `token` value replaced
    /// by `"[redacted]"`. `token_env` values (env var names) are not secrets
    /// and are left as-is.
    pub fn redact(&self) -> Self {
        AppConfig {
            servers: self
                .servers
                .iter()
                .map(|s| DnsServerConfig {
                    token: s.token.as_ref().map(|_| "[redacted]".to_string()),
                    ..s.clone()
                })
                .collect(),
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
                    Error::parse(format!("config does not define a DNS server named '{id}'"))
                });
        }

        match self.servers.as_slice() {
            [server] => Ok(server),
            [] => Err(Error::parse("config file does not define any DNS servers")),
            _ => Err(Error::parse(
                "config file defines multiple DNS servers; select one with --server or DNSYNC_SERVER",
            )),
        }
    }

    fn validate(&self) -> Result<()> {
        let mut ids = std::collections::HashSet::new();
        for server in &self.servers {
            if server.id.trim().is_empty() {
                return Err(Error::parse(
                    "config contains a DNS server with an empty id",
                ));
            }
            if !ids.insert(server.id.to_lowercase()) {
                return Err(Error::parse(format!(
                    "config contains duplicate DNS server id '{}'",
                    server.id
                )));
            }
        }

        Ok(())
    }
}

pub fn init_config(path: Option<PathBuf>, force: bool) -> Result<PathBuf> {
    let Some(path) = path.or_else(default_config_path) else {
        return Err(Error::parse(
            "could not determine a default config path; pass --config <path>",
        ));
    };

    write_default_config(&path, force)?;
    Ok(path)
}

/// Append a new server entry to the config file. Creates the file (with an
/// empty server list plus the new entry) if it does not exist yet.
pub fn add_server(path: Option<PathBuf>, server: DnsServerConfig) -> Result<PathBuf> {
    let Some(path) = path.or_else(default_config_path) else {
        return Err(Error::parse(
            "could not determine a default config path; pass --config <path>",
        ));
    };

    let mut config = if path.exists() {
        load_from_path(&path)?
    } else {
        AppConfig::default()
    };

    config.servers.push(server);
    config.validate()?;

    ensure_config_dir(&path)?;
    write_private_file(&path, &config.render_toml()?)?;
    Ok(path)
}

fn write_default_config(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(Error::parse(format!(
            "config file '{}' already exists; pass --force to overwrite it",
            path.display()
        )));
    }

    ensure_config_dir(path)?;
    let contents = AppConfig::render_starter_toml()?;
    write_private_file(path, &contents)
}

fn ensure_config_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::io(format!("creating config directory '{}'", parent.display()), e)
        })?;
        restrict_dir_permissions(parent)?;
    }
    Ok(())
}

fn load_from_path(path: &Path) -> Result<AppConfig> {
    check_config_permissions(path)?;
    let contents = std::fs::read_to_string(path)
        .map_err(|e| Error::io(format!("reading config file '{}'", path.display()), e))?;
    let config: AppConfig = toml::from_str(&contents).map_err(|e| {
        Error::parse(format!(
            "could not parse config file '{}': {e}",
            path.display()
        ))
    })?;
    config.validate()?;
    Ok(config)
}

/// Write `contents` to `path` with owner-only permissions (0o600 on Unix).
/// Uses `OpenOptions::mode` so the file is never created world-readable,
/// then explicitly sets permissions to handle the overwrite (force) case.
#[cfg(unix)]
fn write_private_file(path: &Path, contents: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| Error::io(format!("creating config file '{}'", path.display()), e))?;

    file.write_all(contents.as_bytes())
        .map_err(|e| Error::io(format!("writing config file '{}'", path.display()), e))?;

    // mode() only applies when the file is newly created; set explicitly for overwrites.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::io(format!("setting permissions on '{}'", path.display()), e))
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents)
        .map_err(|e| Error::io(format!("creating config file '{}'", path.display()), e))
}

/// Restrict the config directory to owner-only access (0o700 on Unix).
#[cfg(unix)]
fn restrict_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::io(format!("setting permissions on '{}'", path.display()), e))
}

#[cfg(not(unix))]
fn restrict_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Error if the config file is readable by anyone other than the owner.
#[cfg(unix)]
fn check_config_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)
        .map_err(|e| Error::io(format!("reading metadata for '{}'", path.display()), e))?;
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::parse(format!(
            "config file '{}' has permissions {:04o} — group or world can read it.\n\
             API tokens must be owner-readable only. Fix with:\n\
             \n    chmod 600 {}",
            path.display(),
            mode,
            path.display(),
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_config_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

impl DnsServerConfig {
    pub fn resolved_base_url(&self, override_url: Option<&str>) -> String {
        override_url
            .map(ToOwned::to_owned)
            .or_else(|| self.base_url.clone())
            .unwrap_or_else(|| "http://localhost:5380".to_string())
    }

    pub fn resolved_token(&self, override_token: Option<&str>) -> Result<ApiToken> {
        if let Some(token) = override_token {
            return Ok(ApiToken::new(token));
        }

        if let Some(ref env_name) = self.token_env {
            return env::var(env_name)
                .map(ApiToken::new)
                .map_err(|_| {
                    Error::parse(format!(
                        "DNS server '{}' requires token env var '{env_name}' to be set",
                        self.id
                    ))
                });
        }

        self.token
            .clone()
            .map(ApiToken::new)
            .ok_or_else(|| {
                Error::parse(format!(
                    "DNS server '{}' has no token configured; set token or token_env in config, or pass --token",
                    self.id
                ))
            })
    }
}

pub fn default_config_path() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    {
        Some(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join(".config")
                .join("dnsync")
                .join("config.toml"),
        )
    }

    #[cfg(not(debug_assertions))]
    env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .map(|dir| dir.join("dnsync").join("config.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_config_path(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();

        env::temp_dir()
            .join("dnsync-config-tests")
            .join(format!("{name}-{}-{nonce}", std::process::id()))
            .join("config.toml")
    }

    fn config() -> AppConfig {
        toml::from_str(
            r#"
                [[servers]]
                id = "home"
                vendor = "technitium"
                base_url = "http://home.local:5380"
                token = "home-token"

                [servers.mcp]
                readonly = true
                allowed_zones = ["example.com", "internal.lan"]

                [[servers]]
                id = "lab"
                vendor = "technitium"
                base_url = "http://lab.local:5380"
                token_env = "LAB_TOKEN"
            "#,
        )
        .expect("config should parse")
    }

    #[test]
    fn parses_per_server_mcp_permissions() {
        let config = config();
        let home = config.selected_server(Some("home")).unwrap();

        assert_eq!(home.id, "home");
        assert_eq!(home.vendor, VendorKind::Technitium);
        assert_eq!(home.base_url.as_deref(), Some("http://home.local:5380"));
        assert!(home.mcp.readonly);
        assert_eq!(home.mcp.allowed_zones, ["example.com", "internal.lan"]);
    }

    #[test]
    fn requires_server_selection_when_multiple_servers_exist() {
        let err = config().selected_server(None).unwrap_err();

        assert!(err.to_string().contains("multiple DNS servers"));
    }

    #[test]
    fn rejects_duplicate_server_ids_case_insensitively() {
        let config: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "home"

                [[servers]]
                id = "HOME"
            "#,
        )
        .expect("config should parse before validation");

        let err = config.validate().unwrap_err();

        assert!(err.to_string().contains("duplicate DNS server id"));
    }

    #[test]
    fn rejects_unknown_mcp_permission_fields() {
        let err = toml::from_str::<AppConfig>(
            r#"
                [[servers]]
                id = "home"

                [servers.mcp]
                read_only = true
            "#,
        )
        .unwrap_err();

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn selected_server_matches_case_insensitively() {
        let config = config();

        assert_eq!(config.selected_server(Some("HOME")).unwrap().id, "home");
    }

    #[test]
    fn load_creates_missing_config_with_defaults() {
        let path = temp_config_path("missing-default");

        let config = AppConfig::load(Some(path.clone()))
            .expect("missing config should be created and loaded")
            .expect("created config should load");

        let server = config.selected_server(None).unwrap();
        assert_eq!(server.id, "default");
        assert_eq!(server.vendor, VendorKind::Technitium);
        assert_eq!(server.base_url.as_deref(), Some("http://localhost:5380"));
        assert_eq!(
            server.token_env.as_deref(),
            Some("DNSYNC_TECHNITIUM_API_TOKEN")
        );
        assert!(server.token.is_none());
        assert!(!server.mcp.readonly);
        assert!(server.mcp.allowed_zones.is_empty());

        // Verify the written file round-trips and uses token_env, not token
        let written = std::fs::read_to_string(&path).unwrap();
        let reparsed: AppConfig = toml::from_str(&written).expect("written config should be valid TOML");
        let reparsed_server = reparsed.selected_server(None).unwrap();
        assert_eq!(reparsed_server.token_env.as_deref(), Some("DNSYNC_TECHNITIUM_API_TOKEN"));
        assert!(reparsed_server.token.is_none());

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn load_does_not_overwrite_existing_config() {
        let path = temp_config_path("existing-config");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"
                [[servers]]
                id = "custom"
                token = "custom-token"
            "#,
        )
        .unwrap();
        // match the permissions the production code sets so the load check passes
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let config = AppConfig::load(Some(path.clone()))
            .expect("existing config should load")
            .expect("config should be present");

        assert_eq!(config.selected_server(None).unwrap().id, "custom");
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("custom-token")
        );

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn init_config_refuses_to_overwrite_existing_config() {
        let path = temp_config_path("init-existing-config");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "existing = true\n").unwrap();

        let err = init_config(Some(path.clone()), false).unwrap_err();

        assert!(err.to_string().contains("already exists"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "existing = true\n");

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn init_config_force_overwrites_existing_config() {
        let path = temp_config_path("init-force-config");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "existing = true\n").unwrap();

        let written_path = init_config(Some(path.clone()), true).unwrap();

        assert_eq!(written_path, path);

        let written = std::fs::read_to_string(&written_path).unwrap();
        let config: AppConfig = toml::from_str(&written).expect("written config should be valid TOML");
        let server = config.selected_server(None).unwrap();
        assert_eq!(server.id, "default");
        assert_eq!(server.token_env.as_deref(), Some("DNSYNC_TECHNITIUM_API_TOKEN"));
        assert!(server.token.is_none());

        std::fs::remove_dir_all(written_path.parent().unwrap()).unwrap();
    }

    #[test]
    fn cli_base_url_override_wins_over_config() {
        let server = config().selected_server(Some("home")).unwrap().clone();

        assert_eq!(
            server.resolved_base_url(Some("http://override.local:5380")),
            "http://override.local:5380"
        );
    }

    #[test]
    fn cli_token_override_wins_over_config() {
        let server = config().selected_server(Some("home")).unwrap().clone();

        assert_eq!(
            server.resolved_token(Some("override-token")).unwrap().expose_for_auth(),
            "override-token"
        );
    }

    #[test]
    fn debug_default_config_path_uses_repo_root() {
        let path = default_config_path().expect("debug builds should have a default config path");

        assert_eq!(
            path,
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join(".config")
                .join("dnsync")
                .join("config.toml")
        );
    }

    #[test]
    fn starter_config_contains_token_env() {
        let toml = AppConfig::render_starter_toml().unwrap();
        assert!(
            toml.contains(r#"token_env = "DNSYNC_TECHNITIUM_API_TOKEN""#),
            "starter TOML should contain token_env assignment"
        );
    }

    #[test]
    fn starter_config_does_not_contain_literal_token() {
        let toml = AppConfig::render_starter_toml().unwrap();
        assert!(
            !toml.lines().any(|l| l.trim_start().starts_with("token =")),
            "starter TOML must not contain a bare `token = ...` key"
        );
    }

    #[test]
    fn starter_config_round_trips() {
        let toml = AppConfig::render_starter_toml().unwrap();
        let reparsed: AppConfig = toml::from_str(&toml).expect("starter TOML should parse back");
        let server = reparsed.selected_server(None).unwrap();
        assert_eq!(server.id, "default");
        assert_eq!(server.vendor, VendorKind::Technitium);
        assert_eq!(server.base_url.as_deref(), Some("http://localhost:5380"));
        assert_eq!(server.token_env.as_deref(), Some("DNSYNC_TECHNITIUM_API_TOKEN"));
        assert!(server.token.is_none());
        assert!(!server.mcp.readonly);
        assert!(server.mcp.allowed_zones.is_empty());
    }

    #[test]
    fn starter_config_validates() {
        AppConfig::starter()
            .validate()
            .expect("starter config should pass validation");
    }

    #[cfg(unix)]
    #[test]
    fn written_config_file_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_config_path("perms-file");

        init_config(Some(path.clone()), false).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "config file should be owner read/write only (0600)");

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn written_config_dir_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_config_path("perms-dir");

        init_config(Some(path.clone()), false).unwrap();

        let dir = path.parent().unwrap();
        let mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "config directory should be owner-only (0700)");

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn redact_replaces_token_but_preserves_token_env() {
        let cfg: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "home"
                token = "secret"
                token_env = "MY_TOKEN_VAR"
            "#,
        )
        .unwrap();

        let redacted = cfg.redact();
        let server = redacted.selected_server(None).unwrap();
        assert_eq!(server.token.as_deref(), Some("[redacted]"));
        assert_eq!(server.token_env.as_deref(), Some("MY_TOKEN_VAR"));
    }

    #[test]
    fn redact_leaves_none_token_as_none() {
        let cfg: AppConfig = toml::from_str(
            r#"
                [[servers]]
                id = "home"
                token_env = "MY_TOKEN_VAR"
            "#,
        )
        .unwrap();

        let redacted = cfg.redact();
        assert!(redacted.selected_server(None).unwrap().token.is_none());
    }

    #[test]
    fn load_if_exists_returns_none_when_no_file() {
        let path = temp_config_path("load-if-exists-missing");
        assert!(!path.exists());

        let result = AppConfig::load_if_exists(Some(path)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn load_if_exists_returns_config_when_file_present() {
        let path = temp_config_path("load-if-exists-present");
        // Use init_config so the file is created with correct permissions
        init_config(Some(path.clone()), false).unwrap();

        let config = AppConfig::load_if_exists(Some(path.clone()))
            .expect("should load")
            .expect("should be Some");
        assert_eq!(config.selected_server(None).unwrap().id, "default");

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn add_server_creates_config_with_single_server() {
        let path = temp_config_path("add-server-new");
        let server = DnsServerConfig {
            id: "myserver".to_string(),
            vendor: VendorKind::Technitium,
            base_url: Some("http://192.168.1.10:5380".to_string()),
            token: None,
            token_env: Some("MY_API_TOKEN".to_string()),
            org_id: None,
            mcp: McpPermissions::default(),
        };

        let written = add_server(Some(path.clone()), server).unwrap();
        assert_eq!(written, path);

        let config = AppConfig::load(Some(path.clone())).unwrap().unwrap();
        let s = config.selected_server(None).unwrap();
        assert_eq!(s.id, "myserver");
        assert_eq!(s.token_env.as_deref(), Some("MY_API_TOKEN"));

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn add_server_appends_to_existing_config() {
        let path = temp_config_path("add-server-existing");
        init_config(Some(path.clone()), false).unwrap();

        let server = DnsServerConfig {
            id: "lab".to_string(),
            vendor: VendorKind::Technitium,
            base_url: Some("http://192.168.1.20:5380".to_string()),
            token: None,
            token_env: Some("LAB_TOKEN".to_string()),
            org_id: None,
            mcp: McpPermissions::default(),
        };

        add_server(Some(path.clone()), server).unwrap();

        let config = AppConfig::load(Some(path.clone())).unwrap().unwrap();
        assert_eq!(config.servers.len(), 2);
        assert!(config.selected_server(Some("default")).is_ok());
        assert!(config.selected_server(Some("lab")).is_ok());

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn add_server_rejects_duplicate_id() {
        let path = temp_config_path("add-server-duplicate");
        init_config(Some(path.clone()), false).unwrap();

        let server = DnsServerConfig {
            id: "default".to_string(), // already exists
            vendor: VendorKind::Technitium,
            base_url: None,
            token: None,
            token_env: None,
            org_id: None,
            mcp: McpPermissions::default(),
        };

        let err = add_server(Some(path.clone()), server).unwrap_err();
        assert!(err.to_string().contains("duplicate DNS server id"));

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn load_errors_if_config_is_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_config_path("world-readable");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, AppConfig::render_starter_toml().unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = AppConfig::load(Some(path.clone())).unwrap_err();

        assert!(err.to_string().contains("chmod 600"), "error should include remediation command");

        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
