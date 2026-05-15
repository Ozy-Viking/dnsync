use std::{
    env,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use crate::core::error::{Error, Result};

const DEFAULT_CONFIG: &str = r#"[[servers]]
id = "default"
vendor = "technitium"
base_url = "http://localhost:5380"
token = "DNSYNC_TECHNITIUM_API_TOKEN"

[servers.mcp]
readonly = false
allowed_zones = []
"#;

/// Supported DNS vendor backends.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VendorKind {
    #[default]
    Technitium,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    #[serde(default)]
    pub servers: Vec<DnsServerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsServerConfig {
    pub id: String,

    #[serde(default)]
    pub vendor: VendorKind,

    pub base_url: Option<String>,
    pub token: Option<String>,
    pub token_env: Option<String>,

    #[serde(default)]
    pub mcp: McpPermissions,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpPermissions {
    #[serde(default)]
    pub readonly: bool,

    #[serde(default)]
    pub allowed_zones: Vec<String>,
}

impl AppConfig {
    pub fn load(path: Option<PathBuf>) -> Result<Option<Self>> {
        let Some(path) = path.or_else(default_config_path) else {
            return Ok(None);
        };

        if !path.exists() {
            write_default_config(&path, false)?;
        }

        let contents = std::fs::read_to_string(&path)
            .map_err(|e| Error::io(format!("reading config file '{}'", path.display()), e))?;

        let config: Self = toml::from_str(&contents).map_err(|e| {
            Error::parse(format!(
                "could not parse config file '{}': {e}",
                path.display()
            ))
        })?;

        config.validate()?;
        Ok(Some(config))
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

fn write_default_config(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(Error::parse(format!(
            "config file '{}' already exists; pass --force to overwrite it",
            path.display()
        )));
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::io(
                format!("creating config directory '{}'", parent.display()),
                e,
            )
        })?;
    }

    std::fs::write(path, DEFAULT_CONFIG)
        .map_err(|e| Error::io(format!("creating config file '{}'", path.display()), e))
}

impl DnsServerConfig {
    pub fn resolved_base_url(&self, override_url: Option<&str>) -> String {
        override_url
            .map(ToOwned::to_owned)
            .or_else(|| env::var("DNSYNC_TECHNITIUM_BASE_URL").ok())
            .or_else(|| self.base_url.clone())
            .unwrap_or_else(|| "http://localhost:5380".to_string())
    }

    pub fn resolved_token(&self, override_token: Option<&str>) -> Result<String> {
        if let Some(token) = override_token {
            return Ok(token.to_string());
        }

        if let Ok(token) = env::var("DNSYNC_TECHNITIUM_API_TOKEN") {
            return Ok(token);
        }

        if let Some(ref env_name) = self.token_env {
            return env::var(env_name).map_err(|_| {
                Error::parse(format!(
                    "DNS server '{}' requires token env var '{}'",
                    self.id, env_name
                ))
            });
        }

        self.token.clone().ok_or_else(|| {
            Error::parse(format!(
                "DNS server '{}' requires an API token from token, token_env, --token, or env",
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
        assert!(!server.mcp.readonly);
        assert!(server.mcp.allowed_zones.is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), DEFAULT_CONFIG);

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
        assert_eq!(
            std::fs::read_to_string(&written_path).unwrap(),
            DEFAULT_CONFIG
        );

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
            server.resolved_token(Some("override-token")).unwrap(),
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
}
