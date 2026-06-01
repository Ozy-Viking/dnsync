use super::run;
use crate::{
    cli::{Cli, Command, ConfigCmd},
    control_plane::{config, policy::Policy},
    core::secret::ApiToken,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn cli(allow_zone: Vec<String>) -> Cli {
    Cli {
        config: None,
        servers: vec![],
        all: false,
        base_url: None,
        token: Some(ApiToken::new("token")),
        access: vec![],
        allow_zone,
        command: Command::Mcp,
        verbose: 0,
        quiet: 0,
        log_filter: None,
        color: colorchoice_clap::Color {
            color: clap::ColorChoice::Never,
        },
    }
}

fn temp_config_path(name: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();

    env!("CARGO_MANIFEST_DIR")
        .parse::<std::path::PathBuf>()
        .unwrap()
        .join("target")
        .join("dnsync-main-tests")
        .join(format!("{name}-{}-{nonce}", std::process::id()))
        .join("config.toml")
}

fn config_cli(path: std::path::PathBuf, force: bool) -> Cli {
    Cli {
        config: Some(path),
        servers: vec![],
        all: false,
        base_url: None,
        token: None,
        access: vec![],
        allow_zone: Vec::new(),
        command: Command::Config(ConfigCmd::Init { force }),
        verbose: 0,
        quiet: 0,
        log_filter: None,
        color: colorchoice_clap::Color {
            color: clap::ColorChoice::Never,
        },
    }
}

#[test]
fn cli_allow_zone_can_narrow_configured_zones() {
    let policy =
        Policy::from_cli_and_config(&cli(vec!["sub.example.com".to_string()]), None).unwrap();

    assert!(policy.check_zone("sub.example.com").is_ok());
    assert!(policy.check_zone("other.example.com").is_err());
}

#[test]
fn cli_allow_zone_cannot_broaden_configured_zones() {
    let config: config::AppConfig = toml::from_str(
        r#"
            [[servers]]
            id = "home"
            vendor = "technitium"
            token = "tok"

            [servers.mcp]
            allowed_zones = ["example.com"]
        "#,
    )
    .unwrap();

    let err = Policy::from_cli_and_config(&cli(vec!["other.net".to_string()]), Some(&config))
        .unwrap_err();

    assert!(err.to_string().contains("outside this server's configured"));
}

#[tokio::test]
async fn config_init_exits_before_token_resolution() {
    let path = temp_config_path("config-init");
    let status = run(config_cli(path.clone(), false)).await;

    assert!(status.is_ok(), "expected Ok, got: {status:?}");
    assert!(path.exists());
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
