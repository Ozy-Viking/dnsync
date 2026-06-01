
use super::*;

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn technitium_env_vars_do_not_populate_global_overrides() {
    let _guard = ENV_LOCK.lock().unwrap();
    // SAFETY: this test serializes access to these process-wide env vars.
    unsafe {
        std::env::set_var("TECHNITIUM_BASE_URL", "http://technitium.local:5380");
        std::env::set_var("TECHNITIUM_API_TOKEN", "technitium-token");
    }

    let cli = Cli::try_parse_from(["dns", "mcp"]).unwrap();

    assert!(cli.base_url.is_none());
    assert!(cli.token.is_none());

    // SAFETY: this test serializes access to these process-wide env vars.
    unsafe {
        std::env::remove_var("TECHNITIUM_BASE_URL");
        std::env::remove_var("TECHNITIUM_API_TOKEN");
    }
}

#[test]
fn settings_accepts_show_secrets_flag() {
    let cli = Cli::try_parse_from(["dns", "settings", "show", "--show-secrets"]).unwrap();

    assert!(matches!(
        cli.command,
        Command::Settings(SettingsCmd::Show { show_secrets: true })
    ));

    let cli = Cli::try_parse_from(["dns", "settings", "show"]).unwrap();

    assert!(matches!(
        cli.command,
        Command::Settings(SettingsCmd::Show {
            show_secrets: false
        })
    ));
}
