use super::*;

use crate::control_plane::config::AppConfig;

fn make_server(config: AppConfig) -> DnsServer {
    DnsServer::new(config, vec![], vec![])
}

#[tokio::test]
async fn dns_get_config_returns_toml() {
    let config: AppConfig = toml::from_str(
        r#"
            [[servers]]
            id = "primary"
            vendor = "technitium"
            token = "supersecret"
            "#,
    )
    .unwrap();
    let server = make_server(config);
    let result = server.dns_get_config().await.unwrap();
    assert!(!result.is_error.unwrap_or(false));
    let text = result.content[0]
        .as_text()
        .expect("expected text content")
        .text
        .clone();
    // Must be parseable TOML
    let parsed: toml::Value = toml::from_str(&text).expect("output should be valid TOML");
    // Token must be redacted
    let token = parsed["servers"][0]["token"].as_str().unwrap();
    assert_eq!(token, "[redacted]");
}

#[tokio::test]
async fn dns_get_config_preserves_token_env() {
    let config: AppConfig = toml::from_str(
        r#"
            [[servers]]
            id = "primary"
            vendor = "technitium"
            token_env = "MY_DNS_TOKEN"
            "#,
    )
    .unwrap();
    let server = make_server(config);
    let result = server.dns_get_config().await.unwrap();
    assert!(!result.is_error.unwrap_or(false));
    let text = result.content[0]
        .as_text()
        .expect("expected text content")
        .text
        .clone();
    let parsed: toml::Value = toml::from_str(&text).expect("output should be valid TOML");
    // token_env should be preserved as-is
    let token_env = parsed["servers"][0]["token_env"].as_str().unwrap();
    assert_eq!(token_env, "MY_DNS_TOKEN");
    // token key should not appear (was None)
    assert!(parsed["servers"][0].get("token").is_none());
}

#[tokio::test]
async fn dns_version_returns_package_version() {
    let server = make_server(AppConfig::default());
    let result = server.dns_version().await.unwrap();
    assert!(!result.is_error.unwrap_or(false));
    let value: serde_json::Value = serde_json::from_str(&result.content[0].as_text().unwrap().text)
        .expect("output should be valid JSON");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
}
