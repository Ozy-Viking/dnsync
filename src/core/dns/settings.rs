use serde_json::Value;

use crate::core::{
    dns::service::{SettingsRead, SettingsWrite},
    error::{Error, Result},
    redaction::redact_sensitive_fields,
};

/// Get DNS server settings through a vendor-neutral settings reader.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn get_settings<C: SettingsRead + ?Sized>(client: &C) -> Result<Value> {
    client.get_settings().await.map(redact_sensitive_fields)
}

/// Get DNS server settings without redacting sensitive fields.
///
/// Use only for explicit user-facing opt-in paths.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend.
pub async fn get_settings_unredacted<C: SettingsRead + ?Sized>(client: &C) -> Result<Value> {
    client.get_settings().await
}

/// Write server-level settings via a vendor-neutral settings writer.
///
/// The `settings` value must be a JSON object. Technitium applies partial
/// updates — only provided keys are changed.
///
/// # Errors
///
/// Returns any error reported by the selected DNS backend, including
/// `Error::Unsupported` for vendors that do not support settings write.
pub async fn set_settings<C: SettingsWrite + ?Sized>(
    client: &C,
    settings: &Value,
) -> Result<Value> {
    if !settings.is_object() {
        return Err(Error::parse("settings must be a JSON object"));
    }
    client.set_settings(settings).await
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::core::{error::Result, redaction::REDACTED_MARKER};

    struct FakeSettingsRead {
        settings: Value,
    }

    impl SettingsRead for FakeSettingsRead {
        async fn get_settings(&self) -> Result<Value> {
            Ok(self.settings.clone())
        }
    }

    #[tokio::test]
    async fn get_settings_redacts_before_returning() {
        let client = FakeSettingsRead {
            settings: json!({
                "version": "13.4.1",
                "tsigKeys": [{ "sharedSecret": "actual-secret" }]
            }),
        };

        let settings = get_settings(&client).await.unwrap();

        assert_eq!(settings["version"], "13.4.1");
        assert_eq!(settings["tsigKeys"][0]["sharedSecret"], REDACTED_MARKER);
    }

    #[tokio::test]
    async fn get_settings_unredacted_preserves_secret_values() {
        let client = FakeSettingsRead {
            settings: json!({
                "version": "13.4.1",
                "tsigKeys": [{ "sharedSecret": "actual-secret" }]
            }),
        };

        let settings = get_settings_unredacted(&client).await.unwrap();

        assert_eq!(settings["version"], "13.4.1");
        assert_eq!(settings["tsigKeys"][0]["sharedSecret"], "actual-secret");
    }
}
