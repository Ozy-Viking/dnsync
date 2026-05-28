use secrecy::{ExposeSecret, SecretString};
use serde_json::Value;

const SENSITIVE_KEY_PARTS: &[&str] = &[
    "secret",
    "password",
    "token",
    "apikey",
    "privatekey",
    "sharedsecret",
];

/// Marker used in API responses when a field exists but its value is sensitive.
pub const REDACTED_MARKER: &str = "[redacted]";

/// Recursively redact sensitive fields in a JSON value while preserving shape.
pub fn redact_sensitive_fields(mut value: Value) -> Value {
    redact_sensitive_fields_in_place(&mut value);
    value
}

/// Recursively redact sensitive fields in a JSON value while preserving shape.
pub fn redact_sensitive_fields_in_place(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if is_sensitive_key(key) {
                    *value = redacted_value();
                } else {
                    redact_sensitive_fields_in_place(value);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_sensitive_fields_in_place(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = normalize_key(key);
    SENSITIVE_KEY_PARTS
        .iter()
        .any(|part| normalized.contains(part))
}

fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn redacted_value() -> Value {
    let marker = SecretString::from(REDACTED_MARKER.to_owned());
    Value::String(marker.expose_secret().to_owned())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn redacts_nested_object_fields() {
        let settings = json!({
            "response": {
                "tsigKeys": [
                    {
                        "name": "zone-transfer",
                        "sharedSecret": "actual-secret"
                    }
                ]
            }
        });

        let redacted = redact_sensitive_fields(settings);

        assert_eq!(
            redacted["response"]["tsigKeys"][0]["sharedSecret"],
            REDACTED_MARKER
        );
        assert_eq!(redacted["response"]["tsigKeys"][0]["name"], "zone-transfer");
    }

    #[test]
    fn redacts_password_fields_even_when_already_masked() {
        let settings = json!({
            "dnsTlsCertificatePassword": "********",
            "webServiceTlsCertificatePassword": ""
        });

        let redacted = redact_sensitive_fields(settings);

        assert_eq!(redacted["dnsTlsCertificatePassword"], REDACTED_MARKER);
        assert_eq!(
            redacted["webServiceTlsCertificatePassword"],
            REDACTED_MARKER
        );
    }

    #[test]
    fn leaves_unrelated_fields_unchanged() {
        let settings = json!({
            "version": "13.4.1",
            "clusterDomain": "cluster.example.test",
            "dnsServerDomain": "dns.example.test"
        });

        let redacted = redact_sensitive_fields(settings.clone());

        assert_eq!(redacted, settings);
    }

    #[test]
    fn redacts_arrays_of_objects() {
        let settings = json!({
            "providers": [
                { "apiKey": "one", "name": "primary" },
                { "api_token": "two", "name": "secondary" },
                { "private-key": "three", "name": "tertiary" }
            ]
        });

        let redacted = redact_sensitive_fields(settings);

        assert_eq!(redacted["providers"][0]["apiKey"], REDACTED_MARKER);
        assert_eq!(redacted["providers"][1]["api_token"], REDACTED_MARKER);
        assert_eq!(redacted["providers"][2]["private-key"], REDACTED_MARKER);
        assert_eq!(redacted["providers"][2]["name"], "tertiary");
    }
}
