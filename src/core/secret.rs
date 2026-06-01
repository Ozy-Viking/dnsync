use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Placeholder substituted wherever a token would otherwise be printed.
pub const REDACTED: &str = "[REDACTED]";

/// An API token that cannot be accidentally printed or logged.
///
/// Backed by `secrecy::SecretString` (zeroized on drop). `Debug` outputs
/// `ApiToken([REDACTED])` and there is no `Display` impl — any attempt to
/// format the token as a string is a compile error unless the caller explicitly
/// calls [`ApiToken::expose_for_auth`], making every real exposure visible and
/// searchable in code review.
///
/// `secrecy` intentionally refuses to `Serialize` a secret, but `DnsServerConfig`
/// derives `Serialize`, so we provide a `Serialize` impl that **redacts** —
/// serialising a config can never emit the plaintext. The config file is
/// persisted via `toml_edit` using [`ApiToken::expose_for_auth`] at that single
/// boundary, not through this `Serialize` impl.
#[derive(Clone)]
pub struct ApiToken(SecretString);

impl ApiToken {
    pub fn new(s: impl Into<String>) -> Self {
        Self(SecretString::from(s.into()))
    }

    /// Returns the raw token value. Call only at HTTP authentication boundaries.
    pub fn expose_for_auth(&self) -> &str {
        self.0.expose_secret()
    }

    /// Whether the concealed token is empty (without exposing it elsewhere).
    pub fn is_empty(&self) -> bool {
        self.0.expose_secret().is_empty()
    }
}

impl std::fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiToken([REDACTED])")
    }
}

impl From<String> for ApiToken {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for ApiToken {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl std::str::FromStr for ApiToken {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
    }
}

impl PartialEq for ApiToken {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Eq for ApiToken {}

/// Redacts on serialize so an accidental `serde_json`/`toml` serialisation of a
/// config can never emit the plaintext token.
impl Serialize for ApiToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED)
    }
}

impl<'de> Deserialize<'de> for ApiToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        if raw == REDACTED {
            return Err(serde::de::Error::custom(
                "redacted token marker is not a valid API token",
            ));
        }
        Ok(Self::new(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_expose_secret() {
        let token = ApiToken::new("super-secret");
        assert_eq!(format!("{token:?}"), "ApiToken([REDACTED])");
        assert!(!format!("{token:?}").contains("super-secret"));
    }

    #[test]
    fn serialize_does_not_expose_secret() {
        let token = ApiToken::new("super-secret");
        let json = serde_json::to_string(&token).unwrap();
        assert!(!json.contains("super-secret"));
        assert_eq!(json, "\"[REDACTED]\"");
    }

    #[test]
    fn deserialize_round_trips_value() {
        let token: ApiToken = serde_json::from_str("\"super-secret\"").unwrap();
        assert_eq!(token.expose_for_auth(), "super-secret");
    }

    #[test]
    fn deserialize_rejects_redacted_marker() {
        let result: Result<ApiToken, _> = serde_json::from_str("\"[REDACTED]\"");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("redacted token marker is not a valid API token"));
    }

    #[test]
    fn expose_for_auth_returns_raw_value() {
        let token = ApiToken::new("super-secret");
        assert_eq!(token.expose_for_auth(), "super-secret");
    }

    #[test]
    fn clone_preserves_value() {
        let token = ApiToken::new("secret");
        assert_eq!(token.clone().expose_for_auth(), "secret");
    }
}
