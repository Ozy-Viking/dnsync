use secrecy::{ExposeSecret, SecretString};

/// An API token that cannot be accidentally printed or logged.
///
/// `Debug` outputs `ApiToken([REDACTED])`. There is no `Display` impl —
/// any attempt to format the token as a string is a compile error unless
/// the caller explicitly calls `expose_for_auth`, making every real exposure
/// visible and searchable in code review.
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
