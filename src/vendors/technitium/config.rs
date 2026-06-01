use crate::core::secret::ApiToken;

/// Technitium vendor configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TechnitiumConfig {
    pub base_url: String,
    pub token: ApiToken,
}
