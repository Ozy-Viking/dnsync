use serde::{Deserialize, Serialize};

/// Which UniFi API surface a token is scoped for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum UnifiApiMode {
    Local,
    Remote,
}
