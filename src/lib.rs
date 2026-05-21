#[cfg(not(any(feature = "technitium", feature = "pangolin", feature = "cloudflare", feature = "pihole")))]
compile_error!(
    "No DNS vendor feature is enabled. Enable at least one vendor feature, such as `technitium`, `pangolin`, `cloudflare`, or `pihole`."
);

pub mod cli;
pub mod control_plane;
pub mod core;
pub mod mcp;
pub mod vendors;

#[cfg(feature = "technitium")]
pub mod client {
    pub use crate::vendors::technitium::client::*;
}

pub mod dns {
    pub use crate::core::dns::service::*;
    pub use crate::core::dns::*;
}

pub mod error {
    pub use crate::core::error::*;
}

pub mod secret {
    pub use crate::core::secret::ApiToken;
}

pub mod policy {
    pub use crate::control_plane::policy::*;
}

pub mod response {
    pub use crate::core::dns::responses::*;
}

pub mod server {
    pub use crate::mcp::server::*;
}

pub mod types {
    pub use crate::core::dns::records::*;
}
