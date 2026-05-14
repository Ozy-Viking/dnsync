#[cfg(not(feature = "technitium"))]
compile_error!(
    "No DNS vendor feature is enabled. Enable at least one vendor feature, such as `technitium`."
);

#[cfg(feature = "technitium")]
pub mod cli;
pub mod control_plane;
pub mod core;
#[cfg(feature = "technitium")]
pub mod mcp;
pub mod vendors;

#[cfg(feature = "technitium")]
pub mod client {
    pub use crate::vendors::technitium::client::*;
}

#[cfg(feature = "technitium")]
pub mod dns {
    pub use crate::vendors::technitium::service::*;
}

pub mod error {
    pub use crate::core::error::*;
}

pub mod policy {
    pub use crate::control_plane::policy::*;
}

pub mod response {
    pub use crate::core::dns::responses::*;
}

#[cfg(feature = "technitium")]
pub mod server {
    pub use crate::mcp::server::*;
}

pub mod types {
    pub use crate::core::dns::records::*;
}
