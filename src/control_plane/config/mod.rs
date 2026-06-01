//! Application configuration.
//!
//! Owns the config file schema, loading/saving, validation, rendering, default
//! resolution, and per-server runtime resolution (base URL, token, location).
//! The submodules split this by responsibility; everything is re-exported here
//! so call sites continue to use `control_plane::config::*` paths.

mod app_config;
mod persist;
mod render;
mod resolve;
mod secure_io;
mod server;
mod types;
mod validate;

pub use persist::*;
pub use resolve::*;
pub use server::*;
pub use types::*;
// Internal-only helpers shared between submodules (no public items to re-export).
pub(crate) use render::*;
pub(crate) use secure_io::*;
pub(crate) use validate::*;

// Shared imports, re-exported so submodules can pull them in via `use super::*;`.
pub(crate) use crate::control_plane::policy::PolicyRule;
pub(crate) use crate::core::error::{Error, Result};
pub(crate) use crate::core::secret::ApiToken;
pub(crate) use hickory_resolver::Resolver;
pub(crate) use regex::Regex;
pub(crate) use serde::{Deserialize, Serialize};
pub(crate) use std::collections::{BTreeMap, HashSet};
pub(crate) use std::env;
pub(crate) use std::net::IpAddr;
pub(crate) use std::path::{Path, PathBuf};

pub const TECHNITIUM_DEFAULT_BASE_URL: &str = "http://localhost:5380";
pub const PANGOLIN_DEFAULT_BASE_URL: &str = "https://api.pangolin.net/v1";
pub const CLOUDFLARE_DEFAULT_BASE_URL: &str = "https://api.cloudflare.com/client/v4";
pub const UNIFI_DEFAULT_BASE_URL: &str = "https://192.168.1.1/proxy/network/integration/v1";
pub const PIHOLE_DEFAULT_BASE_URL: &str = "http://pi.hole";

pub(crate) const CLOUDFLARE_RESOLVER_IP: &str = "1.1.1.1";
pub(crate) const CLOUDFLARE_RESOLVER_NAME: &str = "cloudflare-dns.com";
pub(crate) const CLOUDFLARE_DOH_URL: &str = "https://cloudflare-dns.com/dns-query";

#[cfg(test)]
mod tests;
