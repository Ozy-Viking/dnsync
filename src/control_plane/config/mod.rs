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
// Compatibility re-export: the type is owned by the UniFi vendor module.
pub use crate::vendors::unifi::UnifiApiMode;
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

pub use crate::vendors::runtime::{
    CLOUDFLARE_DEFAULT_BASE_URL, PANGOLIN_DEFAULT_BASE_URL, PIHOLE_DEFAULT_BASE_URL,
    TECHNITIUM_DEFAULT_BASE_URL, UNIFI_CLOUD_DEFAULT_BASE_URL, UNIFI_DEFAULT_BASE_URL,
};

#[cfg(test)]
mod tests;
