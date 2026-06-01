//! Record-level sync between two configured DNS servers.
//!
//! `dns sync` reads records from a source server, optionally rewrites IP
//! addresses on A/AAAA records (e.g. external → internal), and writes the
//! difference to a destination server. It is vendor-neutral: it goes through
//! the shared `core::dns` traits, so any pair of supported vendors can sync.
//!
//! Sync is **additive** — it adds records the destination is missing and
//! updates record sets whose values differ, but never prunes whole names that
//! exist only on the destination. It is **dry-run by default**; `--apply`
//! commits the changes.

mod apply;
mod plan;
mod render;
mod run;
mod types;

pub(crate) use apply::*;
pub(crate) use plan::*;
pub(crate) use render::*;
pub use run::*;
pub use types::*;

// Shared imports, re-exported so submodules can pull them in via `use super::*;`.
pub(crate) use std::collections::HashMap;
pub(crate) use std::net::IpAddr;

pub(crate) use regex::Regex;
pub(crate) use tracing::{debug, instrument, trace};

pub(crate) use crate::control_plane::config::AppConfig;
pub(crate) use crate::core::dns::records::RecordData;
pub(crate) use crate::core::dns::records::query::{list_all_zone_names, resolve_fqdn};
pub(crate) use crate::core::dns::responses::{AnyRecordData, ListRecordsResponse};
pub(crate) use crate::core::dns::service::{ListRecordsOptions, RecordWrite, ZoneRead};
pub(crate) use crate::core::error::{Error, Result};
pub(crate) use crate::vendors::runtime::VendorClient;

#[cfg(test)]
mod tests;
