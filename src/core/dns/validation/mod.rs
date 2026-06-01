//! DNS endpoint validation.
//!
//! Stable serializable report types, resolver endpoint abstractions, and the
//! record comparison/normalization logic, split into submodules.

mod compare;
mod resolver;
mod types;

pub use compare::*;
pub use resolver::*;
pub use types::*;

// Shared imports, re-exported so submodules can pull them in via `use super::*;`.
pub(crate) use std::{future::Future, time::Duration};

pub(crate) use hickory_resolver::{
    Resolver, net::runtime::TokioRuntimeProvider, proto::rr::RecordType,
};
pub(crate) use schemars::JsonSchema;
pub(crate) use serde::{Deserialize, Serialize};

pub(crate) use crate::{
    control_plane::config::ValidationEndpointConfig,
    core::dns::{
        records::RecordData,
        resolver::{ResolverTarget, build_resolver, classify_hickory_error},
        responses::{AnyRecordData, ListRecordsResponse, ZoneRecord},
    },
};

#[cfg(test)]
mod tests;
