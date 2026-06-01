//! `dns query` — direct DNS lookups (dig-style).
//!
//! Resolves a name via the system resolver by default, or via a
//! configured `[[servers]]` entry (`--server <ID>` + one or more of
//! `--dns`/`--dot`/`--doh`/`--doq` or `--all`), or via an ad-hoc
//! resolver (`--at <ADDR>` or dig-style `@ADDR` positional).
//!
//! Output is dig-flavoured: a header line starting with `@`, a blank
//! line, then a column-aligned table of answers (one block per
//! transport when fanning out). `--short` emits answers only;
//! `--json` emits a stable JSON shape.

mod args;
mod execute;
mod output_json;
mod output_table;
mod parse;
mod plan;
mod result;
mod run;

pub use args::*;
pub(crate) use execute::*;
pub(crate) use output_json::*;
pub(crate) use output_table::*;
pub(crate) use parse::*;
pub(crate) use plan::*;
pub use result::*;
pub use run::*;

// Shared imports, re-exported so submodules can pull them in via `use super::*;`.
pub(crate) use std::fmt::Write;
pub(crate) use std::time::{Duration, Instant};

pub(crate) use clap::Args;
pub(crate) use hickory_resolver::{
    Resolver, config::ResolverOpts, net::runtime::TokioRuntimeProvider, proto::rr::Record,
    proto::rr::RecordType,
};
pub(crate) use serde::Serialize;
pub(crate) use serde_json::json;
pub(crate) use tracing::{Span, instrument};

pub(crate) use crate::{
    control_plane::{
        app::select_query_servers,
        config::{AppConfig, DnsServerConfig, ValidationTransport, VendorKind},
    },
    core::{
        dns::{
            resolver::{ResolverKind, ResolverTarget, build_resolver, classify_hickory_error},
            validation::{ObservedRecord, ValidationFailureKind},
        },
        error::{Error, Result},
    },
};

#[cfg(test)]
mod tests;
