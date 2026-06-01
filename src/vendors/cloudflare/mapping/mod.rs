//! Cloudflare-specific DNS record mapping and normalization.
//!
//! Cloudflare's API uses its own JSON payload shapes that differ from the
//! vendor-neutral `core::dns` types. The functions here translate between
//! Cloudflare's format and internal zone-record representations.

mod body;
mod enums;
mod normalize;

pub use body::*;
pub use enums::*;
pub use normalize::*;

pub(crate) use serde_json::Value;

pub(crate) use crate::core::dns::{
    names::relative_to_zone, records::RecordData, responses::ZoneRecord,
};
