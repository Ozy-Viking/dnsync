//! Interactive `config add` / `config server` wizards.
//!
//! Only used on the interactive config paths; production/headless paths never
//! reach these prompts.

mod display;
mod prompts;
mod wizards;

pub(crate) use display::*;
pub(crate) use prompts::*;
pub use wizards::*;

pub(crate) use inquire::validator::Validation;
pub(crate) use inquire::{Confirm, InquireError, MultiSelect, Select, Text};

pub(crate) use crate::control_plane::config::{
    CLOUDFLARE_DEFAULT_BASE_URL, DnsServerConfig, DnsTransportConfig, DohTransportConfig,
    DoqTransportConfig, DotTransportConfig, EndpointUpdate, McpPermissions,
    PANGOLIN_DEFAULT_BASE_URL, PIHOLE_DEFAULT_BASE_URL, ServerLocation,
    TECHNITIUM_DEFAULT_BASE_URL, UNIFI_DEFAULT_BASE_URL, ValidationEndpointConfig, VendorKind,
};
pub(crate) use crate::control_plane::policy::PolicyRule;
pub(crate) use crate::core::error::{Error, Result};
