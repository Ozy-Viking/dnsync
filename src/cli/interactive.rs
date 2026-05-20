use inquire::{Confirm, Select, Text};

use crate::control_plane::config::{DnsServerConfig, McpPermissions, ServerLocation};
use crate::vendors::{
    VendorKind,
    cloudflare::CLOUDFLARE_DEFAULT_BASE_URL,
    pangolin::PANGOLIN_DEFAULT_BASE_URL,
    technitium::TECHNITIUM_DEFAULT_BASE_URL,
};

pub fn run_add_wizard() -> miette::Result<DnsServerConfig> {
    let id = Text::new("Server ID:")
        .with_help_message("Unique identifier for this server entry")
        .prompt()
        .map_err(wizard_err)?;

    let vendor = {
        let choices = vec![
            VendorChoice {
                kind: VendorKind::Technitium,
                label: "technitium",
            },
            VendorChoice {
                kind: VendorKind::Pangolin,
                label: "pangolin",
            },
            VendorChoice {
                kind: VendorKind::Cloudflare,
                label: "cloudflare",
            },
        ];
        Select::new("Vendor:", choices)
            .prompt()
            .map_err(wizard_err)?
            .kind
    };

    let default_url = match vendor {
        VendorKind::Technitium => TECHNITIUM_DEFAULT_BASE_URL,
        VendorKind::Pangolin => PANGOLIN_DEFAULT_BASE_URL,
        VendorKind::Cloudflare => CLOUDFLARE_DEFAULT_BASE_URL,
    };

    let base_url = optional_text(
        "Base URL:",
        &format!("Press Enter for default ({default_url}), or type a custom URL"),
        Some(default_url),
    )?;

    let token_env = optional_text(
        "Token environment variable:",
        "Name of the env var holding the API token (recommended). Leave empty to skip.",
        None,
    )?;

    let token = if token_env.is_none() {
        optional_text(
            "API token (stored in plain text — prefer token env var above):",
            "Leave empty to skip",
            None,
        )?
    } else {
        None
    };

    let org_id = if matches!(vendor, VendorKind::Pangolin) {
        optional_text("Organisation ID (Pangolin):", "Leave empty to skip", None)?
    } else {
        None
    };

    let location = {
        let choices = vec![
            LocationChoice {
                value: None,
                label: "auto-detect",
            },
            LocationChoice {
                value: Some(ServerLocation::Local),
                label: "local",
            },
            LocationChoice {
                value: Some(ServerLocation::External),
                label: "external",
            },
        ];
        Select::new("Location:", choices)
            .with_help_message(
                "auto-detect infers from the base URL (localhost/private IP → local)",
            )
            .prompt()
            .map_err(wizard_err)?
            .value
    };

    let readonly = Confirm::new("Read-only?")
        .with_default(false)
        .with_help_message("Restrict MCP tools to read-only operations for this server")
        .prompt()
        .map_err(wizard_err)?;

    let mut allowed_zones: Vec<String> = Vec::new();
    loop {
        let zone = Text::new("Allowed zone (leave empty to finish):")
            .with_help_message(
                "Restrict zone-targeting MCP tools to this zone; subdomains are also permitted",
            )
            .prompt()
            .map_err(wizard_err)?;
        if zone.is_empty() {
            break;
        }
        allowed_zones.push(zone);
    }

    Ok(DnsServerConfig {
        id,
        vendor,
        location,
        base_url,
        token,
        token_env,
        org_id,
        mcp: McpPermissions {
            readonly,
            allowed_zones,
        },
    })
}

fn optional_text(label: &str, help: &str, default: Option<&str>) -> miette::Result<Option<String>> {
    let mut builder = Text::new(label).with_help_message(help);
    if let Some(d) = default {
        builder = builder.with_default(d);
    }
    let val = builder.prompt().map_err(wizard_err)?;
    Ok(if val.is_empty() { None } else { Some(val) })
}

fn wizard_err(e: inquire::InquireError) -> miette::Error {
    miette::miette!("{e}")
}

// ─── Display wrappers so Select can render enum variants ─────────────────────

struct VendorChoice {
    kind: VendorKind,
    label: &'static str,
}

impl std::fmt::Display for VendorChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label)
    }
}

struct LocationChoice {
    value: Option<ServerLocation>,
    label: &'static str,
}

impl std::fmt::Display for LocationChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label)
    }
}
