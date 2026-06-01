//! choice list item types and label/summary formatting.

use super::*;

// ─── Formatting helpers ───────────────────────────────────────────────────────

pub(crate) fn format_endpoint_label(protocol: &str, description: &str, status: String) -> String {
    format!("{protocol:<4}  {description:<30}  {status}")
}

/// Returns a short status string for an addr-based endpoint (dns/dot/doq).
/// When `is_url` is true, uses url instead of addr.
pub(crate) fn endpoint_addr_status<T: EndpointInfo>(endpoint: Option<&T>, is_url: bool) -> String {
    match endpoint {
        None => "not configured".to_string(),
        Some(ep) => {
            let target = if is_url {
                ep.url_str().unwrap_or_else(|| ep.addr_str().unwrap_or("?"))
            } else {
                ep.addr_str().unwrap_or("?")
            };
            let state = if ep.is_enabled() {
                "enabled"
            } else {
                "disabled"
            };
            format!("{state} → {target}")
        }
    }
}

pub(crate) fn format_server_summary(server: &DnsServerConfig) -> String {
    let vendor = match server.vendor {
        crate::control_plane::config::VendorKind::Technitium => "technitium",
        crate::control_plane::config::VendorKind::Pangolin => "pangolin",
        crate::control_plane::config::VendorKind::Cloudflare => "cloudflare",
        crate::control_plane::config::VendorKind::Unifi => "unifi",
        crate::control_plane::config::VendorKind::Pihole => "pihole",
    };
    let url = server.base_url.as_deref().unwrap_or("(default)");
    format!("{}  [{vendor}]  {url}", server.id)
}

// ─── Trait to unify transport config access for status formatting ─────────────

pub(crate) trait EndpointInfo {
    fn is_enabled(&self) -> bool;
    fn addr_str(&self) -> Option<&str>;
    fn url_str(&self) -> Option<&str> {
        None
    }
}

impl EndpointInfo for DnsTransportConfig {
    fn is_enabled(&self) -> bool {
        self.enabled
    }
    fn addr_str(&self) -> Option<&str> {
        self.addr.as_deref()
    }
}

impl EndpointInfo for DotTransportConfig {
    fn is_enabled(&self) -> bool {
        self.enabled
    }
    fn addr_str(&self) -> Option<&str> {
        self.addr.as_deref()
    }
}

impl EndpointInfo for DohTransportConfig {
    fn is_enabled(&self) -> bool {
        self.enabled
    }
    fn addr_str(&self) -> Option<&str> {
        self.addr.as_deref()
    }
    fn url_str(&self) -> Option<&str> {
        self.url.as_deref()
    }
}

impl EndpointInfo for DoqTransportConfig {
    fn is_enabled(&self) -> bool {
        self.enabled
    }
    fn addr_str(&self) -> Option<&str> {
        self.addr.as_deref()
    }
}

// ─── Display wrappers so Select/MultiSelect can render enum variants ──────────

pub(crate) struct VendorChoice {
    pub(crate) kind: VendorKind,
    pub(crate) label: &'static str,
}

impl std::fmt::Display for VendorChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label)
    }
}

pub(crate) struct LocationChoice {
    pub(crate) value: Option<ServerLocation>,
    pub(crate) label: &'static str,
}

impl std::fmt::Display for LocationChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label)
    }
}

pub(crate) struct AccessChoice {
    pub(crate) rule: PolicyRule,
    pub(crate) label: &'static str,
}

impl std::fmt::Display for AccessChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label)
    }
}

pub(crate) struct ProtocolChoice {
    pub(crate) id: u8,
    pub(crate) label: &'static str,
}

impl std::fmt::Display for ProtocolChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label)
    }
}

pub(crate) enum EndpointProtocol {
    Dns,
    Dot,
    Doh,
    Doq,
}

pub(crate) struct EndpointChoice {
    pub(crate) protocol: EndpointProtocol,
    pub(crate) label: String,
}

impl std::fmt::Display for EndpointChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label)
    }
}

pub(crate) enum EndpointAction {
    Configure,
    Remove,
}

pub(crate) struct ActionChoice {
    pub(crate) action: EndpointAction,
    pub(crate) label: &'static str,
}

impl std::fmt::Display for ActionChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label)
    }
}

pub(crate) struct ServerChoice {
    pub(crate) id: String,
    pub(crate) label: String,
}

impl std::fmt::Display for ServerChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label)
    }
}
