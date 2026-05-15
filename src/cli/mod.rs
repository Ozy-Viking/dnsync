#[cfg(any(feature = "technitium", feature = "pangolin"))]
pub mod runner;

pub mod records;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

// ─── Top-level CLI ───────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "technitium-dns",
    about = "Manage Technitium DNS Server — or run as an MCP server",
    version
)]
pub struct Cli {
    /// Config file path (defaults to $XDG_CONFIG_HOME/dnsync/config.toml or ~/.config/dnsync/config.toml)
    #[arg(long, env = "DNSYNC_CONFIG")]
    pub config: Option<PathBuf>,

    /// DNS server ID from the config file
    #[arg(long, env = "DNSYNC_SERVER")]
    pub server: Option<String>,

    /// Technitium base URL (overrides TECHNITIUM_BASE_URL env)
    #[arg(long, env = "TECHNITIUM_BASE_URL")]
    pub base_url: Option<String>,

    /// API token (overrides TECHNITIUM_API_TOKEN env)
    #[arg(long, env = "TECHNITIUM_API_TOKEN")]
    pub token: Option<String>,

    /// MCP only: reject all write operations
    #[arg(long, env = "DNS_READONLY")]
    pub readonly: bool,

    /// MCP only: restrict access to this zone (repeatable); subdomains are also permitted
    #[arg(long, env = "DNS_ALLOWED_ZONES", value_delimiter = ',')]
    pub allow_zone: Vec<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Write a starter config file
    #[command(subcommand)]
    Config(ConfigCmd),

    /// Start the MCP stdio server (for use with Claude Desktop)
    Mcp,

    /// Manage DNS zones
    #[command(subcommand)]
    Zone(ZoneCmd),

    /// Manage DNS records
    #[command(subcommand)]
    Record(RecordCmd),

    /// Manage the DNS cache
    #[command(subcommand)]
    Cache(CacheCmd),

    /// View server statistics
    Stats {
        /// Stats window: LastHour, LastDay, LastWeek, LastMonth, LastYear
        #[arg(long, default_value = "LastDay")]
        r#type: String,
    },

    /// Manage manually blocked domains
    #[command(subcommand)]
    Blocked(BlockedCmd),

    /// Manage the allowed (whitelist) domains
    #[command(subcommand)]
    Allowed(AllowedCmd),

    /// Show server settings
    Settings,
}

#[derive(Subcommand)]
pub enum ConfigCmd {
    /// Write the starter config file and exit
    Init {
        /// Overwrite an existing config file
        #[arg(long)]
        force: bool,
    },

    /// Print the config to stdout (existing config with tokens redacted, or the
    /// starter template if no config file exists yet)
    Print,

    /// Add a server entry to the config file (creates the file if needed)
    Add {
        /// Unique ID for this server
        #[arg(long)]
        id: String,

        /// DNS vendor backend
        #[arg(long, default_value = "technitium")]
        vendor: crate::control_plane::config::VendorKind,

        /// Base URL of the DNS server API
        #[arg(long)]
        base_url: Option<String>,

        /// Name of the environment variable that holds the API token (recommended)
        #[arg(long)]
        token_env: Option<String>,

        /// API token literal — stored in plain text in the config file; prefer --token-env
        #[arg(long)]
        token: Option<String>,

        /// Organisation ID (Pangolin only)
        #[arg(long)]
        org_id: Option<String>,

        /// Whether the server is on a local network or an external/cloud service
        /// (auto-detected from base_url when omitted)
        #[arg(long)]
        location: Option<crate::control_plane::config::ServerLocation>,

        /// Restrict MCP tools to read-only operations for this server
        #[arg(long)]
        readonly: bool,

        /// Restrict MCP zone-targeting tools to this zone (repeatable)
        #[arg(long, value_name = "ZONE")]
        allow_zone: Vec<String>,
    },
}

// ─── Zone subcommands ────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum ZoneCmd {
    /// List all hosted zones
    List {
        #[arg(long, default_value_t = 1)]
        page: u32,
        #[arg(long, default_value_t = 50)]
        per_page: u32,
    },
    /// Create a new zone
    Create {
        zone: String,
        /// Zone type: Primary, Secondary, Stub, Forwarder
        #[arg(long, default_value = "Primary")]
        r#type: String,
    },
    /// Delete a zone
    Delete { zone: String },
    /// Enable a zone
    Enable { zone: String },
    /// Disable a zone
    Disable { zone: String },
    /// Import a zone file (RFC 1035 format) into an existing zone
    Import {
        zone: String,
        /// Path to the zone file on disk
        file: std::path::PathBuf,
        /// Overwrite existing record sets for imported types (default: true)
        #[arg(long, default_value_t = true)]
        overwrite: bool,
        /// Delete all existing records before importing (clean replace)
        #[arg(long, default_value_t = false)]
        overwrite_zone: bool,
        /// Use the SOA serial from the file instead of auto-incrementing
        #[arg(long, default_value_t = false)]
        overwrite_soa_serial: bool,
    },
}

// ─── Record subcommands ──────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum RecordCmd {
    /// List all records for a domain
    List {
        domain: String,
        #[arg(long)]
        zone: Option<String>,
        /// Prefer a locally-resolved private IP over the provider's public A/AAAA value
        #[arg(long)]
        use_local_ip: bool,
        /// Output raw JSON instead of a table
        #[arg(long)]
        json: bool,
    },
    /// Add a record — type is a subcommand with typed fields
    Add {
        #[arg(long)]
        zone: String,
        #[arg(long)]
        domain: String,
        #[arg(long, default_value_t = 3600)]
        ttl: u32,
        #[command(subcommand)]
        record: CliRecordType,
    },
    /// Delete a record. Value fields are optional — omitting them deletes ALL
    /// records of that type for the domain.
    Delete {
        #[arg(long)]
        zone: String,
        #[arg(long)]
        domain: String,
        #[command(subcommand)]
        record: CliDeleteSelector,
    },
}

/// Identifies a record for deletion. All value fields are optional.
/// Omitting a value deletes every record of that type for the domain.
#[derive(Subcommand, Clone, Debug)]
#[command(rename_all = "lower")]
pub enum CliDeleteSelector {
    /// e.g. `a` (all A records) or `a 1.2.3.4` (specific)
    A {
        ip: Option<std::net::Ipv4Addr>,
    },
    /// e.g. `aaaa` or `aaaa 2001:db8::1`
    Aaaa {
        ip: Option<std::net::Ipv6Addr>,
    },
    Aname {
        aname: Option<String>,
    },
    App {
        app_name: Option<String>,
        class_path: Option<String>,
    },
    Caa {
        value: Option<String>,
    },
    Cname {
        target: Option<String>,
    },
    Dname {
        dname: Option<String>,
    },
    Ds {
        key_tag: Option<u16>,
    },
    Fwd {
        forwarder: Option<String>,
    },
    Https {
        svc_target_name: Option<String>,
    },
    Mx {
        exchange: Option<String>,
    },
    Naptr {
        replacement: Option<String>,
    },
    Ns {
        nameserver: Option<String>,
    },
    Ptr {
        name: Option<String>,
    },
    Sshfp {
        fingerprint: Option<String>,
    },
    Srv {
        target: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        priority: Option<u16>,
        #[arg(long)]
        weight: Option<u16>,
    },
    Svcb {
        svc_target_name: Option<String>,
    },
    Tlsa {
        cert_association_data: Option<String>,
    },
    Txt {
        text: Option<String>,
    },
    Uri {
        uri: Option<String>,
    },
    Unknown {
        rdata: Option<String>,
    },
}

/// One variant per supported DNS record type with exactly the fields that type requires.
///
/// Note: DNSKEY is absent — Technitium manages DNSKEY records automatically
/// via its DNSSEC key management API, not via record add/delete.
#[derive(Subcommand, Clone, Debug)]
#[command(rename_all = "lower")]
pub enum CliRecordType {
    /// IPv4 address  e.g. `a 1.2.3.4`
    A { ip: std::net::Ipv4Addr },

    /// IPv6 address  e.g. `aaaa 2001:db8::1`
    Aaaa { ip: std::net::Ipv6Addr },

    /// Apex alias (Technitium-specific)  e.g. `aname target.example.net`
    Aname { aname: String },

    /// DNS App record  e.g. `app "Split Horizon" "SplitHorizon.SimpleAddress" '{}'`
    App {
        app_name: String,
        class_path: String,
        /// JSON data string passed to the app
        record_data: String,
    },

    /// CA Authorization  e.g. `caa letsencrypt.org --tag issue`
    Caa {
        value: String,
        #[arg(long, default_value_t = 0)]
        flags: u8,
        /// issue, issuewild, or iodef
        #[arg(long, default_value = "issue")]
        tag: String,
    },

    /// Canonical name alias  e.g. `cname www.example.com`
    Cname { target: String },

    /// Subtree redirect  e.g. `dname target.example.com`
    Dname { dname: String },

    /// DNSSEC delegation signer  e.g. `ds 12345 RSASHA256 SHA256 abcdef...`
    Ds {
        key_tag: u16,
        algorithm: crate::core::dns::records::DsAlgorithm,
        digest_type: crate::core::dns::records::DigestType,
        digest: String,
    },

    /// Conditional forwarder (Technitium-specific)  e.g. `fwd 1.1.1.1 --protocol Udp`
    Fwd {
        forwarder: String,
        #[arg(long, default_value = "Udp")]
        protocol: crate::core::dns::records::FwdProtocol,
        #[arg(long, default_value_t = 10)]
        priority: u16,
        #[arg(long, default_value_t = false)]
        dnssec_validation: bool,
    },

    /// HTTPS service binding  e.g. `https --svc-priority 1 svc.example.com`
    Https {
        svc_target_name: String,
        #[arg(long, default_value_t = 1)]
        svc_priority: u16,
        #[arg(long)]
        svc_params: Option<String>,
        #[arg(long, default_value_t = false)]
        auto_ipv4_hint: bool,
        #[arg(long, default_value_t = false)]
        auto_ipv6_hint: bool,
    },

    /// Mail exchange  e.g. `mx mail.example.com --preference 10`
    Mx {
        exchange: String,
        #[arg(long, default_value_t = 10)]
        preference: u16,
    },

    /// Naming authority pointer  e.g. `naptr --order 10 --preference 20 ...`
    Naptr {
        #[arg(long)]
        order: u16,
        #[arg(long)]
        preference: u16,
        #[arg(long, default_value = "")]
        flags: String,
        #[arg(long, default_value = "")]
        services: String,
        #[arg(long, default_value = "")]
        regexp: String,
        replacement: String,
    },

    /// Name server  e.g. `ns ns1.example.com` or `ns ns1.example.com --glue 1.2.3.4`
    Ns {
        nameserver: String,
        #[arg(long)]
        glue: Option<String>,
    },

    /// Reverse DNS pointer  e.g. `ptr host.example.com`
    Ptr { name: String },

    /// SSH fingerprint  e.g. `sshfp RSA SHA256 abcdef...`
    Sshfp {
        algorithm: crate::core::dns::records::SshfpAlgorithm,
        fingerprint_type: crate::core::dns::records::SshfpFingerprintType,
        fingerprint: String,
    },

    /// Service locator  e.g. `srv sip.example.com --port 5060 --priority 10 --weight 20`
    Srv {
        target: String,
        #[arg(long)]
        port: u16,
        #[arg(long, default_value_t = 0)]
        priority: u16,
        #[arg(long, default_value_t = 0)]
        weight: u16,
    },

    /// Service binding (generic)  e.g. `svcb --svc-priority 1 svc.example.com`
    Svcb {
        svc_target_name: String,
        #[arg(long, default_value_t = 1)]
        svc_priority: u16,
        #[arg(long)]
        svc_params: Option<String>,
        #[arg(long, default_value_t = false)]
        auto_ipv4_hint: bool,
        #[arg(long, default_value_t = false)]
        auto_ipv6_hint: bool,
    },

    /// DANE TLS authentication  e.g. `tlsa DANE-EE SPKI SHA2-256 abcdef...`
    Tlsa {
        cert_usage: crate::core::dns::records::TlsaCertUsage,
        selector: crate::core::dns::records::TlsaSelector,
        matching_type: crate::core::dns::records::TlsaMatchingType,
        cert_association_data: String,
    },

    /// Text record  e.g. `txt "v=spf1 ~all"` or `txt "long..." --split-text`
    Txt {
        text: String,
        #[arg(long, default_value_t = false)]
        split_text: bool,
    },

    /// URI record  e.g. `uri https://example.com --priority 10 --weight 1`
    Uri {
        uri: String,
        #[arg(long, default_value_t = 10)]
        priority: u16,
        #[arg(long, default_value_t = 1)]
        weight: u16,
    },

    /// Raw/unknown type — rdata as hex string  e.g. `unknown 0a0b0c...`
    Unknown { rdata: String },
}

// ─── Cache subcommands ───────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum CacheCmd {
    /// Browse the DNS cache for a domain
    List {
        #[arg(default_value = "")]
        domain: String,
    },
    /// Evict a domain from cache
    Delete { domain: String },
    /// Flush the entire DNS cache
    Flush,
}

// ─── Blocked subcommands ─────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum BlockedCmd {
    /// List all blocked domains
    List,
    /// Block a domain
    Add { domain: String },
    /// Unblock a domain
    Delete { domain: String },
}

// ─── Allowed subcommands ─────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum AllowedCmd {
    /// List all whitelisted domains
    List,
    /// Whitelist a domain
    Add { domain: String },
    /// Remove a domain from the whitelist
    Delete { domain: String },
}
