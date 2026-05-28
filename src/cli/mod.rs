pub mod completions;
pub mod interactive;
pub mod query;
pub mod records;
pub mod runner;

use clap::{Parser, Subcommand};
use clap_complete::Shell;
use std::path::PathBuf;

use crate::control_plane::policy::PolicyRule;

// ─── Top-level CLI ───────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "dns", about = "DNS Sync and Control with MCP", version)]
pub struct Cli {
    /// Config file path (defaults to $XDG_CONFIG_HOME/dnsync/config.toml or ~/.config/dnsync/config.toml)
    #[arg(long, env = "DNSYNC_CONFIG")]
    pub config: Option<PathBuf>,

    /// DNS server ID from the config file (repeatable for record list)
    #[arg(long = "server", env = "DNSYNC_SERVER")]
    pub servers: Vec<String>,

    /// Query all configured servers (record list only)
    #[arg(long)]
    pub all: bool,

    /// API base URL override for the selected command only
    #[arg(long)]
    pub base_url: Option<String>,

    /// API token override for the selected command only
    #[arg(long)]
    pub token: Option<String>,

    /// MCP only: allowed operations (comma-separated: read,write,delete); defaults to all if omitted
    #[arg(long, env = "DNS_ACCESS", value_enum, value_delimiter = ',', num_args = 0..)]
    pub access: Vec<PolicyRule>,

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

    /// Start the MCP stdio server
    Mcp,

    /// Manage DNS zones
    #[command(subcommand)]
    Zone(ZoneCmd),

    /// Manage DNS records
    #[command(subcommand)]
    Record(RecordCmd),

    /// Resolve a name directly against the system, a configured server, or any
    /// ad-hoc nameserver. Supports DNS, DoT, DoH, and (with `--features doq`)
    /// DoQ transports.
    #[command(alias = "q")]
    Query(query::QueryArgs),

    /// Sync records between two configured servers, optionally remapping IPs
    Sync {
        /// Named sync profile from the config file
        profile: Option<String>,

        /// Source server ID (overrides the profile's `from`)
        #[arg(long)]
        from: Option<String>,

        /// Destination server ID (overrides the profile's `to`)
        #[arg(long)]
        to: Option<String>,

        /// Zone to sync (repeatable; overrides the profile's zones)
        #[arg(long = "zone", value_name = "ZONE")]
        zone: Vec<String>,

        /// IP rewrite for A/AAAA records, given as SRC=DST (repeatable)
        #[arg(long = "map", value_name = "SRC=DST")]
        map: Vec<String>,

        /// Write the changes (without this flag, sync only previews them)
        #[arg(long)]
        apply: bool,

        /// Output the sync plan as JSON
        #[arg(long)]
        json: bool,
    },

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
    Settings {
        /// Display sensitive settings values instead of redacting them
        #[arg(long)]
        show_secrets: bool,
    },

    /// Fetch DNS query logs
    Logs {
        /// Maximum number of log entries to return
        #[arg(long, default_value_t = 50)]
        lines: u32,
        /// Start time: ISO 8601 (2024-01-01T10:00:00), relative duration (10m, 2h, 1d, 30s),
        /// or time of day (14:30 → most recent occurrence)
        #[arg(long)]
        start: Option<String>,
        /// End time: same format as --start
        #[arg(long)]
        end: Option<String>,
        /// Minimum log level; omit to show all
        #[arg(long, value_enum)]
        level: Option<crate::core::dns::logs::LogLevel>,
    },

    /// Print a shell completion script to stdout.
    ///
    /// Redirect the output to a file in your shell's completions directory:
    ///   dns completions fish > ~/.config/fish/completions/dns.fish
    ///   dns completions bash > ~/.local/share/bash-completion/completions/dns
    ///   dns completions zsh > ~/.zsh/completions/_dns
    Completions { shell: Shell },

    /// Print configured server IDs (used by shell completions)
    #[command(name = "_servers", hide = true)]
    ServerIds,
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

    /// Add a server entry to the config file (creates the file if needed).
    /// Run with no flags to enter interactive setup.
    Add {
        /// Unique ID for this server
        #[arg(long)]
        id: Option<String>,

        /// DNS vendor backend
        #[arg(long, default_value = "technitium")]
        vendor: crate::control_plane::config::VendorKind,

        /// Base URL of the DNS server API
        #[arg(long)]
        base_url: Option<String>,

        /// Name of the environment variable that holds the base URL
        #[arg(long)]
        base_url_env: Option<String>,

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

        /// MCP allowed operations for this server (default: all)
        #[arg(long, value_enum, value_delimiter = ',', num_args = 0.., default_values = &["read", "write", "delete"])]
        access: Vec<PolicyRule>,

        /// Restrict MCP zone-targeting tools to this zone (repeatable)
        #[arg(long, value_name = "ZONE")]
        allow_zone: Vec<String>,

        /// Validation endpoint in name:transport:address format (repeatable; transport: dns, doh, dot)
        #[arg(long = "validation-endpoint", value_name = "NAME:TRANSPORT:ADDRESS")]
        validation_endpoints: Vec<crate::control_plane::config::ValidationEndpointConfig>,
    },

    /// Set or clear a DNS query endpoint on an existing server entry.
    ///
    /// Run with no arguments to enter interactive setup.
    /// Example (non-interactive): dns config server myserver dns --addr 10.0.0.1:53
    Server {
        /// ID of the server to update (case-insensitive).
        /// Omit to be prompted interactively.
        server_id: Option<String>,

        /// Endpoint type and options.
        /// Omit to be prompted interactively.
        #[command(subcommand)]
        endpoint: Option<ServerEndpointCmd>,
    },
}

/// Transport endpoint subcommands for `config server`.
#[derive(Subcommand)]
pub enum ServerEndpointCmd {
    /// Set or clear the plain DNS (port 53) endpoint
    Dns {
        /// Host:port for the DNS server (e.g. 10.0.0.1:53)
        #[arg(long)]
        addr: Option<String>,

        /// Timeout for DNS queries in milliseconds
        #[arg(long)]
        timeout_ms: Option<u64>,

        /// Mark the endpoint as disabled (default: enabled)
        #[arg(long)]
        disable: bool,

        /// Remove the entire [servers.dns] block from the config
        #[arg(long)]
        clear: bool,
    },

    /// Set or clear the DNS-over-TLS (DoT, port 853) endpoint
    Dot {
        /// Host:port for the DoT server (e.g. 10.0.0.1:853)
        #[arg(long)]
        addr: Option<String>,

        /// TLS SNI server name (defaults to the hostname in --addr)
        #[arg(long)]
        server_name: Option<String>,

        /// Timeout for DoT queries in milliseconds
        #[arg(long)]
        timeout_ms: Option<u64>,

        /// Mark the endpoint as disabled (default: enabled)
        #[arg(long)]
        disable: bool,

        /// Remove the entire [servers.dot] block from the config
        #[arg(long)]
        clear: bool,
    },

    /// Set or clear the DNS-over-HTTPS (DoH) endpoint
    Doh {
        /// Full HTTPS URL for the DoH resolver (e.g. https://dns.example.com/dns-query)
        #[arg(long)]
        url: Option<String>,

        /// Host:port to connect to (overrides the address resolved from --url)
        #[arg(long)]
        addr: Option<String>,

        /// TLS SNI server name
        #[arg(long)]
        server_name: Option<String>,

        /// Timeout for DoH queries in milliseconds
        #[arg(long)]
        timeout_ms: Option<u64>,

        /// Mark the endpoint as disabled (default: enabled)
        #[arg(long)]
        disable: bool,

        /// Remove the entire [servers.doh] block from the config
        #[arg(long)]
        clear: bool,
    },

    /// Set or clear the DNS-over-QUIC (DoQ) endpoint
    Doq {
        /// Host:port for the DoQ server (e.g. 10.0.0.1:853)
        #[arg(long)]
        addr: Option<String>,

        /// TLS SNI server name (defaults to the hostname in --addr)
        #[arg(long)]
        server_name: Option<String>,

        /// Timeout for DoQ queries in milliseconds
        #[arg(long)]
        timeout_ms: Option<u64>,

        /// Mark the endpoint as disabled (default: enabled)
        #[arg(long)]
        disable: bool,

        /// Remove the entire [servers.doq] block from the config
        #[arg(long)]
        clear: bool,
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
        #[command(flatten)]
        options: crate::core::dns::zones::ZoneImportOptions,
    },
    /// Export a zone as a BIND-format (RFC 1035) zone file
    Export {
        zone: String,
        /// Write zone file to this path instead of stdout
        #[arg(long, short)]
        output: Option<std::path::PathBuf>,
    },
    /// Copy a zone from one configured server to another
    Transfer {
        zone: String,
        /// Source server ID (must be in config file)
        #[arg(long)]
        from: String,
        /// Destination server ID (must be in config file)
        #[arg(long)]
        to: String,
        /// Overwrite existing record sets in the destination for imported types (default: true)
        #[arg(long, default_value_t = true)]
        overwrite: bool,
        /// Delete all existing records in the destination before importing (clean replace)
        #[arg(long, default_value_t = false)]
        overwrite_zone: bool,
    },
}

// ─── Record subcommands ──────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum RecordCmd {
    /// List DNS records, optionally filtered to a domain
    List {
        /// Domain to look up. Omitting it lists records for all hosted zones.
        /// A bare label (e.g. `huly`) can be combined with --zone, or searched
        /// across all zones when --zone is omitted.
        domain: Option<String>,
        /// Zone the domain belongs to.  When given, a bare domain label is automatically
        /// qualified: `huly` + `--zone hankin.io` → `huly.hankin.io`.
        #[arg(long)]
        zone: Option<String>,
        /// Also show records for every subdomain of the given domain
        #[arg(long)]
        all_subdomains: bool,
        /// Server IDs to query (repeatable); ignored when --all is used
        #[arg(long = "server", value_name = "ID")]
        servers: Vec<String>,
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
        record: crate::core::dns::records::RecordData,
    },
    /// Delete a record. Value fields are optional — omitting them deletes ALL
    /// records of that type for the domain.
    Delete {
        #[arg(long)]
        zone: String,
        #[arg(long)]
        domain: String,
        #[command(subcommand)]
        record: crate::core::dns::records::RecordSelector,
    },
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

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn technitium_env_vars_do_not_populate_global_overrides() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: this test serializes access to these process-wide env vars.
        unsafe {
            std::env::set_var("TECHNITIUM_BASE_URL", "http://technitium.local:5380");
            std::env::set_var("TECHNITIUM_API_TOKEN", "technitium-token");
        }

        let cli = Cli::try_parse_from(["dns", "mcp"]).unwrap();

        assert!(cli.base_url.is_none());
        assert!(cli.token.is_none());

        // SAFETY: this test serializes access to these process-wide env vars.
        unsafe {
            std::env::remove_var("TECHNITIUM_BASE_URL");
            std::env::remove_var("TECHNITIUM_API_TOKEN");
        }
    }

    #[test]
    fn settings_accepts_show_secrets_flag() {
        let cli = Cli::try_parse_from(["dns", "settings", "--show-secrets"]).unwrap();

        assert!(matches!(
            cli.command,
            Command::Settings { show_secrets: true }
        ));

        let cli = Cli::try_parse_from(["dns", "settings"]).unwrap();

        assert!(matches!(
            cli.command,
            Command::Settings {
                show_secrets: false
            }
        ));
    }
}
