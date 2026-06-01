pub mod commands;
pub mod completions;
pub mod dispatch;
pub mod interactive;
pub mod query;
pub mod records;

pub use commands::*;

pub(crate) use clap::{ArgAction, Parser, Subcommand};
pub(crate) use clap_complete::Shell;
pub(crate) use std::path::PathBuf;

pub(crate) use crate::control_plane::policy::PolicyRule;
pub(crate) use crate::core::secret::ApiToken;

// ─── Top-level CLI ───────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
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
    pub token: Option<ApiToken>,

    /// MCP only: allowed operations (comma-separated: read,write,delete); defaults to all if omitted
    #[arg(long, env = "DNS_ACCESS", value_enum, value_delimiter = ',', num_args = 0..)]
    pub access: Vec<PolicyRule>,

    /// MCP only: restrict access to this zone (repeatable); subdomains are also permitted
    #[arg(long, env = "DNS_ALLOWED_ZONES", value_delimiter = ',')]
    pub allow_zone: Vec<String>,

    #[command(subcommand)]
    pub command: Command,

    /// Increase log verbosity: -v = debug, -vv = trace
    #[arg(short, long, action = ArgAction::Count, conflicts_with = "quiet")]
    pub verbose: u8,

    /// Decrease log verbosity: -q = warn, -qq = error, -qqq = off
    #[arg(short, long, action = ArgAction::Count, conflicts_with = "verbose")]
    pub quiet: u8,

    /// Full tracing filter override, e.g. dnsync=trace,tower_http=warn
    #[arg(long, env = "DNSYNC_LOG")]
    pub log_filter: Option<String>,

    #[command(flatten)]
    pub color: colorchoice_clap::Color,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Write a starter config file
    #[command(subcommand)]
    Config(ConfigCmd),

    /// Start the MCP stdio server
    Mcp,

    /// Run the sync daemon in the foreground
    Daemon,

    /// Manage daemon jobs
    #[command(subcommand)]
    Job(JobCmd),

    /// Check if the daemon is healthy (exit 0 = healthy, exit 1 = not healthy)
    Healthcheck,

    /// Manage DNS zones
    #[command(subcommand)]
    Zone(ZoneCmd),

    /// Manage DNS records
    #[command(subcommand)]
    Record(RecordCmd),

    /// Resolve a name directly against the system, a configured server, or any
    /// ad-hoc nameserver. Supports DNS, DoT, DoH, and DoQ transports.
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

    /// Read or write DNS server settings (write is Technitium only)
    #[command(subcommand)]
    Settings(SettingsCmd),

    /// Fetch DNS server logs
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

impl Command {
    /// Get the canonical command name for this `Command` variant.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let cmd = Command::Mcp;
    /// assert_eq!(cmd.name(), "mcp");
    /// ```
    ///
    /// # Returns
    ///
    /// The canonical command name as a static string.
    pub fn name(&self) -> &'static str {
        match self {
            Command::Config(_) => "config",
            Command::Mcp => "mcp",
            Command::Zone(_) => "zone",
            Command::Record(_) => "record",
            Command::Sync { .. } => "sync",
            Command::Cache(_) => "cache",
            Command::Stats { .. } => "stats",
            Command::Blocked(_) => "blocked",
            Command::Allowed(_) => "allowed",
            Command::Settings { .. } => "settings",
            Command::Logs { .. } => "logs",
            Command::Query(_) => "query",
            Command::Daemon => "daemon",
            Command::Job(_) => "job",
            Command::Healthcheck => "healthcheck",
            Command::ServerIds => "server-ids",
            Command::Completions { .. } => "completions",
        }
    }
}

#[cfg(test)]
mod tests;
