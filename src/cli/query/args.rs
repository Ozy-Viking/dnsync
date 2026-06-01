//! `QueryArgs` CLI definition and query constants.

use super::*;

/// Default per-attempt timeout when no `--timeout` and no per-block
/// `timeout_ms` is configured.
pub(crate) const DEFAULT_TIMEOUT_MS: u64 = 5_000;

/// Order in which transports render and run when fanning out, and the
/// precedence used to pick a server's *default* transport when none is
/// requested explicitly. Plain DNS is first (the universally-available
/// baseline); DoQ is last because it is an opt-in build. A server with
/// a single configured transport block uses that block as its default
/// regardless of where the block sits in this list.
pub const TRANSPORT_PRECEDENCE: [ValidationTransport; 4] = [
    ValidationTransport::Dns,
    ValidationTransport::Dot,
    ValidationTransport::Doh,
    ValidationTransport::Doq,
];

pub(crate) const DEFAULT_RECORD_TYPES: [&str; 10] = [
    "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA", "PTR", "SOA",
];

#[derive(Args, Debug, Clone, Default)]
pub struct QueryArgs {
    /// Domain to resolve, plus an optional dig-style `@ADDR` positional
    /// (alias for `--at`). The non-`@` positional is the domain; the
    /// `@`-prefixed one, if any, is the ad-hoc resolver target.
    pub targets: Vec<String>,

    /// Record type, repeatable (default: query all supported standard
    /// types). Standard mnemonics:
    /// `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SRV`, `CAA`, `PTR`,
    /// `SOA`, `ANY`.
    #[arg(short = 't', long = "type", value_name = "RR")]
    pub r#type: Vec<String>,

    /// A configured `[[servers]]` entry to query, repeatable. Each is
    /// matched case-insensitively against `server.id`. Mutually
    /// exclusive with `--at`/`@ADDR`. Pass `--server` more than once to
    /// fan out across several servers, or use `--all-servers`.
    #[arg(long)]
    pub server: Vec<String>,

    /// Ad-hoc resolver. `host[:port]` or `scheme://host[:port][/path]`.
    /// Schemes recognised: `udp://`, `tcp://`, `dns://`, `tls://`,
    /// `dot://`, `https://`, `doh://`, `quic://`, `doq://`.
    #[arg(long)]
    pub at: Option<String>,

    /// Use the `[servers.dns]` block (plain DNS). With `--at`, forces
    /// plain DNS.
    #[arg(long)]
    pub dns: bool,

    /// Use the `[servers.dot]` block (DoT). With `--at`, forces DoT.
    #[arg(long)]
    pub dot: bool,

    /// Use the `[servers.doh]` block (DoH). With `--at`, forces DoH.
    #[arg(long)]
    pub doh: bool,

    /// Use the `[servers.doq]` block (DoQ). With `--at`, forces DoQ.
    /// Requires the `doq` Cargo feature.
    #[arg(long)]
    pub doq: bool,

    /// Query every transport block (DNS/DoT/DoH/DoQ) present and
    /// `enabled = true` on the target. Requires a server target
    /// (`--server`/`--all-servers`). Mutually exclusive with the
    /// individual `--dns`/`--dot`/`--doh`/`--doq` flags.
    #[arg(long)]
    pub all_transports: bool,

    /// Query every configured `[[servers]]` entry. Cannot be combined
    /// with `--at`/`@ADDR`. Without a transport flag, each server is
    /// queried over its default transport (see precedence).
    #[arg(long)]
    pub all_servers: bool,

    /// Query every supported record type, overriding any `-t`/`--type`.
    /// This is also the default when no `-t` is given.
    #[arg(long)]
    pub all_types: bool,

    /// Shorthand for `--all-servers --all-types --all-transports`:
    /// every server, every record type, every enabled transport.
    #[arg(long)]
    pub all: bool,

    /// Override the port. Defaults: DNS 53, DoT 853, DoH 443, DoQ 853.
    /// Only valid with an ad-hoc target.
    #[arg(long)]
    pub port: Option<u16>,

    /// SNI / certificate name override for DoT, DoH, DoQ. Only valid
    /// with an ad-hoc target.
    #[arg(long = "tls-server-name")]
    pub tls_server_name: Option<String>,

    /// Per-attempt timeout in milliseconds (default 5000).
    #[arg(long)]
    pub timeout: Option<u64>,

    /// With `--dns`, force TCP only for the plain-DNS query (skip
    /// UDP). Ignored for other transports.
    #[arg(long)]
    pub tcp: bool,

    /// Follow CNAME (and DNAME) chains to their terminal address
    /// records. Without this, a single-type query like `-t CNAME` shows
    /// only the CNAME hop; with it, the chain is walked to its A/AAAA
    /// terminal and the whole chain is shown in order. Bounded against
    /// loops by a depth limit.
    #[arg(long, visible_alias = "chain")]
    pub chase: bool,

    /// Print only the data column. Mirrors `dig +short`.
    #[arg(long)]
    pub short: bool,

    /// Emit structured JSON output.
    #[arg(long)]
    pub json: bool,
}

/// Maximum number of chain hops `--chase` will follow before giving up,
/// guarding against CNAME loops and pathologically long chains.
pub(crate) const MAX_CHASE_DEPTH: usize = 8;

/// Record types `--chase` looks up when walking to a chain's terminal:
/// further CNAME/DNAME hops to keep walking, plus the address types that
/// end it.
pub(crate) const CHASE_TYPES: [&str; 4] = ["CNAME", "DNAME", "A", "AAAA"];
