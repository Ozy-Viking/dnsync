#[cfg(not(any(
    feature = "technitium",
    feature = "pangolin",
    feature = "cloudflare",
    feature = "unifi",
    feature = "pihole"
)))]
compile_error!(
    "No DNS vendor feature is enabled. Enable at least one vendor feature, such as `technitium`, `pangolin`, `cloudflare`, `unifi`, or `pihole`."
);

pub mod cli;
pub mod control_plane;
pub mod core;
pub mod daemon;
pub mod formatter;
pub mod mcp;
pub mod vendors;

#[cfg(feature = "technitium")]
pub mod client {
    pub use crate::vendors::technitium::client::*;
}

pub mod dns {
    pub use crate::core::dns::service::*;
    pub use crate::core::dns::validation::*;
    pub use crate::core::dns::*;
}

pub mod error {
    pub use crate::core::error::*;
}

pub mod secret {
    pub use crate::core::secret::ApiToken;
}

pub mod policy {
    pub use crate::control_plane::policy::*;
}

pub mod response {
    pub use crate::core::dns::responses::*;
}

pub mod server {
    pub use crate::mcp::server::*;
}

pub mod types {
    pub use crate::core::dns::records::*;
}

pub mod setup {
    use super::formatter::{DnsEventFormat, DnsFields};
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::{EnvFilter, fmt};
    pub const DEFAULT_LOG_LEVEL: &str = "warn";

    use crate::cli::Cli;

    pub fn init_tracing(cli: &Cli) -> miette::Result<()> {
        cli.color.write_global();
        let app_level = level_from_verbosity(cli.verbose, cli.quiet);
        let ansi = tracing_use_ansi(cli.color);
        let filter_string = cli
            .log_filter
            .clone()
            .unwrap_or_else(|| format!("dns={app_level},{DEFAULT_LOG_LEVEL}"));

        let filter = EnvFilter::try_new(&filter_string)
            .map_err(|err| miette::miette!("invalid tracing filter `{filter_string}`: {err}"))?;

        fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_ansi(ansi)
            .fmt_fields(DnsFields)
            .event_format(DnsEventFormat)
            .init();

        tracing::info!(
            filter = %filter_string,
            app_level = %app_level,
            ansi,
            "tracing initialised"
        );
        Ok(())
    }

    fn tracing_use_ansi(color: colorchoice_clap::Color) -> bool {
        use std::io::IsTerminal;
        match color.color {
            colorchoice_clap::ColorChoice::Always => true,
            colorchoice_clap::ColorChoice::Never => false,
            colorchoice_clap::ColorChoice::Auto => std::io::stderr().is_terminal(),
        }
    }
    fn level_from_verbosity(verbose: u8, quiet: u8) -> LevelFilter {
        match (verbose, quiet) {
            (_, 3..) => LevelFilter::OFF,
            (_, 2) => LevelFilter::ERROR,
            (_, 1) => LevelFilter::WARN,

            (0, 0) => LevelFilter::INFO,
            (1, 0) => LevelFilter::DEBUG,
            (2.., 0) => LevelFilter::TRACE,
        }
    }
}
