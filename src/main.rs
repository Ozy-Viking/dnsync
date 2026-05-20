#[cfg(not(any(feature = "technitium", feature = "pangolin", feature = "cloudflare")))]
compile_error!(
    "No DNS vendor feature is enabled. Enable at least one vendor feature, such as `technitium`, `pangolin`, or `cloudflare`."
);

#[cfg(not(any(feature = "technitium", feature = "pangolin", feature = "cloudflare")))]
fn main() {}

#[cfg(any(feature = "technitium", feature = "pangolin", feature = "cloudflare"))]
#[tokio::main]
async fn main() {
    use clap::Parser;
    use dnslib::cli::Cli;
    use tracing_subscriber::{EnvFilter, fmt};

    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    std::process::exit(dnslib::cli::runner::execute(cli).await);
}
