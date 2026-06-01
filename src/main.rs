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

#[cfg(not(any(
    feature = "technitium",
    feature = "pangolin",
    feature = "cloudflare",
    feature = "unifi",
    feature = "pihole"
)))]
fn main() {}

#[cfg(any(
    feature = "technitium",
    feature = "pangolin",
    feature = "cloudflare",
    feature = "unifi",
    feature = "pihole"
))]
#[tokio::main]
async fn main() -> miette::Result<()> {
    use clap::Parser;
    use dnslib::{cli::Cli, cli::dispatch, setup::init_tracing};

    let cli = Cli::parse();
    init_tracing(&cli)?;
    dispatch::run(cli).await?;
    Ok(())
}
