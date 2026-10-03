//! `svx-mock-idp` — development-only OIDC provider.
//!
//! ```sh
//! svx-mock-idp --listen 127.0.0.1:8081 --config examples/idp-example-corp.json
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;
use svx_mock_idp::{Config, MockIdp};

#[derive(Parser)]
#[command(
    name = "svx-mock-idp",
    version,
    about = "DEVELOPMENT-ONLY OIDC provider for SVX demos and tests"
)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:8081")]
    listen: SocketAddr,
    /// JSON file: {"client_id": "...", "users": [{"sub": "alice", "groups": [...]}]}
    #[arg(long)]
    config: PathBuf,
    /// Allow binding to a non-loopback address. This IdP logs anyone in
    /// without a password; never do this on a reachable network.
    #[arg(long)]
    i_know_this_is_insecure: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if !args.listen.ip().is_loopback() && !args.i_know_this_is_insecure {
        bail!(
            "refusing to bind the dev IdP to non-loopback address {}",
            args.listen
        );
    }
    let config: Config = serde_json::from_slice(
        &std::fs::read(&args.config)
            .with_context(|| format!("reading {}", args.config.display()))?,
    )
    .context("parsing config")?;
    let idp = MockIdp::spawn(config, args.listen).await?;
    eprintln!("svx-mock-idp (DEVELOPMENT ONLY) issuer: {}", idp.issuer());
    tokio::signal::ctrl_c().await?;
    Ok(())
}
