//! `svx-server` — the SVX managed service.
//!
//! ```sh
//! svx-server --database-url postgres://... --service-id svx.example \
//!   --kem-key service.kem.key [--kem-key old-x25519.kem.key] --grant-key grant.sign.key --registry-key registry.sign.key \
//!   --listen 0.0.0.0:8443 --tls-cert cert.pem --tls-key key.pem
//! ```
//!
//! Plain HTTP is only permitted with `--dev` on a loopback address.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::Parser;
use svx_core::format::Identifier;
use svx_oidc::Validator;
use svx_server::dns::SystemDns;
use svx_server::keys::LocalKeys;
use svx_server::{AppState, app};

#[derive(Parser)]
#[command(name = "svx-server", version, about = "SVX managed service")]
struct Args {
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    #[arg(long, env = "SVX_SERVICE_ID")]
    service_id: String,
    /// KEM secret key files receiving the service share (repeatable). One
    /// must be X-Wing (post-quantum hybrid); it is published for new
    /// artifacts. X25519 keys only open older files.
    #[arg(long = "kem-key", required = true)]
    kem_keys: Vec<PathBuf>,
    /// Ed25519 secret key file signing release grants.
    #[arg(long)]
    grant_key: PathBuf,
    /// Ed25519 secret key file signing registry records.
    #[arg(long)]
    registry_key: PathBuf,
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// Development mode: plain HTTP on loopback; loopback http IdPs allowed.
    #[arg(long)]
    dev: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let a = Args::parse();
    if a.tls_cert.is_none() && !(a.dev && a.listen.ip().is_loopback()) {
        bail!("TLS is required (--tls-cert/--tls-key); plain HTTP only with --dev on loopback");
    }
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(20)
        .connect(&a.database_url)
        .await
        .context("connecting to Postgres")?;
    let state = AppState {
        db,
        service_id: Identifier::new(&a.service_id).context("invalid service id")?,
        keys: Arc::new(LocalKeys::load(&a.kem_keys, &a.grant_key, &a.registry_key)?),
        oidc: Arc::new(Validator::new(a.dev)?),
        dns: Arc::new(SystemDns::new()?),
        dev: a.dev,
    };
    let router = app(state).await?;
    tracing::info!(listen = %a.listen, tls = a.tls_cert.is_some(), "svx-server starting");
    match (a.tls_cert, a.tls_key) {
        (Some(cert), Some(key)) => {
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?;
            axum_server::bind_rustls(a.listen, tls)
                .serve(router.into_make_service())
                .await?;
        }
        _ => {
            let listener = tokio::net::TcpListener::bind(a.listen).await?;
            axum::serve(listener, router).await?;
        }
    }
    Ok(())
}
