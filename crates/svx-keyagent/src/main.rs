//! `svx-keyagent` — run by the recipient organization.
//!
//! ```sh
//! svx-keyagent --database-url postgres://... --org-id example-corp \
//!   --idp-issuer https://login.example-corp.example --idp-client-id svx \
//!   --service-id svx.example --service-grant-key service-grant.sign.pub \
//!   --kem-key example.kem.key --listen 0.0.0.0:9443 --tls-cert cert.pem --tls-key key.pem
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::Parser;
use svx_core::format::Identifier;
use svx_core::keyfile;
use svx_keyagent::{AgentState, app};
use svx_oidc::{IssuerConfig, Validator};

#[derive(Parser)]
#[command(name = "svx-keyagent", version, about = "SVX recipient key agent")]
struct Args {
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    #[arg(long)]
    org_id: String,
    #[arg(long)]
    idp_issuer: String,
    #[arg(long)]
    idp_client_id: String,
    #[arg(long, default_value = "groups")]
    group_claim: String,
    #[arg(long)]
    service_id: String,
    /// The managed service's grant public key (ed25519-public key file), pinned.
    #[arg(long)]
    service_grant_key: PathBuf,
    /// KEM secret key files: the org's X-Wing key and any older keys (X25519
    /// or rotated) still needed to open existing files. Repeatable.
    #[arg(long = "kem-key", required = true)]
    kem_keys: Vec<PathBuf>,
    #[arg(long, default_value = "127.0.0.1:9443")]
    listen: SocketAddr,
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
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
    let org_id = Identifier::new(&a.org_id).context("invalid org id")?;
    let mut kem_keys = Vec::new();
    for p in &a.kem_keys {
        let (owner, sk) =
            keyfile::load_kem_secret(p).with_context(|| format!("loading {}", p.display()))?;
        if owner != org_id {
            bail!("{} belongs to {owner}, not {org_id}", p.display());
        }
        kem_keys.push(sk);
    }
    let (_, service_grant_key) = keyfile::load_verifying_key(&a.service_grant_key)?;
    if service_grant_key.kind() != svx_core::crypto::KeyKind::Ed25519Signing {
        bail!("the service grant key must be an Ed25519 key (svx keygen --kind service-sign)");
    }
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .connect(&a.database_url)
        .await
        .context("connecting to Postgres")?;
    let state = AgentState {
        db,
        org_id,
        idp: IssuerConfig {
            issuer: a.idp_issuer,
            client_id: a.idp_client_id,
            group_claim: a.group_claim,
        },
        service_id: Identifier::new(&a.service_id).context("invalid service id")?,
        service_grant_key,
        kem_keys: Arc::new(kem_keys),
        oidc: Arc::new(Validator::new(a.dev)?),
    };
    let router = app(state).await?;
    tracing::info!(listen = %a.listen, "svx-keyagent starting");
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
