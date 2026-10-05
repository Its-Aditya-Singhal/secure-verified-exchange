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
use svx_protocol::personal::PersonalIdp;
use svx_server::dns::SystemDns;
use svx_server::keys::{KeyProvider, LocalKeys};
use svx_server::limits::Limits;
use svx_server::notify::{LogNotifier, SmtpNotifier};
use svx_server::{AppState, RateLimiter, RecordCache, app};

#[derive(Parser)]
#[command(name = "svx-server", version, about = "SVX managed service")]
struct Args {
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    #[arg(long, env = "SVX_SERVICE_ID")]
    service_id: String,
    /// KEM secret key files receiving the service share (repeatable). One
    /// must be MLKEM1024-P384 (suite SVX-2); it is published for new
    /// artifacts. X-Wing and X25519 keys only open older files.
    #[arg(long = "kem-key", required = true)]
    kem_keys: Vec<PathBuf>,
    /// SVX-2 signing key file (svx keygen --kind sign) for release grants.
    #[arg(long)]
    grant_key: PathBuf,
    /// SVX-2 signing key file (svx keygen --kind sign) for registry records.
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
    /// A sign-in provider for personal accounts (repeatable), as
    /// `issuer=https://accounts.google.com,client_id=…[,name=Google][,client_secret=…]`.
    #[arg(long = "personal-idp", value_parser = parse_personal_idp)]
    personal_idps: Vec<PersonalIdp>,
    /// SMTP server for approval emails, e.g. `smtps://user:pass@smtp.example.com`.
    /// Without it, emails are only logged.
    #[arg(long, env = "SVX_SMTP_URL", requires = "smtp_from")]
    smtp_url: Option<String>,
    /// Sender address of approval emails.
    #[arg(long, env = "SVX_SMTP_FROM")]
    smtp_from: Option<String>,
    /// Publish desktop app updates from this directory: `manifest.json`
    /// (signed offline with the release key, `svx release sign`) and the
    /// packages it names, served under /v1/updates.
    #[arg(long, env = "SVX_UPDATES_DIR")]
    updates_dir: Option<PathBuf>,
    /// Read the client's address from this header, set by a proxy in front
    /// of the service (Cloudflare: `CF-Connecting-IP`). Only when the
    /// firewall admits nothing but that proxy: otherwise anyone can claim
    /// any address. Without it, the connection's address is used.
    #[arg(long, env = "SVX_CLIENT_IP_HEADER")]
    client_ip_header: Option<axum::http::HeaderName>,
    /// Emails the service may send per day (codes and notifications); keep
    /// it under the mail provider's limit.
    #[arg(long, env = "SVX_MAX_EMAILS_PER_DAY", default_value_t = Limits::default().emails_per_day)]
    max_emails_per_day: u32,
}

fn parse_personal_idp(s: &str) -> Result<PersonalIdp, String> {
    let (mut issuer, mut client_id, mut name, mut client_secret) = (None, None, None, None);
    for part in s.split(',') {
        let (k, v) = part
            .split_once('=')
            .ok_or_else(|| format!("expected key=value, got {part:?}"))?;
        let v = Some(v.trim().to_string());
        match k.trim() {
            "issuer" => issuer = v,
            "client_id" => client_id = v,
            "name" => name = v,
            "client_secret" => client_secret = v,
            other => return Err(format!("unknown key {other:?}")),
        }
    }
    let issuer = issuer.ok_or("issuer= is required")?;
    let client_id = client_id.ok_or("client_id= is required")?;
    let name = name.unwrap_or_else(|| match issuer.as_str() {
        "https://accounts.google.com" => "Google".into(),
        _ => issuer.clone(),
    });
    Ok(PersonalIdp {
        name,
        issuer,
        client_id,
        client_secret,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    svx_protocol::install_tls_provider();
    let a = Args::parse();
    if a.tls_cert.is_none() && !(a.dev && a.listen.ip().is_loopback()) {
        bail!("TLS is required (--tls-cert/--tls-key); plain HTTP only with --dev on loopback");
    }
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(20)
        .connect(&a.database_url)
        .await
        .context("connecting to Postgres")?;
    let keys = LocalKeys::load(&a.kem_keys, &a.grant_key, &a.registry_key)?;
    // Clients pin this fingerprint (`svx init --registry-key`).
    tracing::info!(
        registry_fingerprint = %hex::encode(keys.registry_public().fingerprint()),
        "registry key loaded"
    );
    let state = AppState {
        db,
        service_id: Identifier::new(&a.service_id).context("invalid service id")?,
        keys: Arc::new(keys),
        oidc: Arc::new(Validator::new(a.dev)?),
        dns: Arc::new(SystemDns::new()?),
        personal_idps: Arc::new(a.personal_idps),
        notifier: match (&a.smtp_url, &a.smtp_from) {
            (Some(url), Some(from)) => Arc::new(SmtpNotifier::new(url, from)?),
            _ => {
                tracing::warn!("no SMTP configured: approval emails are only logged");
                Arc::new(LogNotifier)
            }
        },
        limiter: Arc::new(RateLimiter::default()),
        limits: Limits {
            emails_per_day: a.max_emails_per_day,
            ..Limits::default()
        },
        client_ip_header: a.client_ip_header,
        records: Arc::new(RecordCache::default()),
        updates: a.updates_dir.map(Arc::new),
        dev: a.dev,
    };
    let router = app(state).await?;
    tracing::info!(listen = %a.listen, tls = a.tls_cert.is_some(), "svx-server starting");
    let service = router.into_make_service_with_connect_info::<SocketAddr>();
    match (a.tls_cert, a.tls_key) {
        (Some(cert), Some(key)) => {
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?;
            axum_server::bind_rustls(a.listen, tls)
                .serve(service)
                .await?;
        }
        _ => {
            let listener = tokio::net::TcpListener::bind(a.listen).await?;
            axum::serve(listener, service).await?;
        }
    }
    Ok(())
}
