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
use svx_server::notify::{LogNotifier, SmtpNotifier};
use svx_server::relay::{AppleKey, RelayConfig};
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
    /// `issuer=https://accounts.google.com,client_id=…[,name=Google][,client_secret=…][,relay=true]`.
    /// Apple (`issuer=https://appleid.apple.com,client_id=<Services ID>`) is
    /// always relayed through this service (needs --public-url and --apple-key).
    #[arg(long = "personal-idp", value_parser = parse_personal_idp)]
    personal_idps: Vec<PersonalIdp>,
    /// SMTP server for approval emails, e.g. `smtps://user:pass@smtp.example.com`.
    /// Without it, emails are only logged.
    #[arg(long, env = "SVX_SMTP_URL", requires = "smtp_from")]
    smtp_url: Option<String>,
    /// Sender address of approval emails.
    #[arg(long, env = "SVX_SMTP_FROM")]
    smtp_from: Option<String>,
    /// This service's public base URL (https). Relayed sign-ins (Apple)
    /// return to `<URL>/v1/auth/relay/callback`, registered with the provider.
    #[arg(long, env = "SVX_PUBLIC_URL")]
    public_url: Option<String>,
    /// Apple's "Sign in with Apple" key: `team_id=…,key_id=…,file=AuthKey_….p8`.
    #[arg(long)]
    apple_key: Option<String>,
}

fn parse_kv(s: &str) -> Result<Vec<(String, String)>, String> {
    s.split(',')
        .map(|part| {
            part.split_once('=')
                .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
                .ok_or_else(|| format!("expected key=value, got {part:?}"))
        })
        .collect()
}

fn relay_config(a: &Args) -> Result<RelayConfig> {
    let apple = match &a.apple_key {
        None => None,
        Some(spec) => {
            let kv = parse_kv(spec).map_err(anyhow::Error::msg)?;
            let get = |k: &str| {
                kv.iter()
                    .find(|(key, _)| key == k)
                    .map(|(_, v)| v.clone())
                    .with_context(|| format!("--apple-key needs {k}="))
            };
            let pem = std::fs::read(get("file")?).context("reading the Apple key")?;
            Some(AppleKey::from_pem(&get("team_id")?, &get("key_id")?, &pem)?)
        }
    };
    let redirect_uri = match &a.public_url {
        Some(u) => {
            svx_protocol::check_url(u, a.dev).context("--public-url must be https")?;
            Some(format!(
                "{}/v1/auth/relay/callback",
                u.trim_end_matches('/')
            ))
        }
        None => None,
    };
    if a.personal_idps.iter().any(|p| p.relay) && redirect_uri.is_none() {
        bail!("relayed sign-in providers need --public-url");
    }
    Ok(RelayConfig {
        redirect_uri,
        apple,
    })
}

fn parse_personal_idp(s: &str) -> Result<PersonalIdp, String> {
    let (mut issuer, mut client_id, mut name, mut client_secret) = (None, None, None, None);
    let mut relay = false;
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
            "relay" => relay = v.as_deref() == Some("true"),
            other => return Err(format!("unknown key {other:?}")),
        }
    }
    let issuer = issuer.ok_or("issuer= is required")?;
    let client_id = client_id.ok_or("client_id= is required")?;
    // Apple can't sign in desktop apps directly: always relayed.
    relay |= issuer == svx_server::relay::APPLE_ISSUER;
    let name = name.unwrap_or_else(|| match issuer.as_str() {
        "https://accounts.google.com" => "Google".into(),
        "https://appleid.apple.com" => "Apple".into(),
        _ => issuer.clone(),
    });
    Ok(PersonalIdp {
        name,
        issuer,
        client_id,
        client_secret,
        relay,
    })
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
    let keys = LocalKeys::load(&a.kem_keys, &a.grant_key, &a.registry_key)?;
    // Clients pin this fingerprint (`svx init --registry-key`).
    tracing::info!(
        registry_fingerprint = %hex::encode(keys.registry_public().fingerprint()),
        "registry key loaded"
    );
    let relay = Arc::new(relay_config(&a)?);
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
        records: Arc::new(RecordCache::default()),
        relay,
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
