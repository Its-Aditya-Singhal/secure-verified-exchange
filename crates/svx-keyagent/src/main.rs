//! `svx-keyagent` — run by the recipient organization.
//!
//! ```sh
//! svx-keyagent --config /etc/svx/agent.toml            # serve (see docs/key-agent.md)
//! svx-keyagent --config /etc/svx/agent.toml check      # validate config, keys, database, registry
//! svx-keyagent healthcheck --addr 127.0.0.1:9443       # liveness probe (containers)
//! ```
//!
//! Every setting can also be given as a flag, which wins over the file:
//!
//! ```sh
//! svx-keyagent --database-url postgres://... --org-id example-corp \
//!   --idp-issuer https://login.example-corp.example --idp-client-id svx \
//!   --service-id svx.example --service-grant-key service-grant.sign.pub \
//!   --kem-key example.kem.key --listen 0.0.0.0:9443 --tls-cert cert.pem --tls-key key.pem
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use svx_core::format::Identifier;
use svx_keyagent::config::{AgentConfig, LoadedKeys, load_keys};
use svx_keyagent::{AgentState, app};
use svx_oidc::{IssuerConfig, Validator};

#[derive(Parser)]
#[command(name = "svx-keyagent", version, about = "SVX recipient key agent")]
struct Args {
    /// Configuration file (TOML); flags override its values.
    #[arg(long, env = "SVX_KEYAGENT_CONFIG", global = true)]
    config: Option<PathBuf>,
    #[arg(long, env = "DATABASE_URL", global = true, hide_env_values = true)]
    database_url: Option<String>,
    #[arg(long)]
    org_id: Option<String>,
    #[arg(long)]
    idp_issuer: Option<String>,
    #[arg(long)]
    idp_client_id: Option<String>,
    /// Default: groups.
    #[arg(long)]
    group_claim: Option<String>,
    #[arg(long)]
    service_id: Option<String>,
    /// The managed service's grant public key (ed25519-public key file), pinned.
    #[arg(long)]
    service_grant_key: Option<PathBuf>,
    /// KEM secret key files: the org's X-Wing key and any older keys (X25519
    /// or rotated) still needed to open existing files. Repeatable.
    #[arg(long = "kem-key")]
    kem_keys: Vec<PathBuf>,
    /// Default: 127.0.0.1:9443.
    #[arg(long)]
    listen: Option<SocketAddr>,
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// Development mode: plain HTTP on loopback, loopback http IdPs.
    #[arg(long)]
    dev: bool,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the key agent (the default).
    Serve,
    /// Check the configuration, keys, database and (if `service_url` and
    /// `registry_key` are set) that the registry's active encryption key is
    /// one this agent holds. Exits non-zero on any problem.
    Check,
    /// Liveness probe: succeed if the agent accepts connections.
    Healthcheck {
        #[arg(long, default_value = "127.0.0.1:9443")]
        addr: SocketAddr,
    },
}

impl Args {
    fn config(&self) -> Result<AgentConfig> {
        let flags = AgentConfig {
            database_url: self.database_url.clone(),
            org_id: self.org_id.clone(),
            idp_issuer: self.idp_issuer.clone(),
            idp_client_id: self.idp_client_id.clone(),
            group_claim: self.group_claim.clone(),
            service_id: self.service_id.clone(),
            service_grant_key: self.service_grant_key.clone(),
            kem_keys: self.kem_keys.clone(),
            listen: self.listen,
            tls_cert: self.tls_cert.clone(),
            tls_key: self.tls_key.clone(),
            dev: self.dev,
            service_url: None,
            registry_key: None,
        };
        Ok(match &self.config {
            Some(p) => flags.or(AgentConfig::load(p)?),
            None => flags,
        })
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let a = Args::parse();
    let r = match a.cmd {
        Some(Cmd::Healthcheck { addr }) => healthcheck(addr).await,
        Some(Cmd::Check) => check(&a).await,
        Some(Cmd::Serve) | None => serve(&a).await,
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn healthcheck(addr: SocketAddr) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(addr))
        .await
        .context("timed out")?
        .with_context(|| format!("connecting to {addr}"))?;
    Ok(())
}

async fn connect_db(cfg: &AgentConfig) -> Result<sqlx::PgPool> {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(10))
        .connect(AgentConfig::require(&cfg.database_url, "database_url")?)
        .await
        .context("connecting to Postgres")
}

fn state(cfg: &AgentConfig, keys: LoadedKeys, db: sqlx::PgPool) -> Result<AgentState> {
    Ok(AgentState {
        db,
        org_id: keys.org_id,
        idp: IssuerConfig {
            issuer: AgentConfig::require(&cfg.idp_issuer, "idp_issuer")?.clone(),
            client_id: AgentConfig::require(&cfg.idp_client_id, "idp_client_id")?.clone(),
            group_claim: cfg.group_claim.clone().unwrap_or_else(|| "groups".into()),
        },
        service_id: Identifier::new(AgentConfig::require(&cfg.service_id, "service_id")?)
            .context("invalid service_id")?,
        service_grant_key: keys.service_grant_key,
        kem_keys: Arc::new(keys.kem_keys),
        oidc: Arc::new(Validator::new(cfg.dev)?),
    })
}

async fn serve(a: &Args) -> Result<()> {
    let cfg = a.config()?;
    cfg.check_tls()?;
    let keys = load_keys(&cfg)?;
    let db = connect_db(&cfg).await?;
    let router = app(state(&cfg, keys, db)?).await?;
    let listen = cfg.listen();
    tracing::info!(listen = %listen, "svx-keyagent starting");
    match (&cfg.tls_cert, &cfg.tls_key) {
        (Some(cert), Some(key)) => {
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?;
            axum_server::bind_rustls(listen, tls)
                .serve(router.into_make_service())
                .await?;
        }
        _ => {
            let listener = tokio::net::TcpListener::bind(listen).await?;
            axum::serve(listener, router).await?;
        }
    }
    Ok(())
}

async fn check(a: &Args) -> Result<()> {
    let cfg = a.config()?;
    cfg.check_tls()?;
    println!("Configuration: ok (listen {})", cfg.listen());
    let keys = load_keys(&cfg)?;
    for k in &keys.kem_keys {
        println!(
            "Key:           {} {}",
            svx_protocol::KeyKindWire::from_key_kind(k.kind()).as_str(),
            hex::encode(k.public_key().key_id())
        );
    }
    let db = connect_db(&cfg).await?;
    sqlx::query("SELECT 1").execute(&db).await?;
    println!("Database:      ok");
    let st = state(&cfg, keys, db)?;
    match (&cfg.service_url, &cfg.registry_key) {
        (Some(url), Some(reg)) => {
            let mut pin = [0u8; 32];
            hex::decode_to_slice(reg.trim(), &mut pin).context("registry_key must be 64 hex")?;
            let pin =
                svx_core::crypto::VerifyingKey::from_bytes(&pin).context("invalid registry_key")?;
            let client = svx_protocol::ManagedClient::new(cfg.dev)?;
            let rec = client
                .org_record(url, st.org_id.as_str(), &pin)
                .await
                .context("fetching the registry record")?;
            let active = rec
                .active_hybrid_kem_key()
                .context("the registry has no active post-quantum encryption key for this org")?;
            if !st
                .kem_keys
                .iter()
                .any(|k| k.public_key().key_id() == active.key_id)
            {
                bail!(
                    "the registry's active encryption key {} is not loaded here; files sent now \
                     can't be opened",
                    hex::encode(active.key_id)
                );
            }
            println!(
                "Registry:      ok (active key {} is loaded)",
                hex::encode(active.key_id)
            );
        }
        _ => println!("Registry:      not checked (set service_url and registry_key)"),
    }
    Ok(())
}
