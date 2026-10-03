//! Commands that talk to the managed service.

use std::fs::File;
use std::io::{BufReader, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use svx_client::config::{Paths, parse_registry_key};
use svx_client::login::{Authenticator, BrowserLogin, DevLogin, print_url, system_browser};
use svx_client::pack::ManagedPack;
use svx_client::registry::Registry;
use svx_client::session::{self, Session};
use svx_client::{ClientConfig, ClientError, Output, Step, admin};
use svx_core::format::Identifier;
use svx_core::keyfile;
use svx_oidc::Validator;
use svx_protocol::{DenyReason, ManagedClient, Policy};

use crate::local::{fmt_time, header_json, now, parse_expiry, print_header};

const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

/// Loaded configuration plus an HTTP client honouring its dev setting.
pub struct Ctx {
    pub paths: Paths,
    pub cfg: ClientConfig,
    pub client: ManagedClient,
}

impl Ctx {
    pub fn load(config: Option<&Path>) -> Result<Ctx> {
        let paths = Paths::resolve(config)?;
        let cfg = ClientConfig::load(&paths.config)?;
        let client = ManagedClient::new(cfg.dev)?;
        Ok(Ctx { paths, cfg, client })
    }

    fn authenticator(
        &self,
        dev_user: Option<String>,
        no_browser: bool,
    ) -> Result<Box<dyn Authenticator>> {
        Ok(match dev_user {
            Some(user) => {
                if !self.cfg.dev {
                    bail!("--dev-user is only available with a dev configuration");
                }
                Box::new(DevLogin {
                    client: self.client.clone(),
                    issuer: self.cfg.idp_issuer.clone(),
                    client_id: self.cfg.idp_client_id.clone(),
                    user,
                })
            }
            None => Box::new(BrowserLogin {
                client: self.client.clone(),
                issuer: self.cfg.idp_issuer.clone(),
                client_id: self.cfg.idp_client_id.clone(),
                opener: if no_browser {
                    print_url()
                } else {
                    system_browser()
                },
                timeout: LOGIN_TIMEOUT,
            }),
        })
    }

    fn session(&self) -> Result<Session> {
        Ok(session::require(&self.paths.session, now())?)
    }
}

/// Map a client error to a user-facing message and exit code.
pub fn report(e: &ClientError) -> ExitCode {
    match e {
        ClientError::Denied(r) => {
            eprintln!("ACCESS DENIED");
            eprintln!(
                "Reason: {}",
                match r {
                    DenyReason::NotAuthorized => "you are not authorized for this artifact",
                    DenyReason::ExpiredOrRevoked => "artifact expired or revoked",
                    DenyReason::InvalidArtifact => "artifact not accepted by the service",
                    DenyReason::InvalidRequest => "invalid request",
                    DenyReason::Unavailable => "service unavailable",
                }
            );
        }
        ClientError::Expired => eprintln!("ACCESS DENIED\nReason: artifact expired"),
        ClientError::Rejected(why) => eprintln!("REJECTED: {why}\nNothing was decrypted."),
        other => eprintln!("error: {other}"),
    }
    ExitCode::from(e.exit_code())
}

pub struct InitArgs {
    pub service: String,
    pub registry_key: String,
    pub org: String,
    pub client_id: String,
    pub dev: bool,
    pub output_dir: Option<PathBuf>,
    pub force: bool,
}

pub async fn init(config: Option<&Path>, a: InitArgs) -> Result<ExitCode> {
    let paths = Paths::resolve(config)?;
    if paths.config.exists() && !a.force {
        bail!(
            "{} exists (use --force to replace it)",
            paths.config.display()
        );
    }
    let key = parse_registry_key(&a.registry_key)?;
    let client = ManagedClient::new(a.dev)?;
    svx_protocol::check_url(&a.service, a.dev).map_err(|e| anyhow!("{e}"))?;
    // Both lookups verify signatures with the pinned key: a wrong pin fails here.
    let service = client
        .service_record(&a.service, &key)
        .await
        .map_err(ClientError::from)
        .context("verifying the service record with the given registry key")?;
    let org = client
        .org_record(&a.service, &a.org, &key)
        .await
        .map_err(ClientError::from)
        .with_context(|| format!("fetching the verified registry record for {}", a.org))?;
    let cfg = ClientConfig {
        service_url: a.service,
        registry_key: hex::encode(key.to_bytes()),
        org_id: a.org,
        idp_issuer: org.idp_issuer.clone(),
        idp_client_id: a.client_id,
        group_claim: "groups".into(),
        dev: a.dev,
        default_output_dir: a.output_dir,
    };
    cfg.save(&paths.config)?;
    println!("Wrote {}", paths.config.display());
    println!(
        "Service:       {} ({})",
        service.service_id, cfg.service_url
    );
    println!("Organization:  {} — {}", org.org_id, org.display_name);
    println!("Identity:      {}", org.idp_issuer);
    if org.key_agent_url.is_none() {
        println!(
            "Note: {} has no key agent, so it can send but not receive artifacts.",
            org.org_id
        );
    }
    Ok(ExitCode::SUCCESS)
}

pub async fn login(ctx: &Ctx, dev_user: Option<String>, no_browser: bool) -> Result<ExitCode> {
    let auth = ctx.authenticator(dev_user, no_browser)?;
    // Admin sessions are not bound to a release key; a fresh random nonce
    // still prevents replay of an older token into this login.
    let nonce = hex::encode(svx_core::crypto::random_bytes::<16>());
    let token = match auth.id_token(&nonce).await {
        Ok(t) => t,
        Err(e) => return Ok(report(&e)),
    };
    let id = Validator::new(ctx.cfg.dev)?
        .validate(&ctx.cfg.issuer_config(), &token, Some(&nonce))
        .await
        .map_err(|e| anyhow!("the IdP returned an invalid token: {e}"))?;
    let exp = session::token_exp(&token).ok_or_else(|| anyhow!("token has no exp"))?;
    session::save(
        &ctx.paths.session,
        &Session {
            id_token: token,
            issuer: id.issuer.clone(),
            sub: id.sub.clone(),
            exp,
        },
    )?;
    println!("Logged in as {} ({})", id.sub, ctx.cfg.org_id);
    println!("Session expires {}", fmt_time(exp));
    Ok(ExitCode::SUCCESS)
}

pub fn logout(ctx: &Ctx) -> Result<ExitCode> {
    if session::clear(&ctx.paths.session)? {
        println!("Logged out.");
    } else {
        println!("No active session.");
    }
    Ok(ExitCode::SUCCESS)
}

pub async fn whoami(ctx: &Ctx) -> Result<ExitCode> {
    let s = match ctx.session() {
        Ok(s) => s,
        Err(_) => {
            println!("Not logged in.");
            return Ok(ExitCode::from(1));
        }
    };
    match Validator::new(ctx.cfg.dev)?
        .validate(&ctx.cfg.issuer_config(), &s.id_token, None)
        .await
    {
        Ok(id) => {
            println!("Subject:       {}", id.sub);
            println!("Organization:  {}", ctx.cfg.org_id);
            println!("Issuer:        {}", id.issuer);
            if let Some(e) = &id.email {
                println!("Email:         {e}");
            }
            println!("Groups:        {}", id.groups.join(", "));
            println!("Assurance:     {}", id.acr.as_deref().unwrap_or("-"));
            println!("Expires:       {}", fmt_time(s.exp));
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            let _ = session::clear(&ctx.paths.session);
            println!("Session no longer valid ({e}); run `svx login`.");
            Ok(ExitCode::from(1))
        }
    }
}

pub struct OpenArgs {
    pub file: PathBuf,
    pub output_dir: Option<PathBuf>,
    pub stdout: bool,
    pub overwrite: bool,
    pub dev_user: Option<String>,
    pub no_browser: bool,
}

pub async fn open(ctx: &Ctx, a: OpenArgs) -> Result<ExitCode> {
    let output = if a.stdout {
        if std::io::stdout().is_terminal() {
            bail!("refusing to write plaintext to a terminal; redirect stdout or use -o DIR");
        }
        Output::Writer(Box::new(std::io::stdout()))
    } else {
        let dir = match a.output_dir.or_else(|| ctx.cfg.default_output_dir.clone()) {
            Some(d) => d,
            None => svx_client::config::default_open_dir()?,
        };
        Output::Dir {
            dir,
            overwrite: a.overwrite,
        }
    };
    let auth = ctx.authenticator(a.dev_user, a.no_browser)?;
    let issuer = ctx.cfg.idp_issuer.clone();
    let mut progress = move |s: Step| {
        let msg = match s {
            Step::Verifying => "Verifying artifact...".to_owned(),
            Step::SignatureValid { sender } => format!("Signature valid (sender: {sender})"),
            Step::Connecting => "Connecting to SVX service...".to_owned(),
            Step::Authenticating => format!("Authenticating with {issuer}..."),
            Step::CheckingAuthorization => "Checking authorization...".to_owned(),
            Step::AccessApproved => "Access approved".to_owned(),
            Step::Decrypting => "Decrypting locally...".to_owned(),
        };
        eprintln!("{msg}");
    };
    match svx_client::open(
        &ctx.cfg,
        &ctx.client,
        auth.as_ref(),
        &a.file,
        output,
        &mut progress,
    )
    .await
    {
        Ok(o) => {
            if let Some(p) = &o.path {
                eprintln!("Opened:         {}", p.display());
            }
            if let Some(c) = &o.manifest.classification {
                eprintln!("Classification: {c}");
            }
            eprintln!(
                "Reminder: plaintext is now outside SVX protection; revocation cannot recall it."
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => Ok(report(&e)),
    }
}

pub async fn status(ctx: &Ctx, file: &Path) -> Result<ExitCode> {
    let registry = Registry::new(&ctx.cfg, &ctx.client)?;
    let (_, header) = svx_core::inspect(BufReader::new(File::open(file)?))
        .map_err(|e| anyhow!("not a valid SVX file: {e}"))?;
    let trust = match registry.sender_trust(header.sender_org.as_str()).await {
        Ok(t) => t,
        Err(e @ ClientError::Unavailable(_)) => return Ok(report(&e)),
        Err(_) => {
            println!(
                "REJECTED: sender {} is not a verified organization",
                header.sender_org
            );
            return Ok(ExitCode::from(1));
        }
    };
    match svx_core::verify(BufReader::new(File::open(file)?), &trust) {
        Ok(v) => {
            let j = header_json(&v.prelude, &v.header);
            println!("VALID: signature and integrity verified against the registry");
            print_header(&j);
            let mine = v.header.recipient_org.as_str() == ctx.cfg.org_id;
            println!(
                "  For you:    {}",
                if mine {
                    "yes (your organization is the recipient)"
                } else {
                    "no"
                }
            );
            if v.is_expired(now()) {
                println!("  State:      EXPIRED");
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            println!("REJECTED: {e}");
            Ok(ExitCode::from(1))
        }
    }
}

pub struct ManagedPackArgs {
    pub input: PathBuf,
    pub output: Option<PathBuf>,
    pub force: bool,
    pub sign_key: PathBuf,
    pub recipient: String,
    pub policy: String,
    pub expires: Option<String>,
    pub classification: Option<String>,
    pub description: Option<String>,
    pub name: Option<String>,
    pub chunk_size: Option<u32>,
    pub register: bool,
}

pub async fn pack(ctx: &Ctx, a: ManagedPackArgs) -> Result<ExitCode> {
    let (sender_org, signing_key) =
        keyfile::load_signing_key(&a.sign_key).context("loading signing key")?;
    let expires_at = a.expires.as_deref().map(parse_expiry).transpose()?;
    let name = match a.name {
        Some(n) => n,
        None => a
            .input
            .file_name()
            .and_then(|n| n.to_str())
            .context("input has no usable file name")?
            .to_owned(),
    };
    let output = a.output.unwrap_or_else(|| a.input.with_extension("svx"));
    let packed = svx_client::pack::pack(
        &ctx.cfg,
        &ctx.client,
        ManagedPack {
            input: &a.input,
            output,
            overwrite: a.force,
            signing_key: &signing_key,
            sender_org: sender_org.clone(),
            recipient_org: Identifier::new(&a.recipient).context("invalid recipient")?,
            policy: Identifier::new(&a.policy).context("invalid policy")?,
            expires_at,
            classification: a.classification,
            description: a.description,
            name,
            chunk_size: a.chunk_size,
        },
    )
    .await;
    let packed = match packed {
        Ok(p) => p,
        Err(e) => return Ok(report(&e)),
    };
    println!("Created:     {}", packed.path.display());
    println!("Artifact ID: {}", hex::encode(packed.summary.artifact_id));
    println!("Sender:      {sender_org}");
    println!("Recipient:   {}", a.recipient);
    println!("Service:     {}", packed.service_id);
    println!("Policy:      {}", a.policy);
    println!(
        "Expiration:  {}",
        expires_at.map(fmt_time).unwrap_or_else(|| "none".into())
    );
    println!("Encryption:  enabled (keys from the verified registry)");
    println!(
        "Signature:   valid (key {})",
        hex::encode(signing_key.verifying_key().key_id())
    );
    if a.register {
        let s = ctx.session()?;
        match svx_client::pack::register(&ctx.cfg, &ctx.client, &packed.path, &s.id_token).await {
            Ok(()) => println!("Registered:  yes"),
            Err(e) => return Ok(report(&e)),
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub async fn revoke(ctx: &Ctx, target: &str) -> Result<ExitCode> {
    let s = ctx.session()?;
    let mut id = [0u8; 16];
    if target.len() == 32 && hex::decode_to_slice(target, &mut id).is_ok() {
    } else {
        let (_, h) = svx_core::inspect(BufReader::new(
            File::open(target).with_context(|| format!("opening {target}"))?,
        ))
        .map_err(|e| anyhow!("not a valid SVX file: {e}"))?;
        id = h.artifact_id;
    }
    match admin::revoke(&ctx.cfg, &ctx.client, &s.id_token, &id).await {
        Ok(()) => {
            println!(
                "Revoked {}. Future access attempts will be denied.",
                hex::encode(id)
            );
            println!(
                "Note: revocation cannot erase plaintext already decrypted by authorized users."
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => Ok(report(&e)),
    }
}

pub enum PolicyCmd {
    List,
    Show(String),
    Set { name: String, file: PathBuf },
}

pub async fn policy(ctx: &Ctx, cmd: PolicyCmd) -> Result<ExitCode> {
    let s = ctx.session()?;
    let r = match cmd {
        PolicyCmd::List => admin::list_policies(&ctx.cfg, &ctx.client, &s.id_token)
            .await
            .map(|m| {
                if m.is_empty() {
                    println!("No policies.");
                }
                for (name, p) in m {
                    println!("{name}: {}", serde_json::to_string(&p).unwrap_or_default());
                }
            }),
        PolicyCmd::Show(name) => admin::list_policies(&ctx.cfg, &ctx.client, &s.id_token)
            .await
            .and_then(|m| {
                m.get(&name)
                    .map(|p| println!("{}", serde_json::to_string_pretty(p).unwrap_or_default()))
                    .ok_or_else(|| ClientError::Other(format!("no policy named {name}")))
            }),
        PolicyCmd::Set { name, file } => {
            let p: Policy = serde_json::from_slice(&std::fs::read(&file)?)
                .with_context(|| format!("parsing {}", file.display()))?;
            p.validate().map_err(|e| anyhow!(e))?;
            admin::set_policy(&ctx.cfg, &ctx.client, &s.id_token, &name, &p)
                .await
                .map(|_| println!("Policy {name} saved."))
        }
    };
    match r {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(e) => Ok(report(&e)),
    }
}

pub async fn organization(ctx: &Ctx, org: &str) -> Result<ExitCode> {
    let registry = Registry::new(&ctx.cfg, &ctx.client)?;
    match registry.org(org).await {
        Ok(r) => {
            println!("Organization:  {} — {}", r.org_id, r.display_name);
            println!("Domain:        {} (verified)", r.domain);
            println!("Identity:      {}", r.idp_issuer);
            println!(
                "Key agent:     {}",
                r.key_agent_url
                    .as_deref()
                    .unwrap_or("none (cannot receive)")
            );
            for k in &r.keys {
                println!(
                    "Key:           {} {} {}",
                    k.kind.as_str(),
                    hex::encode(k.key_id),
                    k.status.as_str()
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => Ok(report(&e)),
    }
}

pub async fn audit(ctx: &Ctx, limit: u32, as_json: bool) -> Result<ExitCode> {
    let s = ctx.session()?;
    match admin::audit(&ctx.cfg, &ctx.client, &s.id_token, limit).await {
        Ok(page) => {
            if as_json {
                println!("{}", serde_json::to_string_pretty(&page)?);
            } else {
                for e in &page.entries {
                    println!(
                        "{:>6}  {}  {:<28} {:<24} {} {}",
                        e.seq,
                        fmt_time(e.at),
                        e.event,
                        e.subject.as_deref().unwrap_or("-"),
                        e.artifact_id.as_deref().unwrap_or("-"),
                        e.reason.as_deref().unwrap_or("")
                    );
                }
                println!(
                    "Hash chain: {}",
                    if page.chain_valid {
                        "valid"
                    } else {
                        "BROKEN — investigate"
                    }
                );
            }
            Ok(if page.chain_valid {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Err(e) => Ok(report(&e)),
    }
}

/// `svx verify --registry`: trust from the verified registry.
pub async fn registry_trust(ctx: &Ctx, file: &Path) -> Result<svx_core::TrustStore> {
    let (_, h) = svx_core::inspect(BufReader::new(File::open(file)?))
        .map_err(|e| anyhow!("not a valid SVX file: {e}"))?;
    Ok(Registry::new(&ctx.cfg, &ctx.client)?
        .sender_trust(h.sender_org.as_str())
        .await
        .unwrap_or_default())
}
