//! Commands that talk to the managed service.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, anyhow, bail};
use svx_client::account::{self, LoginMethod};
use svx_client::config::Paths;
use svx_client::login::{Authenticator, print_url, system_browser};
use svx_client::pack::ManagedPack;
use svx_client::registry::Registry;
use svx_client::session::{self, Session};
use svx_client::setup::{self, SetupRequest};
use svx_client::{ClientConfig, ClientError, Output, Step, admin};
use svx_core::format::Identifier;
use svx_core::keyfile;
use svx_protocol::{DenyReason, ManagedClient, Policy};

use crate::local::{fmt_time, now, parse_expiry, print_info};

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
        let method = match dev_user {
            Some(user) => LoginMethod::Dev(user),
            None if no_browser => LoginMethod::Browser(print_url()),
            None => LoginMethod::Browser(system_browser()),
        };
        account::authenticator(&self.cfg, &self.client, method).map_err(|e| match e {
            ClientError::Config(_) => {
                anyhow!("--dev-user is only available with a dev configuration")
            }
            e => e.into(),
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
    let p = setup::verify(SetupRequest {
        service_url: a.service,
        registry_key: a.registry_key,
        org_id: a.org,
        idp_client_id: a.client_id,
        dev: a.dev,
        default_output_dir: a.output_dir,
    })
    .await?;
    setup::write(&paths, &p.config, a.force)?;
    println!("Wrote {}", paths.config.display());
    println!("Service:       {} ({})", p.service_id, p.service_url);
    println!("Organization:  {} — {}", p.org_id, p.org_display_name);
    println!("Identity:      {}", p.idp_issuer);
    if !p.can_receive {
        println!(
            "Note: {} has no key agent, so it can send but not receive artifacts.",
            p.org_id
        );
    }
    Ok(ExitCode::SUCCESS)
}

pub async fn login(ctx: &Ctx, dev_user: Option<String>, no_browser: bool) -> Result<ExitCode> {
    let auth = ctx.authenticator(dev_user, no_browser)?;
    match account::login(&ctx.cfg, auth.as_ref(), &ctx.paths.session).await {
        Ok(id) => {
            println!("Logged in as {} ({})", id.sub, ctx.cfg.org_id);
            println!("Session expires {}", fmt_time(id.expires_at));
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => Ok(report(&e)),
    }
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
    let had_session = session::load(&ctx.paths.session, now()).is_some();
    match account::whoami(&ctx.cfg, &ctx.paths.session).await {
        Ok(id) => {
            println!("Subject:       {}", id.sub);
            println!("Organization:  {}", id.org_id);
            println!("Issuer:        {}", id.issuer);
            if let Some(e) = &id.email {
                println!("Email:         {e}");
            }
            println!("Groups:        {}", id.groups.join(", "));
            println!("Assurance:     {}", id.acr.as_deref().unwrap_or("-"));
            println!("Expires:       {}", fmt_time(id.expires_at));
            Ok(ExitCode::SUCCESS)
        }
        Err(ClientError::NotLoggedIn) if had_session => {
            println!("Session no longer valid; run `svx login`.");
            Ok(ExitCode::from(1))
        }
        Err(ClientError::NotLoggedIn) => {
            println!("Not logged in.");
            Ok(ExitCode::from(1))
        }
        Err(e) => Ok(report(&e)),
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
    match svx_client::status(&ctx.cfg, &ctx.client, file).await {
        Ok(st) => {
            println!("VALID: signature and integrity verified against the registry");
            print_info(&st.info);
            println!(
                "  For you:    {}",
                if st.for_you {
                    "yes (your organization is the recipient)"
                } else {
                    "no"
                }
            );
            if st.expired {
                println!("  State:      EXPIRED");
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(e @ ClientError::Unavailable(_)) => Ok(report(&e)),
        Err(ClientError::Rejected(why)) => {
            println!("REJECTED: {why}");
            Ok(ExitCode::from(1))
        }
        Err(e) => Err(e.into()),
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
    let input = svx_client::pack::prepare_input(&a.input, a.name).map_err(anyhow::Error::from)?;
    let output = a.output.unwrap_or_else(|| input.default_output.clone());
    let packed = svx_client::pack::pack(
        &ctx.cfg,
        &ctx.client,
        ManagedPack {
            input: &input.path,
            output,
            overwrite: a.force,
            signing_key: &signing_key,
            sender_org: sender_org.clone(),
            recipient_org: Identifier::new(&a.recipient).context("invalid recipient")?,
            policy: Identifier::new(&a.policy).context("invalid policy")?,
            expires_at,
            classification: a.classification,
            description: a.description,
            name: input.name.clone(),
            content_type: input.content_type.clone(),
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
    println!("Protection:  {}", packed.summary.suite.description());
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
    let id = svx_client::artifact_id_of(target).with_context(|| format!("reading {target}"))?;
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
    match svx_client::info::registry_trust(&ctx.cfg, &ctx.client, file).await {
        Ok(t) => Ok(t),
        Err(ClientError::Rejected(_)) => Ok(svx_core::TrustStore::default()),
        Err(e) => Err(e.into()),
    }
}
