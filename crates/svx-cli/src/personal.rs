//! Personal accounts from the command line: the same account and keychain
//! keys as the desktop app.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use svx_client::Client;
use svx_client::account::LoginMethod;
use svx_client::config::Paths;
use svx_client::defaults::{ServiceTarget, service_target};
use svx_client::login::{print_url, system_browser};
use svx_client::personal::{self, KeyChoice, SendOptions, SignUpOptions};
use svx_protocol::email_account::{CodePurpose, password_strength};
use svx_protocol::personal::{FileRules, FileStatus, RecipientState, UpdateFileRequest};

use crate::local::{fmt_time, parse_expiry};

pub fn client(config: Option<&Path>) -> Result<Client> {
    let c = Client::load(config)?;
    if !c.cfg.is_personal() {
        bail!("this is a company setup; personal commands need `svx account signup`");
    }
    Ok(c)
}

pub struct SignUpArgs {
    pub service: Option<String>,
    pub registry_key: Option<String>,
    pub dev: bool,
    pub provider: Option<String>,
    pub email: Option<String>,
    pub names: Option<(String, String)>,
    pub dev_user: Option<String>,
    pub no_browser: bool,
    pub reset: bool,
    pub restore: Option<PathBuf>,
    pub force: bool,
}

fn password(prompt: &str) -> Result<String> {
    if let Ok(p) = std::env::var("SVX_RECOVERY_PASSWORD") {
        return Ok(p);
    }
    rpassword::prompt_password(prompt).context("reading the recovery password")
}

/// The service to sign up with: given, or the built-in one.
pub fn target(
    service: Option<String>,
    registry_key: Option<String>,
    dev: bool,
) -> Result<ServiceTarget> {
    Ok(match (service, registry_key) {
        (Some(service_url), Some(registry_key)) => ServiceTarget {
            service_url,
            registry_key,
            dev,
        },
        (None, None) => service_target()?,
        _ => bail!("give both --service and --registry-key, or neither"),
    })
}

/// The account password: `$SVX_ACCOUNT_PASSWORD` (scripts), or asked.
fn account_password(prompt: &str) -> Result<String> {
    if let Ok(p) = std::env::var("SVX_ACCOUNT_PASSWORD") {
        return Ok(p);
    }
    rpassword::prompt_password(prompt).context("reading the password")
}

/// A new account password, checked with the service's rules and typed twice.
fn new_account_password(prompt: &str, inputs: &[&str]) -> Result<String> {
    loop {
        let pw = account_password(prompt)?;
        let s = password_strength(&pw, inputs);
        if !s.ok {
            let why = format!("choose a stronger password: {}", s.feedback.join(" "));
            if std::env::var_os("SVX_ACCOUNT_PASSWORD").is_some() {
                bail!(why);
            }
            eprintln!("{why}");
            continue;
        }
        if std::env::var_os("SVX_ACCOUNT_PASSWORD").is_none()
            && rpassword::prompt_password("Repeat it: ")? != pw
        {
            eprintln!("The passwords don't match.");
            continue;
        }
        return Ok(pw);
    }
}

/// Ask for the code that was emailed (`$SVX_EMAIL_CODE` for scripts).
fn email_code(email: &str) -> Result<String> {
    if let Ok(c) = std::env::var("SVX_EMAIL_CODE") {
        return Ok(c);
    }
    eprint!("Enter the 6-digit code sent to {email}: ");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}

async fn sign_up_email(
    paths: &Paths,
    target: ServiceTarget,
    email: &str,
    names: Option<(String, String)>,
    keys: KeyChoice,
    force: bool,
) -> Result<personal::AccountInfo> {
    let password = match &names {
        Some((f, l)) => new_account_password(
            "Choose a password (at least 12 characters): ",
            &[email, f, l],
        )?,
        None => account_password("Password: ")?,
    };
    let purpose = if names.is_some() {
        CodePurpose::SignUp
    } else {
        CodePurpose::SignIn
    };
    let sent = personal::request_email_code(&target, email, purpose).await?;
    let code = email_code(email)?;
    let (_, info) = personal::sign_up_email(
        paths,
        svx_client::keystore::os_keychain(),
        SignUpOptions {
            target,
            issuer: None,
            keys,
            default_output_dir: None,
            replace: force,
        },
        personal::EmailCredentials {
            email: email.to_owned(),
            password: zeroize::Zeroizing::new(password),
            names,
            challenge: sent.challenge,
            code,
        },
    )
    .await?;
    Ok(info)
}

pub async fn sign_up(config: Option<&Path>, a: SignUpArgs) -> Result<ExitCode> {
    let target = target(a.service, a.registry_key, a.dev)?;
    if let Some(email) = &a.email {
        if a.names.is_some() && (a.restore.is_some() || a.reset) {
            bail!("--restore and --reset are for signing in to an existing account");
        }
        let keys = match (&a.restore, a.reset) {
            (Some(_), true) => bail!("use --restore or --reset, not both"),
            (Some(file), false) => {
                let pw = password("Recovery password: ")?;
                KeyChoice::Restore(Box::new(personal::read_backup(file, &pw)?))
            }
            (None, true) => KeyChoice::Reset,
            (None, false) => KeyChoice::New,
        };
        let paths = Paths::resolve(config)?;
        let info = sign_up_email(&paths, target, email, a.names, keys, a.force).await?;
        println!("Signed in as {} ({})", info.email, info.account);
        println!("Keys are in this computer's keychain. Save a backup: svx account backup FILE");
        return Ok(ExitCode::SUCCESS);
    }
    let providers = personal::providers(&target).await?;
    let issuer = match &a.provider {
        Some(name) => providers
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(name) || &p.issuer == name)
            .map(|p| p.issuer.clone())
            .with_context(|| {
                let names: Vec<_> = providers.iter().map(|p| p.name.as_str()).collect();
                format!(
                    "no provider {name:?}; this service offers {}",
                    names.join(", ")
                )
            })?,
        None => providers
            .first()
            .map(|p| p.issuer.clone())
            .context("this service doesn't offer personal accounts")?,
    };
    let keys = match (&a.restore, a.reset) {
        (Some(_), true) => bail!("use --restore or --reset, not both"),
        (Some(file), false) => {
            let pw = password("Recovery password: ")?;
            KeyChoice::Restore(Box::new(personal::read_backup(file, &pw)?))
        }
        (None, true) => KeyChoice::Reset,
        (None, false) => KeyChoice::New,
    };
    let login = match a.dev_user {
        Some(u) => LoginMethod::Dev(u),
        None if a.no_browser => LoginMethod::Browser(print_url()),
        None => LoginMethod::Browser(system_browser()),
    };
    let paths = Paths::resolve(config)?;
    let (_, info) = personal::sign_up(
        &paths,
        svx_client::keystore::os_keychain(),
        SignUpOptions {
            target,
            issuer: Some(issuer),
            keys,
            default_output_dir: None,
            replace: a.force,
        },
        login,
    )
    .await?;
    println!("Signed in as {} ({})", info.email, info.account);
    println!("Keys are in this computer's keychain. Save a backup: svx account backup FILE");
    Ok(ExitCode::SUCCESS)
}

pub async fn show(c: &Client) -> Result<ExitCode> {
    let a = c.account().await?;
    println!("Email:          {}", a.email);
    println!("Signed in with: {}", a.provider);
    println!("Account:        {}", a.account);
    println!("Signing key:    {}", a.signing_key_id);
    println!("Encryption key: {}", a.kem_key_id);
    Ok(ExitCode::SUCCESS)
}

pub async fn change_password(c: &Client) -> Result<ExitCode> {
    let email = c
        .cfg
        .account
        .as_ref()
        .map(|a| a.email.clone())
        .unwrap_or_default();
    let current = account_password("Current password: ")?;
    let new = new_account_password("New password (at least 12 characters): ", &[&email])?;
    c.change_password(&current, &new).await?;
    println!("Password changed.");
    Ok(ExitCode::SUCCESS)
}

pub async fn reset_password(target: ServiceTarget, email: &str) -> Result<ExitCode> {
    let sent = personal::request_email_code(&target, email, CodePurpose::ResetPassword).await?;
    let code = email_code(email)?;
    let new = new_account_password("New password (at least 12 characters): ", &[email])?;
    personal::reset_password(&target, email, sent.challenge, &code, &new).await?;
    println!("Password changed. Sign in with it: svx account signup --email {email}");
    Ok(ExitCode::SUCCESS)
}

pub fn backup(c: &Client, file: &Path) -> Result<ExitCode> {
    let pw = password("New recovery password (at least 10 characters): ")?;
    if std::env::var_os("SVX_RECOVERY_PASSWORD").is_none() {
        let again = rpassword::prompt_password("Repeat it: ")?;
        if again != pw {
            bail!("the passwords don't match");
        }
    }
    c.save_backup(file, &pw)?;
    println!(
        "Backup written to {} (owner-only). Keep it away from this computer.",
        file.display()
    );
    Ok(ExitCode::SUCCESS)
}

pub fn sign_out(c: &Client) -> Result<ExitCode> {
    c.sign_out()?;
    println!("Signed out: keys and configuration removed from this computer.");
    Ok(ExitCode::SUCCESS)
}

pub struct SendArgs {
    pub input: PathBuf,
    pub to: Vec<String>,
    pub no_approval: bool,
    pub no_one_time: bool,
    pub expires: Option<String>,
    pub output: Option<PathBuf>,
    pub force: bool,
}

pub async fn send(c: &Client, a: SendArgs) -> Result<ExitCode> {
    let r = c
        .send(SendOptions {
            input: a.input,
            output: a.output,
            overwrite: a.force,
            to: a.to,
            rules: FileRules {
                require_approval: !a.no_approval,
                one_time: !a.no_one_time,
                expires_at: None,
            },
            expires_at: a.expires.as_deref().map(parse_expiry).transpose()?,
            name: None,
        })
        .await?;
    println!("Encrypted: {}", r.path.display());
    let to: Vec<_> = r.recipients.iter().map(|c| c.email.as_str()).collect();
    println!("  For:        {}", to.join(", "));
    println!("  Approval:   {}", on_off(r.rules.require_approval));
    println!("  One-time:   {}", on_off(r.rules.one_time));
    println!("  File ID:    {}", r.artifact_id);
    println!("Share the .svx file any way you like; only they can open it.");
    Ok(ExitCode::SUCCESS)
}

fn on_off(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}

pub async fn requests(c: &Client) -> Result<ExitCode> {
    let list = c.requests().await?;
    if list.is_empty() {
        println!("No requests waiting.");
    }
    for r in list {
        println!(
            "{}  {} wants to open file {} (asked {})",
            hex::encode(r.request_id),
            r.requester_email.as_deref().unwrap_or(&r.requester),
            hex::encode(r.artifact_id),
            fmt_time(r.requested_at)
        );
    }
    Ok(ExitCode::SUCCESS)
}

pub async fn decide(c: &Client, id: &str, approve: bool) -> Result<ExitCode> {
    let r = if approve {
        c.approve(id).await?
    } else {
        c.decline(id).await?
    };
    println!(
        "{} {}.",
        if approve { "Approved" } else { "Declined" },
        r.requester_email.as_deref().unwrap_or(&r.requester)
    );
    Ok(ExitCode::SUCCESS)
}

fn state(s: RecipientState) -> &'static str {
    match s {
        RecipientState::NotOpened => "not opened",
        RecipientState::Requested => "waiting for approval",
        RecipientState::Approved => "approved",
        RecipientState::Opened => "opened",
        RecipientState::Declined => "declined",
        RecipientState::Revoked => "revoked",
    }
}

fn print_file(f: &FileStatus) {
    println!(
        "File {}  sent {}",
        hex::encode(f.artifact_id),
        fmt_time(f.created_at)
    );
    println!(
        "  Approval {}, one-time {}{}{}",
        on_off(f.rules.require_approval),
        on_off(f.rules.one_time),
        f.rules
            .expires_at
            .or(f.signed_expires_at)
            .map(|t| format!(", stops {}", fmt_time(t)))
            .unwrap_or_default(),
        f.revoked_at.map(|_| ", REVOKED").unwrap_or_default()
    );
    for r in &f.recipients {
        println!(
            "  {:<32} {}",
            r.email.as_deref().unwrap_or(&r.account),
            state(r.state)
        );
    }
}

pub async fn history(c: &Client, json: bool) -> Result<ExitCode> {
    let h = c.history().await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&h)?);
        return Ok(ExitCode::SUCCESS);
    }
    println!("Sent:");
    for f in &h.sent {
        print_file(f);
    }
    println!("Received:");
    for f in &h.received {
        println!(
            "File {}  from {}  sent {}  {}",
            hex::encode(f.artifact_id),
            f.sender_email.as_deref().unwrap_or(&f.sender),
            fmt_time(f.created_at),
            state(f.state)
        );
    }
    Ok(ExitCode::SUCCESS)
}

pub struct FileArgs {
    pub target: String,
    pub approval: Option<bool>,
    pub one_time: Option<bool>,
    pub expires: Option<String>,
    pub revoke: bool,
    pub revoke_for: Vec<String>,
}

pub async fn file(c: &Client, a: FileArgs) -> Result<ExitCode> {
    let change = a.approval.is_some()
        || a.one_time.is_some()
        || a.expires.is_some()
        || a.revoke
        || !a.revoke_for.is_empty();
    let f = if change {
        // People can be named by email: map them to account IDs.
        let current = c.file_status(&a.target).await?;
        let mut revoke_recipients = Vec::new();
        for who in &a.revoke_for {
            let r = current
                .recipients
                .iter()
                .find(|r| {
                    r.account == *who
                        || r.email
                            .as_deref()
                            .is_some_and(|e| e.eq_ignore_ascii_case(who))
                })
                .with_context(|| format!("{who} is not a recipient of this file"))?;
            revoke_recipients.push(r.account.clone());
        }
        c.update_file(
            &a.target,
            &UpdateFileRequest {
                require_approval: a.approval,
                one_time: a.one_time,
                expires_at: a.expires.as_deref().map(parse_expiry).transpose()?,
                revoke: a.revoke,
                revoke_recipients,
            },
        )
        .await?
    } else {
        c.file_status(&a.target).await?
    };
    print_file(&f);
    Ok(ExitCode::SUCCESS)
}
