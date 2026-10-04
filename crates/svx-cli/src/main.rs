//! `svx` — the SVX command-line client.
//!
//! Offline: `keygen`, `pack` (with key files), `inspect`, `verify`.
//! Managed: `init`, `login`, `logout`, `whoami`, `open`, `status`, `pack
//! --recipient`, `revoke`, `policy`, `organizations`, `audit`.
//! Personal accounts: `account`, `send`, `requests`, `approve`, `decline`,
//! `history`, `file` (and `open`).
//!
//! There is no way to decrypt without shares released by the managed
//! service and the recipient's key agent after authentication and
//! authorization. Exit codes: 0 ok, 1 refused/rejected, 2 error, 3 service
//! unavailable.

mod local;
mod managed;
mod personal;
mod release;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

use managed::{Ctx, InitArgs, ManagedPackArgs, OpenArgs, PolicyCmd};

#[derive(Parser)]
#[command(name = "svx", version, about = "SVX managed secure exchange — client")]
struct Cli {
    /// Configuration file (default: $SVX_CONFIG or the platform config dir).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Ask for Touch ID / the computer's password / Windows Hello before a
    /// personal account's keys are used, as the desktop app does.
    #[arg(long, global = true)]
    require_presence: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Configure the managed service and your organization.
    Init {
        /// Managed service URL.
        #[arg(long)]
        service: String,
        /// The fingerprint of the service's registry key (64 hex), obtained
        /// out of band.
        #[arg(long)]
        registry_key: String,
        /// Your organization ID.
        #[arg(long)]
        org: String,
        /// SVX client ID at your organization's IdP.
        #[arg(long)]
        client_id: String,
        /// Development mode (loopback http, dev logins). Never in production.
        #[arg(long)]
        dev: bool,
        /// Default directory for opened files.
        #[arg(long)]
        output_dir: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Sign in for administrative commands (cached briefly, owner-only file).
    Login {
        #[arg(long)]
        dev_user: Option<String>,
        /// Print the sign-in URL instead of opening a browser.
        #[arg(long)]
        no_browser: bool,
    },
    /// Remove the cached session.
    Logout,
    /// Show the signed-in identity.
    Whoami,
    /// Authenticate, obtain authorization, verify and decrypt an artifact.
    Open {
        file: PathBuf,
        /// Output directory (default: config default_output_dir, else ~/SVX).
        #[arg(short = 'o', long)]
        output_dir: Option<PathBuf>,
        /// Write plaintext to stdout (refused when stdout is a terminal).
        #[arg(long, conflicts_with = "output_dir")]
        stdout: bool,
        #[arg(long)]
        overwrite: bool,
        #[arg(long)]
        dev_user: Option<String>,
        #[arg(long)]
        no_browser: bool,
    },
    /// Verify an artifact against the registry and show who it is for.
    Status { file: PathBuf },
    /// Encrypt and sign a file (or a folder, managed mode) into a .svx artifact.
    Pack {
        input: PathBuf,
        /// Sender's signing key file (SVX-2: Ed25519 + ML-DSA-87 + SLH-DSA). Its owner is the sender organization.
        #[arg(long)]
        sign_key: PathBuf,
        /// Recipient organization (managed: keys come from the verified registry).
        #[arg(long, conflicts_with_all = ["recipient_key", "service_key"])]
        recipient: Option<String>,
        /// Offline mode: recipient organization's MLKEM1024-P384 public key file.
        #[arg(long, requires = "service_key")]
        recipient_key: Option<PathBuf>,
        /// Offline mode: managed service's MLKEM1024-P384 public key file.
        #[arg(long, requires = "recipient_key")]
        service_key: Option<PathBuf>,
        /// Authorization policy reference (defined by the recipient).
        #[arg(long)]
        policy: String,
        /// Expiry as RFC 3339 UTC, e.g. 2026-10-10T18:00:00Z.
        #[arg(long)]
        expires: Option<String>,
        /// Classification label (stored only in the encrypted manifest).
        #[arg(long)]
        classification: Option<String>,
        /// Description (stored only in the encrypted manifest).
        #[arg(long)]
        description: Option<String>,
        /// File name recorded in the encrypted manifest (default: input file name).
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        chunk_size: Option<u32>,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        force: bool,
        /// Register the artifact with the service (requires `svx login`).
        #[arg(long, requires = "recipient")]
        register: bool,
    },
    /// Revoke future access to an artifact (file or artifact ID). Admin.
    Revoke { target: String },
    /// Manage your organization's authorization policies. Admin.
    Policy {
        #[command(subcommand)]
        cmd: PolicySub,
    },
    /// Show verified organization records.
    Organizations {
        #[command(subcommand)]
        cmd: OrgSub,
    },
    /// Show your organization's audit log. Admin.
    Audit {
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// Personal account: sign up, backup, restore.
    Account {
        #[command(subcommand)]
        cmd: AccountSub,
    },
    /// Personal account: encrypt a file or folder for people by email.
    Send {
        input: PathBuf,
        /// Recipient email (repeatable).
        #[arg(long = "to", required = true)]
        to: Vec<String>,
        /// Don't ask me before each open.
        #[arg(long)]
        no_approval: bool,
        /// Allow opening more than once.
        #[arg(long)]
        no_one_time: bool,
        /// View only: recipients see it in the SVX desktop app but can't save, copy or print it
        /// (PDF, images, plain text, or Office files converted with LibreOffice). Not stopped:
        /// a photo of the screen.
        #[arg(long)]
        view_only: bool,
        /// With --view-only: recipients may ask to keep a copy (you decide, with `svx approve`).
        #[arg(long, requires = "view_only")]
        allow_share_requests: bool,
        /// Expiry as RFC 3339 UTC, signed into the file.
        #[arg(long)]
        expires: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Personal account: ask the sender to let you keep a copy of a view-only file you received
    /// (file or ID), and show where the request stands.
    Keep {
        target: String,
        /// Wait for the sender's answer (Ctrl-C to stop).
        #[arg(long)]
        wait: bool,
    },
    /// Personal account: requests waiting for your approval.
    Requests,
    /// Personal account: approve a request (check it's really them first).
    Approve { request_id: String },
    /// Personal account: decline a request.
    Decline { request_id: String },
    /// Personal account: files sent and received.
    History {
        #[arg(long)]
        json: bool,
    },
    /// Personal account: show or change a sent file's rules (ID or .svx file).
    File {
        target: String,
        #[arg(long, value_enum)]
        approval: Option<OnOff>,
        #[arg(long, value_enum)]
        one_time: Option<OnOff>,
        /// View only on or off (on only for a file that was sent view-only; off lets everyone
        /// who opens it save it, and can't be taken back).
        #[arg(long, value_enum)]
        view_only: Option<OnOff>,
        /// For a view-only file: whether recipients may ask to keep a copy.
        #[arg(long, value_enum)]
        share_requests: Option<OnOff>,
        /// Stop opening at this time (RFC 3339 UTC; not later than the signed expiry).
        #[arg(long)]
        expires: Option<String>,
        /// Revoke for everyone.
        #[arg(long)]
        revoke: bool,
        /// Revoke for one person (email or account ID; repeatable).
        #[arg(long = "revoke-for")]
        revoke_for: Vec<String>,
    },
    /// Desktop app releases: sign the update manifest (offline, with the
    /// release key from `svx keygen --kind sign`).
    #[command(subcommand)]
    Release(ReleaseSub),
    /// Generate an organization key pair (test/dev; production keys live in a KMS/HSM).
    Keygen {
        #[arg(long, value_enum)]
        kind: KeyKindArg,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Show the public header WITHOUT verifying it.
    Inspect {
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Verify structure, sender trust, integrity and signature (no decryption).
    Verify {
        file: PathBuf,
        /// Trusted sender public signing key file(s).
        #[arg(long = "trust", required_unless_present = "registry")]
        trust: Vec<PathBuf>,
        /// Trust sender keys from the verified registry instead.
        #[arg(long, conflicts_with = "trust")]
        registry: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ReleaseSub {
    /// Sign a release: write `manifest.json` and copy the packages into
    /// OUT, ready for `svx-server --updates-dir OUT`.
    Sign {
        /// The release signing key (`*.sign.key`, SVX-2).
        #[arg(long)]
        key: PathBuf,
        /// The new version (`major.minor.patch`, as in tauri.conf.json).
        #[arg(long)]
        version: String,
        #[arg(long, default_value = "")]
        notes: String,
        /// Where the packages will be downloadable, e.g.
        /// `https://svx.example/v1/updates/files`.
        #[arg(long)]
        base_url: String,
        /// `<os>-<arch>=<package>` (repeatable), e.g.
        /// `darwin-aarch64=…/Secure Verified Exchange.app.tar.gz`. Its Tauri
        /// signature is read from `<package>.sig`.
        #[arg(long = "platform", required = true)]
        platforms: Vec<String>,
        /// Output directory (created if needed).
        #[arg(long)]
        out: PathBuf,
    },
    /// Print a release key's fingerprint (what release builds pin as
    /// SVX_RELEASE_KEY).
    Fingerprint {
        /// The release key's public half (`*.sign.pub`).
        key: PathBuf,
    },
    /// Check a published manifest against a release key fingerprint.
    Verify {
        manifest: PathBuf,
        #[arg(long)]
        fingerprint: String,
    },
}

#[derive(Subcommand)]
enum AccountSub {
    /// Sign up (or sign in on this computer) with Google or email.
    Signup {
        /// Service URL (default: the built-in service, or $SVX_SERVICE_URL).
        #[arg(long, requires = "registry_key")]
        service: Option<String>,
        /// The service's registry key fingerprint (64 hex).
        #[arg(long, requires = "service")]
        registry_key: Option<String>,
        /// Development service (loopback http, dev sign-in).
        #[arg(long)]
        dev: bool,
        /// Google (default: the first the service offers).
        #[arg(long, conflicts_with = "email")]
        provider: Option<String>,
        /// Use an email account instead: asks for the password and the
        /// code emailed to this address. With --first-name and --last-name
        /// it creates the account; without, it signs in on this computer.
        #[arg(long)]
        email: Option<String>,
        #[arg(long, requires = "email", requires = "last_name")]
        first_name: Option<String>,
        #[arg(long, requires = "email", requires = "first_name")]
        last_name: Option<String>,
        #[arg(long)]
        dev_user: Option<String>,
        #[arg(long)]
        no_browser: bool,
        /// Restore keys from a backup file (asks for its password).
        #[arg(long)]
        restore: Option<PathBuf>,
        /// Replace the account's keys (files sent to the old ones stop opening).
        #[arg(long)]
        reset: bool,
        /// Replace an existing configuration on this computer.
        #[arg(long)]
        force: bool,
    },
    /// Show the account and its key IDs.
    Show,
    /// Change the password of an email account.
    Password,
    /// Forgot the password of an email account: set a new one with an
    /// emailed code.
    ResetPassword {
        email: String,
        #[arg(long, requires = "registry_key")]
        service: Option<String>,
        #[arg(long, requires = "service")]
        registry_key: Option<String>,
        #[arg(long)]
        dev: bool,
    },
    /// Save an encrypted backup of the keys (asks for a recovery password).
    Backup { file: PathBuf },
    /// Remove the account's keys and configuration from this computer.
    Signout,
}

#[derive(Clone, Copy, ValueEnum)]
enum OnOff {
    On,
    Off,
}

impl OnOff {
    fn on(self) -> bool {
        matches!(self, OnOff::On)
    }
}

#[derive(Subcommand)]
enum PolicySub {
    List,
    Show {
        name: String,
    },
    Set {
        name: String,
        #[arg(long)]
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum OrgSub {
    Show { org: String },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum KeyKindArg {
    /// Signing key (Ed25519 + ML-DSA-87 + SLH-DSA-SHA2-256s).
    Sign,
    /// Encryption key (MLKEM1024-P384: ML-KEM-1024 + P-384).
    Kem,
}

#[tokio::main]
async fn main() -> ExitCode {
    svx_protocol::install_tls_provider();
    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(e) => {
            if let Some(ce) = e.downcast_ref::<svx_client::ClientError>() {
                return managed::report(ce);
            }
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let config = cli.config.as_deref();
    personal::REQUIRE_PRESENCE.store(cli.require_presence, std::sync::atomic::Ordering::Relaxed);
    match cli.cmd {
        Cmd::Init {
            service,
            registry_key,
            org,
            client_id,
            dev,
            output_dir,
            force,
        } => {
            managed::init(
                config,
                InitArgs {
                    service,
                    registry_key,
                    org,
                    client_id,
                    dev,
                    output_dir,
                    force,
                },
            )
            .await
        }
        Cmd::Login {
            dev_user,
            no_browser,
        } => managed::login(&Ctx::load(config)?, dev_user, no_browser).await,
        Cmd::Logout => managed::logout(&Ctx::load(config)?),
        Cmd::Whoami => managed::whoami(&Ctx::load(config)?).await,
        Cmd::Open {
            file,
            output_dir,
            stdout,
            overwrite,
            dev_user,
            no_browser,
        } => {
            managed::open(
                &Ctx::load(config)?,
                OpenArgs {
                    file,
                    output_dir,
                    stdout,
                    overwrite,
                    dev_user,
                    no_browser,
                },
            )
            .await
        }
        Cmd::Status { file } => managed::status(&Ctx::load(config)?, &file).await,
        Cmd::Pack {
            input,
            sign_key,
            recipient,
            recipient_key,
            service_key,
            policy,
            expires,
            classification,
            description,
            name,
            chunk_size,
            output,
            force,
            register,
        } => match (recipient, recipient_key, service_key) {
            (Some(recipient), None, None) => {
                managed::pack(
                    &Ctx::load(config)?,
                    ManagedPackArgs {
                        input,
                        output,
                        force,
                        sign_key,
                        recipient,
                        policy,
                        expires,
                        classification,
                        description,
                        name,
                        chunk_size,
                        register,
                    },
                )
                .await
            }
            (None, Some(recipient_key), Some(service_key)) => local::pack(
                &input,
                output,
                local::PackOpts {
                    sign_key,
                    recipient_key,
                    service_key,
                    policy,
                    expires,
                    classification,
                    description,
                    name,
                    chunk_size,
                    force,
                },
            ),
            _ => bail!(
                "use either --recipient ORG (managed) or --recipient-key and --service-key (offline)"
            ),
        },
        Cmd::Revoke { target } => managed::revoke(&Ctx::load(config)?, &target).await,
        Cmd::Policy { cmd } => {
            let cmd = match cmd {
                PolicySub::List => PolicyCmd::List,
                PolicySub::Show { name } => PolicyCmd::Show(name),
                PolicySub::Set { name, file } => PolicyCmd::Set { name, file },
            };
            managed::policy(&Ctx::load(config)?, cmd).await
        }
        Cmd::Organizations {
            cmd: OrgSub::Show { org },
        } => managed::organization(&Ctx::load(config)?, &org).await,
        Cmd::Audit { limit, json } => managed::audit(&Ctx::load(config)?, limit, json).await,
        Cmd::Account { cmd } => match cmd {
            AccountSub::Signup {
                service,
                registry_key,
                dev,
                provider,
                email,
                first_name,
                last_name,
                dev_user,
                no_browser,
                restore,
                reset,
                force,
            } => {
                personal::sign_up(
                    config,
                    personal::SignUpArgs {
                        service,
                        registry_key,
                        dev,
                        provider,
                        email,
                        names: first_name.zip(last_name),
                        dev_user,
                        no_browser,
                        reset,
                        restore,
                        force,
                    },
                )
                .await
            }
            AccountSub::Show => personal::show(&personal::client(config)?).await,
            AccountSub::Password => personal::change_password(&personal::client(config)?).await,
            AccountSub::ResetPassword {
                email,
                service,
                registry_key,
                dev,
            } => {
                personal::reset_password(personal::target(service, registry_key, dev)?, &email)
                    .await
            }
            AccountSub::Backup { file } => personal::backup(&personal::client(config)?, &file),
            AccountSub::Signout => personal::sign_out(&personal::client(config)?),
        },
        Cmd::Send {
            input,
            to,
            no_approval,
            no_one_time,
            view_only,
            allow_share_requests,
            expires,
            output,
            force,
        } => {
            personal::send(
                &personal::client(config)?,
                personal::SendArgs {
                    input,
                    to,
                    no_approval,
                    no_one_time,
                    view_only,
                    allow_share_requests,
                    expires,
                    output,
                    force,
                },
            )
            .await
        }
        Cmd::Keep { target, wait } => {
            personal::keep(&personal::client(config)?, &target, wait).await
        }
        Cmd::Requests => personal::requests(&personal::client(config)?).await,
        Cmd::Approve { request_id } => {
            personal::decide(&personal::client(config)?, &request_id, true).await
        }
        Cmd::Decline { request_id } => {
            personal::decide(&personal::client(config)?, &request_id, false).await
        }
        Cmd::History { json } => personal::history(&personal::client(config)?, json).await,
        Cmd::File {
            target,
            approval,
            one_time,
            view_only,
            share_requests,
            expires,
            revoke,
            revoke_for,
        } => {
            personal::file(
                &personal::client(config)?,
                personal::FileArgs {
                    target,
                    approval: approval.map(OnOff::on),
                    one_time: one_time.map(OnOff::on),
                    view_only: view_only.map(OnOff::on),
                    share_requests: share_requests.map(OnOff::on),
                    expires,
                    revoke,
                    revoke_for,
                },
            )
            .await
        }
        Cmd::Keygen { kind, owner, out } => local::keygen(kind, &owner, &out),
        Cmd::Release(ReleaseSub::Sign {
            key,
            version,
            notes,
            base_url,
            platforms,
            out,
        }) => release::sign(&key, &version, &notes, &base_url, &platforms, &out),
        Cmd::Release(ReleaseSub::Fingerprint { key }) => release::fingerprint(&key),
        Cmd::Release(ReleaseSub::Verify {
            manifest,
            fingerprint,
        }) => release::verify(&manifest, &fingerprint),
        Cmd::Inspect { file, json } => local::inspect(&file, json),
        Cmd::Verify {
            file,
            trust,
            registry,
            json,
        } => {
            let trust = if registry {
                managed::registry_trust(&Ctx::load(config)?, &file).await?
            } else {
                local::trust_from_files(&trust)?
            };
            local::verify(&file, &trust, json)
        }
    }
}
