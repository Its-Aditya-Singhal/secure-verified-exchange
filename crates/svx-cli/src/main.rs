//! `svx` — the SVX command-line client.
//!
//! Offline: `keygen`, `pack` (with key files), `inspect`, `verify`.
//! Managed: `init`, `login`, `logout`, `whoami`, `open`, `status`, `pack
//! --recipient`, `revoke`, `policy`, `organizations`, `audit`.
//!
//! There is no way to decrypt without shares released by the managed
//! service and the recipient's key agent after authentication and
//! authorization. Exit codes: 0 ok, 1 refused/rejected, 2 error, 3 service
//! unavailable.

mod local;
mod managed;

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
        /// The service's registry public key (hex), obtained out of band.
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
        /// Sender's signing key file (Ed25519 + ML-DSA-65). Its owner is the sender organization.
        #[arg(long)]
        sign_key: PathBuf,
        /// Recipient organization (managed: keys come from the verified registry).
        #[arg(long, conflicts_with_all = ["recipient_key", "service_key"])]
        recipient: Option<String>,
        /// Offline mode: recipient organization's X-Wing public key file.
        #[arg(long, requires = "service_key")]
        recipient_key: Option<PathBuf>,
        /// Offline mode: managed service's X-Wing public key file.
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
    /// Artifact signing key (Ed25519 + ML-DSA-65).
    Sign,
    /// Encryption key (X-Wing: X25519 + ML-KEM-768).
    Kem,
    /// The managed service's registry or grant key (Ed25519).
    ServiceSign,
}

#[tokio::main]
async fn main() -> ExitCode {
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
        Cmd::Keygen { kind, owner, out } => local::keygen(kind, &owner, &out),
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
