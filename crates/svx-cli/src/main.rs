//! `svx` — create, inspect and verify SVX artifacts.
//!
//! Phase 1 deliberately has no `open`/`unpack` command: decryption requires
//! key shares released by the managed service after authentication and
//! authorization (Phase 2/3). There is no local bypass.

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;
use svx_core::crypto::{KemSecretKey, SigningKey, os_rng};
use svx_core::format::{EnvelopeRole, Header, Identifier, Prelude};
use svx_core::{Manifest, PackRequest, TrustStore, keyfile};

#[derive(Parser)]
#[command(
    name = "svx",
    version,
    about = "SVX managed secure exchange — reference CLI"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an organization key pair (test/dev use; production keys live in a KMS/HSM).
    Keygen {
        #[arg(long, value_enum)]
        kind: KeyKindArg,
        /// Owner identifier, e.g. `acme-security` or `svx.example`.
        #[arg(long)]
        owner: String,
        /// Output prefix; writes `<prefix>.sign.{key,pub}` or `<prefix>.kem.{key,pub}`.
        #[arg(long)]
        out: PathBuf,
    },
    /// Encrypt and sign a file into a .svx artifact.
    Pack {
        input: PathBuf,
        /// Sender's Ed25519 secret key file. Its owner is the sender organization.
        #[arg(long)]
        sign_key: PathBuf,
        /// Recipient organization's X25519 public key file. Its owner is the recipient organization.
        #[arg(long)]
        recipient_key: PathBuf,
        /// Managed service's X25519 public key file. Its owner is the service ID.
        #[arg(long)]
        service_key: PathBuf,
        /// Authorization policy reference held by the managed service.
        #[arg(long)]
        policy: String,
        /// Expiry as RFC 3339 UTC, e.g. 2026-10-10T18:00:00Z.
        #[arg(long)]
        expires: Option<String>,
        /// Classification label (stored only in the encrypted manifest).
        #[arg(long)]
        classification: Option<String>,
        /// Free-text description (stored only in the encrypted manifest).
        #[arg(long)]
        description: Option<String>,
        /// File name recorded in the encrypted manifest (default: input file name).
        #[arg(long)]
        name: Option<String>,
        /// Plaintext chunk size in bytes.
        #[arg(long)]
        chunk_size: Option<u32>,
        /// Output path (default: input with .svx extension).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Overwrite the output if it exists.
        #[arg(long)]
        force: bool,
    },
    /// Show the public header WITHOUT verifying it.
    Inspect {
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Verify structure, sender trust, integrity and signature. Exit code 0 = valid.
    Verify {
        file: PathBuf,
        /// Trusted sender public signing key file(s).
        #[arg(long = "trust", required = true)]
        trust: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum KeyKindArg {
    Sign,
    Kem,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.cmd {
        Cmd::Keygen { kind, owner, out } => keygen(kind, &owner, &out),
        Cmd::Pack {
            input,
            sign_key,
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
        } => {
            let opts = PackOpts {
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
            };
            pack(&input, output, opts)
        }
        Cmd::Inspect { file, json } => inspect(&file, json),
        Cmd::Verify { file, trust, json } => verify(&file, &trust, json),
    }
}

fn keygen(kind: KeyKindArg, owner: &str, out: &Path) -> Result<ExitCode> {
    let owner = Identifier::new(owner).context("invalid owner identifier")?;
    let mut rng = os_rng();
    match kind {
        KeyKindArg::Sign => {
            let sk = SigningKey::generate(&mut rng);
            keyfile::write_signing_pair(out, &owner, &sk)?;
            println!(
                "Wrote {0}.sign.key (secret) and {0}.sign.pub",
                out.display()
            );
            println!("Key ID: {}", hex::encode(sk.verifying_key().key_id()));
        }
        KeyKindArg::Kem => {
            let sk = KemSecretKey::generate(&mut rng);
            keyfile::write_kem_pair(out, &owner, &sk)?;
            println!("Wrote {0}.kem.key (secret) and {0}.kem.pub", out.display());
            println!("Key ID: {}", hex::encode(sk.public_key().key_id()));
        }
    }
    Ok(ExitCode::SUCCESS)
}

struct PackOpts {
    sign_key: PathBuf,
    recipient_key: PathBuf,
    service_key: PathBuf,
    policy: String,
    expires: Option<String>,
    classification: Option<String>,
    description: Option<String>,
    name: Option<String>,
    chunk_size: Option<u32>,
    force: bool,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn fmt_time(t: i64) -> String {
    match u64::try_from(t) {
        Ok(s) => humantime::format_rfc3339_seconds(UNIX_EPOCH + std::time::Duration::from_secs(s))
            .to_string(),
        Err(_) => format!("<invalid {t}>"),
    }
}

fn pack(input: &Path, output: Option<PathBuf>, o: PackOpts) -> Result<ExitCode> {
    let (sender_org, signing_key) =
        keyfile::load_signing_key(&o.sign_key).context("loading signing key")?;
    let (recipient_org, recipient_key) =
        keyfile::load_kem_public(&o.recipient_key).context("loading recipient key")?;
    let (service_id, service_key) =
        keyfile::load_kem_public(&o.service_key).context("loading service key")?;
    let policy_ref = Identifier::new(&o.policy).context("invalid policy reference")?;

    let created_at = now();
    let expires_at = match &o.expires {
        Some(s) => {
            let t = humantime::parse_rfc3339(s)
                .context("--expires must be RFC 3339 UTC, e.g. 2026-10-10T18:00:00Z")?;
            let secs = t
                .duration_since(UNIX_EPOCH)
                .context("expiry before 1970")?
                .as_secs() as i64;
            if secs <= created_at {
                bail!("expiry is in the past");
            }
            Some(secs)
        }
        None => None,
    };

    let file = File::open(input).with_context(|| format!("opening {}", input.display()))?;
    let size = file.metadata()?.len();
    let name = match o.name {
        Some(n) => n,
        None => input
            .file_name()
            .and_then(|n| n.to_str())
            .context("input has no usable file name")?
            .to_owned(),
    };
    let mut manifest = Manifest::single_file(&name, size);
    manifest.classification = o.classification;
    manifest.description = o.description;

    let out_path = output.unwrap_or_else(|| input.with_extension("svx"));
    let dir = match out_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    // Write to a temporary file and move into place only on success, so a
    // failure never leaves a partial artifact behind.
    let tmp = tempfile::NamedTempFile::new_in(&dir).context("creating temporary output")?;

    let req = PackRequest {
        sender_org: sender_org.clone(),
        signing_key: &signing_key,
        recipient_org: recipient_org.clone(),
        recipient_key: &recipient_key,
        service_id: service_id.clone(),
        service_key: &service_key,
        policy_ref: policy_ref.clone(),
        created_at,
        expires_at,
        chunk_size: o.chunk_size,
        manifest,
    };
    let summary = svx_core::pack(
        &req,
        BufReader::new(file),
        BufWriter::new(tmp.as_file()),
        &mut os_rng(),
    )?;
    tmp.as_file().sync_all()?;
    if o.force {
        tmp.persist(&out_path)?;
    } else {
        tmp.persist_noclobber(&out_path)
            .map_err(|e| e.error)
            .with_context(|| format!("{} exists (use --force to overwrite)", out_path.display()))?;
    }

    println!("Created:     {}", out_path.display());
    println!("Artifact ID: {}", hex::encode(summary.artifact_id));
    println!("Sender:      {sender_org}");
    println!("Recipient:   {recipient_org}");
    println!("Service:     {service_id}");
    println!("Policy:      {policy_ref}");
    println!(
        "Expiration:  {}",
        expires_at.map(fmt_time).unwrap_or_else(|| "none".into())
    );
    println!("Encryption:  ChaCha20-Poly1305 (STREAM), split-key HPKE envelopes");
    println!(
        "Signature:   Ed25519, key {}",
        hex::encode(signing_key.verifying_key().key_id())
    );
    Ok(ExitCode::SUCCESS)
}

fn header_json(p: &Prelude, h: &Header) -> serde_json::Value {
    json!({
        "format_version": format!("{}.{}", p.major, p.minor),
        "suite_id": p.suite_id,
        "artifact_id": hex::encode(h.artifact_id),
        "created_at": fmt_time(h.created_at),
        "expires_at": h.expires_at.map(fmt_time),
        "sender_org": h.sender_org.as_str(),
        "sender_key_id": hex::encode(h.sender_key_id),
        "recipient_org": h.recipient_org.as_str(),
        "service_id": h.service_id.as_str(),
        "policy_ref": h.policy_ref.as_str(),
        "chunk_size": h.chunk_size,
        "envelopes": h.envelopes.iter().map(|e| json!({
            "role": match e.role { EnvelopeRole::Service => "service", EnvelopeRole::RecipientOrg => "recipient-org" },
            "key_id": hex::encode(e.key_id),
        })).collect::<Vec<_>>(),
        "encrypted_manifest_bytes": h.encrypted_manifest.len(),
        "unknown_fields": h.unknown.iter().map(|u| u.tag).collect::<Vec<_>>(),
    })
}

fn inspect(path: &Path, as_json: bool) -> Result<ExitCode> {
    let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let (p, h) = svx_core::inspect(BufReader::new(f))?;
    let mut v = header_json(&p, &h);
    v["verified"] = json!(false);
    if as_json {
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        println!("UNVERIFIED header (run `svx verify` before trusting any of this)");
        print_header(&v);
    }
    Ok(ExitCode::SUCCESS)
}

fn print_header(v: &serde_json::Value) {
    let s = |k: &str| {
        v[k].as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| v[k].to_string())
    };
    println!(
        "  Format:     SVX {} (suite {:#06x})",
        s("format_version"),
        v["suite_id"].as_u64().unwrap_or(0)
    );
    println!("  Artifact:   {}", s("artifact_id"));
    println!(
        "  Sender:     {} (key {})",
        s("sender_org"),
        s("sender_key_id")
    );
    println!("  Recipient:  {}", s("recipient_org"));
    println!("  Service:    {}", s("service_id"));
    println!("  Policy:     {}", s("policy_ref"));
    println!("  Created:    {}", s("created_at"));
    println!(
        "  Expires:    {}",
        v["expires_at"].as_str().unwrap_or("never")
    );
}

fn verify(path: &Path, trust_files: &[PathBuf], as_json: bool) -> Result<ExitCode> {
    let mut trust = TrustStore::new();
    for t in trust_files {
        let (org, vk) =
            keyfile::load_verifying_key(t).with_context(|| format!("loading {}", t.display()))?;
        trust.add(org, vk);
    }
    let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    match svx_core::verify(BufReader::new(f), &trust) {
        Ok(v) => {
            let expired = v.is_expired(now());
            let mut j = header_json(&v.prelude, &v.header);
            j["verified"] = json!(true);
            j["chunk_count"] = json!(v.chunk_count);
            j["expired"] = json!(expired);
            if as_json {
                println!("{}", serde_json::to_string_pretty(&j)?);
            } else {
                println!("VALID: signature and integrity verified");
                print_header(&j);
                if expired {
                    println!(
                        "  WARNING: artifact has expired; the managed service will refuse key release"
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &json!({"verified": false, "error": e.to_string()})
                    )?
                );
            } else {
                println!("REJECTED: {e}");
            }
            Ok(ExitCode::from(1))
        }
    }
}
