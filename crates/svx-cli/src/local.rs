//! Offline commands that need no managed service: key generation, packing
//! with explicit key files, inspection and verification.

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result, bail};
use serde_json::json;
use svx_core::crypto::os_rng;
use svx_core::format::{EnvelopeRole, Header, Identifier, Prelude};
use svx_core::{Manifest, PackRequest, TrustStore, keyfile};

use crate::KeyKindArg;

pub fn keygen(kind: KeyKindArg, owner: &str, out: &Path) -> Result<ExitCode> {
    match kind {
        KeyKindArg::Sign => {
            let id = svx_client::keys::generate_signing(out, owner)?;
            println!(
                "Wrote {0}.sign.key (secret) and {0}.sign.pub",
                out.display()
            );
            println!("Key ID: {id}");
        }
        KeyKindArg::Kem => {
            let id = svx_client::keys::generate_kem(out, owner)?;
            println!("Wrote {0}.kem.key (secret) and {0}.kem.pub", out.display());
            println!("Key ID: {id}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub struct PackOpts {
    pub sign_key: PathBuf,
    pub recipient_key: PathBuf,
    pub service_key: PathBuf,
    pub policy: String,
    pub expires: Option<String>,
    pub classification: Option<String>,
    pub description: Option<String>,
    pub name: Option<String>,
    pub chunk_size: Option<u32>,
    pub force: bool,
}

pub fn now() -> i64 {
    svx_protocol::unix_now()
}

pub fn fmt_time(t: i64) -> String {
    match u64::try_from(t) {
        Ok(s) => humantime::format_rfc3339_seconds(UNIX_EPOCH + std::time::Duration::from_secs(s))
            .to_string(),
        Err(_) => format!("<invalid {t}>"),
    }
}

pub fn pack(input: &Path, output: Option<PathBuf>, o: PackOpts) -> Result<ExitCode> {
    let (sender_org, signing_key) =
        keyfile::load_signing_key(&o.sign_key).context("loading signing key")?;
    let (recipient_org, recipient_key) =
        keyfile::load_kem_public(&o.recipient_key).context("loading recipient key")?;
    let (service_id, service_key) =
        keyfile::load_kem_public(&o.service_key).context("loading service key")?;
    let policy_ref = Identifier::new(&o.policy).context("invalid policy reference")?;

    let created_at = now();
    let expires_at = o.expires.as_deref().map(parse_expiry).transpose()?;

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

pub fn header_json(p: &Prelude, h: &Header) -> serde_json::Value {
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

pub fn inspect(path: &Path, as_json: bool) -> Result<ExitCode> {
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

pub fn print_header(v: &serde_json::Value) {
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

/// Human-readable view of verified artifact metadata.
pub fn print_info(i: &svx_client::ArtifactInfo) {
    println!(
        "  Format:     SVX {} (suite {:#06x})",
        i.format_version, i.suite_id
    );
    println!("  Artifact:   {}", i.artifact_id);
    println!("  Sender:     {} (key {})", i.sender_org, i.sender_key_id);
    println!("  Recipient:  {}", i.recipient_org);
    println!("  Service:    {}", i.service_id);
    println!("  Policy:     {}", i.policy_ref);
    println!("  Created:    {}", fmt_time(i.created_at));
    println!(
        "  Expires:    {}",
        i.expires_at.map(fmt_time).unwrap_or_else(|| "never".into())
    );
}

pub fn trust_from_files(trust_files: &[PathBuf]) -> Result<TrustStore> {
    Ok(svx_client::info::trust_from_files(trust_files)?)
}

/// Parse an RFC 3339 expiry and require it to be in the future.
pub fn parse_expiry(s: &str) -> Result<i64> {
    let t = humantime::parse_rfc3339(s)
        .context("--expires must be RFC 3339 UTC, e.g. 2026-10-10T18:00:00Z")?;
    let secs = t
        .duration_since(UNIX_EPOCH)
        .context("expiry before 1970")?
        .as_secs() as i64;
    if secs <= now() {
        bail!("expiry is in the past");
    }
    Ok(secs)
}

pub fn verify(path: &Path, trust: &TrustStore, as_json: bool) -> Result<ExitCode> {
    let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    match svx_core::verify(BufReader::new(f), trust) {
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
