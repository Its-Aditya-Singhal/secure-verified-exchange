//! Artifact metadata, local verification and status: everything that can be
//! learned about an artifact without any key release.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use serde::Serialize;
use svx_core::crypto::Suite;
use svx_core::format::{EnvelopeRole, Header, Prelude};
use svx_core::{TrustStore, keyfile};
use svx_protocol::ManagedClient;

use crate::config::ClientConfig;
use crate::error::{ClientError, Result};
use crate::registry::Registry;

/// Header fields of an artifact. Unverified unless obtained from
/// [`verify_with`] or [`status`].
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ArtifactInfo {
    pub format_version: String,
    pub suite_id: u16,
    /// Human-readable protection level of the suite, e.g. "maximum
    /// (ML-KEM-1024 + P-384, Ed25519 + ML-DSA-87 + SLH-DSA, SHA-512)".
    pub protection: String,
    /// Whether the suite resists quantum attacks (SVX-1H, SVX-2).
    pub post_quantum: bool,
    pub artifact_id: String,
    /// Unix seconds, UTC.
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub sender_org: String,
    pub sender_key_id: String,
    pub recipient_org: String,
    /// Every recipient (several for personal files sent to several people).
    pub recipients: Vec<String>,
    pub service_id: String,
    pub policy_ref: String,
    pub chunk_size: u32,
    pub envelopes: Vec<EnvelopeInfo>,
    pub encrypted_manifest_bytes: usize,
    pub unknown_fields: Vec<u16>,
    /// Signed as view-only (format 1.4): it can be shown in the app, not saved.
    pub view_only: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct EnvelopeInfo {
    pub role: &'static str,
    pub key_id: String,
}

impl ArtifactInfo {
    pub fn new(p: &Prelude, h: &Header) -> Self {
        ArtifactInfo {
            format_version: format!("{}.{}", p.major, p.minor),
            suite_id: p.suite_id,
            protection: Suite::from_id(p.suite_id)
                .map_or("unknown suite", Suite::description)
                .into(),
            post_quantum: Suite::from_id(p.suite_id).is_ok_and(Suite::is_post_quantum),
            artifact_id: hex::encode(h.artifact_id),
            created_at: h.created_at,
            expires_at: h.expires_at,
            sender_org: h.sender_org.to_string(),
            sender_key_id: hex::encode(h.sender_key_id),
            recipient_org: h.recipient_org.to_string(),
            recipients: h.all_recipients().iter().map(|r| r.to_string()).collect(),
            service_id: h.service_id.to_string(),
            policy_ref: h.policy_ref.to_string(),
            chunk_size: h.chunk_size,
            envelopes: h
                .envelopes
                .iter()
                .map(|e| EnvelopeInfo {
                    role: match e.role {
                        EnvelopeRole::Service => "service",
                        EnvelopeRole::RecipientOrg => "recipient-org",
                    },
                    key_id: hex::encode(e.key_id),
                })
                .collect(),
            encrypted_manifest_bytes: h.encrypted_manifest.len(),
            unknown_fields: h.unknown.iter().map(|u| u.tag).collect(),
            view_only: h.view_only,
        }
    }
}

/// Parse the header without verifying anything. Never trust the result.
pub fn inspect(path: &Path) -> Result<ArtifactInfo> {
    let (p, h) = svx_core::inspect(BufReader::new(File::open(path)?))
        .map_err(|e| ClientError::Rejected(e.to_string()))?;
    Ok(ArtifactInfo::new(&p, &h))
}

/// A successfully verified artifact.
#[derive(Clone, Debug, Serialize)]
pub struct Verified {
    pub info: ArtifactInfo,
    pub chunk_count: u64,
    pub expired: bool,
}

/// Verify signature and integrity of the whole file against `trust`.
pub fn verify_with(path: &Path, trust: &TrustStore) -> Result<Verified> {
    let v = svx_core::verify(BufReader::new(File::open(path)?), trust)
        .map_err(|e| ClientError::Rejected(e.to_string()))?;
    Ok(Verified {
        info: ArtifactInfo::new(&v.prelude, &v.header),
        chunk_count: v.chunk_count,
        expired: v.is_expired(crate::now()),
    })
}

/// Trust store from `*.sign.pub` files (offline verification).
pub fn trust_from_files(files: &[PathBuf]) -> Result<TrustStore> {
    let mut trust = TrustStore::new();
    for f in files {
        let (org, vk) = keyfile::load_verifying_key(f)
            .map_err(|e| ClientError::Config(format!("loading {}: {e}", f.display())))?;
        trust.add(org, vk);
    }
    Ok(trust)
}

/// Sender trust for `path` from the verified registry. An unknown sender is
/// a rejection; an unreachable service is [`ClientError::Unavailable`].
pub async fn registry_trust(
    cfg: &ClientConfig,
    client: &ManagedClient,
    path: &Path,
) -> Result<TrustStore> {
    let info = inspect(path)?;
    match Registry::new(cfg, client)?
        .sender_trust(&info.sender_org)
        .await
    {
        Ok(t) => Ok(t),
        Err(e @ ClientError::Unavailable(_)) => Err(e),
        Err(_) => Err(ClientError::Rejected(format!(
            "sender {} is not a verified organization",
            info.sender_org
        ))),
    }
}

/// Local status of an artifact for this client: verified against the
/// registry, no key release and no audit event.
#[derive(Clone, Debug, Serialize)]
pub struct Status {
    pub info: ArtifactInfo,
    pub chunk_count: u64,
    pub expired: bool,
    /// The user's organization (or personal account) is a recipient.
    pub for_you: bool,
    /// Who sent it, for display: a personal account's verified email, or
    /// the organization's name.
    pub sender_name: String,
}

pub async fn status(cfg: &ClientConfig, client: &ManagedClient, path: &Path) -> Result<Status> {
    let info = inspect(path)?;
    let sender = match Registry::new(cfg, client)?.org(&info.sender_org).await {
        Ok(r) => r,
        Err(e @ ClientError::Unavailable(_)) => return Err(e),
        Err(_) => {
            return Err(ClientError::Rejected(format!(
                "sender {} is not a verified organization",
                info.sender_org
            )));
        }
    };
    let mut trust = TrustStore::new();
    sender
        .add_signing_keys_to(&mut trust)
        .map_err(|e| ClientError::Other(e.to_string()))?;
    let v = verify_with(path, &trust)?;
    Ok(Status {
        for_you: v.info.recipients.iter().any(|r| r == &cfg.org_id),
        sender_name: sender_label(&sender),
        info: v.info,
        chunk_count: v.chunk_count,
        expired: v.expired,
    })
}

/// How to name a sender: a personal account's verified email, after the
/// name it gave (email accounts) as `First Last <email>`; a company's
/// display name.
pub fn sender_label(sender: &svx_protocol::OrgRecord) -> String {
    match &sender.account_email {
        Some(e) if &sender.display_name != e => format!("{} <{e}>", sender.display_name),
        Some(e) => e.clone(),
        None => sender.display_name.clone(),
    }
}

/// An artifact ID given as 32 hex digits, or read from an artifact file.
pub fn artifact_id_of(target: &str) -> Result<[u8; 16]> {
    let mut id = [0u8; 16];
    if target.len() == 32 && hex::decode_to_slice(target, &mut id).is_ok() {
        return Ok(id);
    }
    let (_, h) = svx_core::inspect(BufReader::new(File::open(target)?))
        .map_err(|e| ClientError::Rejected(format!("not a valid SVX file: {e}")))?;
    Ok(h.artifact_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_id_from_hex() {
        let id = artifact_id_of("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(id[0], 0x00);
        assert_eq!(id[15], 0xff);
    }

    #[test]
    fn artifact_id_missing_file() {
        assert!(matches!(
            artifact_id_of("/nonexistent/x.svx"),
            Err(ClientError::Io(_))
        ));
    }
}
