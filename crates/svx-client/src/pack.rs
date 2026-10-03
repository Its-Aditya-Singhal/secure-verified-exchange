//! Managed packing: recipient and service keys come from the verified
//! registry, so a sender never has to handle recipient key files.

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

use svx_core::crypto::{KeyKind, SigningKey, Suite, os_rng};
use svx_core::format::Identifier;
use svx_core::{Manifest, PackRequest, PackSummary};
use svx_protocol::encoding::b64_encode;
use svx_protocol::{KeyKindWire, KeyStatus, ManagedClient};

use crate::config::ClientConfig;
use crate::error::{ClientError, Result};
use crate::folder;
use crate::registry::{Registry, active_hybrid_kem_key};

pub struct ManagedPack<'a> {
    pub input: &'a Path,
    pub output: PathBuf,
    pub overwrite: bool,
    pub signing_key: &'a SigningKey,
    pub sender_org: Identifier,
    pub recipient_org: Identifier,
    pub policy: Identifier,
    pub expires_at: Option<i64>,
    pub classification: Option<String>,
    pub description: Option<String>,
    /// File name recorded in the encrypted manifest.
    pub name: String,
    /// Content type recorded in the manifest (e.g. the folder marker).
    pub content_type: Option<String>,
    pub chunk_size: Option<u32>,
}

pub struct Packed {
    pub path: PathBuf,
    pub summary: PackSummary,
    pub service_id: String,
}

/// What to pack: a file as is, or a folder zipped into a private temporary
/// file (kept alive by this value) and marked for extraction on open.
pub struct PackInput {
    pub path: PathBuf,
    /// File name for the manifest.
    pub name: String,
    pub content_type: Option<String>,
    /// `<input>.svx` next to the input.
    pub default_output: PathBuf,
    _zip: Option<tempfile::NamedTempFile>,
}

/// Prepare `input` (a file or a folder) for [`pack`]. `name` overrides the
/// manifest file name.
pub fn prepare_input(input: &Path, name: Option<String>) -> Result<PackInput> {
    let base = input
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| ClientError::Config("input has no usable file name".into()))?
        .to_owned();
    if std::fs::symlink_metadata(input)?.is_dir() {
        let zip = folder::zip_dir(input)?;
        Ok(PackInput {
            path: zip.path().to_path_buf(),
            name: name.unwrap_or_else(|| format!("{base}.zip")),
            content_type: Some(folder::FOLDER_CONTENT_TYPE.into()),
            default_output: input.with_file_name(format!("{base}.svx")),
            _zip: Some(zip),
        })
    } else {
        Ok(PackInput {
            path: input.to_path_buf(),
            name: name.unwrap_or(base),
            content_type: None,
            default_output: input.with_extension("svx"),
            _zip: None,
        })
    }
}

pub async fn pack(
    cfg: &ClientConfig,
    client: &ManagedClient,
    req: ManagedPack<'_>,
) -> Result<Packed> {
    let registry = Registry::new(cfg, client)?;

    // New files are always post-quantum hybrid (suite SVX-1H).
    if req.signing_key.kind() != KeyKind::HybridSigning {
        return Err(ClientError::Config(
            "the signing key is a classical Ed25519 key; new files need a post-quantum hybrid \
             key (Ed25519 + ML-DSA-65): generate one with `svx keygen --kind sign` and register it"
                .into(),
        ));
    }
    // The sender's key must be registered, or every recipient will reject.
    let sender = registry.org(req.sender_org.as_str()).await?;
    let my_key_id = req.signing_key.verifying_key().key_id();
    let registered = sender.keys.iter().any(|k| {
        k.kind == KeyKindWire::Ed25519Mldsa65
            && k.status == KeyStatus::Active
            && k.key_id == my_key_id
    });
    if !registered {
        return Err(ClientError::Config(format!(
            "signing key {} is not an active key of {} in the registry",
            hex::encode(my_key_id),
            req.sender_org
        )));
    }
    let recipient = registry.org(req.recipient_org.as_str()).await?;
    let recipient_key = active_hybrid_kem_key(&recipient)?;
    if recipient.key_agent_url.is_none() {
        return Err(ClientError::Config(format!(
            "{} cannot receive artifacts (no key agent)",
            req.recipient_org
        )));
    }
    let service = registry.service().await?;
    let service_key = service
        .kem_public_key()
        .map_err(|_| ClientError::Other("invalid service key".into()))?;
    let service_id = Identifier::new(&service.service_id)
        .map_err(|_| ClientError::Other("invalid service id".into()))?;

    let input = File::open(req.input)?;
    let size = input.metadata()?.len();
    let mut manifest = Manifest::single_file(&req.name, size);
    manifest.files[0].content_type = req.content_type;
    manifest.classification = req.classification;
    manifest.description = req.description;

    let dir = req
        .output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .to_path_buf();
    let tmp = tempfile::NamedTempFile::new_in(&dir)?;
    let summary = svx_core::pack(
        &PackRequest {
            suite: Suite::Svx1H,
            sender_org: req.sender_org,
            signing_key: req.signing_key,
            recipient_org: req.recipient_org,
            recipient_key: &recipient_key,
            service_id,
            service_key: &service_key,
            policy_ref: req.policy,
            created_at: crate::now(),
            expires_at: req.expires_at,
            chunk_size: req.chunk_size,
            manifest,
        },
        BufReader::new(input),
        BufWriter::new(tmp.as_file()),
        &mut os_rng(),
    )
    .map_err(|e| ClientError::Other(e.to_string()))?;
    tmp.as_file().sync_all()?;
    if req.overwrite {
        tmp.persist(&req.output)
            .map_err(|e| ClientError::Io(e.error))?;
    } else {
        tmp.persist_noclobber(&req.output).map_err(|e| {
            if e.error.kind() == std::io::ErrorKind::AlreadyExists {
                ClientError::OutputExists(req.output.clone())
            } else {
                ClientError::Io(e.error)
            }
        })?;
    }
    Ok(Packed {
        path: req.output,
        summary,
        service_id: service.service_id,
    })
}

/// Register an artifact with the managed service (sender-side audit).
pub async fn register(
    cfg: &ClientConfig,
    client: &ManagedClient,
    artifact: &Path,
    bearer: &str,
) -> Result<()> {
    let registry = Registry::new(cfg, client)?;
    let (_, header) = svx_core::inspect(BufReader::new(File::open(artifact)?))
        .map_err(|e| ClientError::Rejected(e.to_string()))?;
    let trust = registry.sender_trust(header.sender_org.as_str()).await?;
    let v = svx_core::verify(BufReader::new(File::open(artifact)?), &trust)
        .map_err(|e| ClientError::Rejected(e.to_string()))?;
    let body = serde_json::json!({
        "header_region": b64_encode(&v.header_region),
        "trailer": b64_encode(&v.trailer.encode().map_err(|e| ClientError::Other(e.to_string()))?),
    });
    let _: serde_json::Value = client
        .post_json(&cfg.service_url, "/v1/artifacts", &body, Some(bearer))
        .await?;
    Ok(())
}
