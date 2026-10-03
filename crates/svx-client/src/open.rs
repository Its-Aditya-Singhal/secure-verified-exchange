//! The fail-closed open flow (product spec §12, §25; `docs/client.md`).
//!
//! Order matters: everything that can be checked locally is checked before
//! the user is asked to log in, and nothing is decrypted unless every step
//! succeeds. Plaintext is written to a private temporary file inside the
//! chosen directory and only renamed into place once the whole payload has
//! authenticated.

use std::fs::File;
use std::io::{BufReader, BufWriter, Seek, Write};
use std::path::{Path, PathBuf};

use svx_core::Manifest;
use svx_protocol::{ManagedClient, ReleaseSession};

use crate::config::ClientConfig;
use crate::error::{ClientError, Result};
use crate::folder;
use crate::login::Authenticator;
use crate::registry::Registry;

/// Progress events, for UIs to narrate the flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    Verifying,
    SignatureValid { sender: String },
    Connecting,
    Authenticating,
    CheckingAuthorization,
    AccessApproved,
    Decrypting,
}

impl Step {
    /// Stable snake_case name, for SDK callbacks.
    pub fn name(&self) -> &'static str {
        match self {
            Step::Verifying => "verifying",
            Step::SignatureValid { .. } => "signature_valid",
            Step::Connecting => "connecting",
            Step::Authenticating => "authenticating",
            Step::CheckingAuthorization => "checking_authorization",
            Step::AccessApproved => "access_approved",
            Step::Decrypting => "decrypting",
        }
    }
}

/// Where plaintext goes.
pub enum Output {
    /// Write `<dir>/<manifest file name>`; refuse to overwrite unless asked.
    Dir { dir: PathBuf, overwrite: bool },
    /// Stream to a writer (e.g. stdout). The caller is responsible for
    /// discarding output if an error is returned.
    Writer(Box<dyn Write + Send>),
}

#[derive(Debug)]
pub struct OpenOutcome {
    pub manifest: Manifest,
    /// The written file (or extracted folder), for [`Output::Dir`].
    pub path: Option<PathBuf>,
    pub sender_org: String,
    pub artifact_id: String,
}

impl OpenOutcome {
    /// Whether the payload is a folder (extracted for [`Output::Dir`]).
    pub fn is_folder(&self) -> bool {
        self.manifest.files[0].content_type.as_deref() == Some(folder::FOLDER_CONTENT_TYPE)
    }
}

/// Join a manifest file name onto `dir`, refusing anything that is not a
/// single plain path component (defence in depth: the manifest is already
/// validated when decrypted).
pub fn output_path(dir: &Path, name: &str) -> Result<PathBuf> {
    let p = Path::new(name);
    let mut comps = p.components();
    match (comps.next(), comps.next()) {
        (Some(std::path::Component::Normal(c)), None) if c == p.as_os_str() => Ok(dir.join(c)),
        _ => Err(ClientError::Rejected(format!(
            "unsafe file name in manifest: {name:?}"
        ))),
    }
}

pub async fn open(
    cfg: &ClientConfig,
    client: &ManagedClient,
    auth: &dyn Authenticator,
    artifact: &Path,
    output: Output,
    progress: &mut (dyn FnMut(Step) + Send),
) -> Result<OpenOutcome> {
    let registry = Registry::new(cfg, client)?;

    // 1. Local verification against registry-backed sender trust.
    progress(Step::Verifying);
    let (_, header) = svx_core::inspect(BufReader::new(File::open(artifact)?))
        .map_err(|e| ClientError::Rejected(e.to_string()))?;
    let trust = match registry.sender_trust(header.sender_org.as_str()).await {
        Ok(t) => t,
        Err(ClientError::Unavailable(e)) => return Err(ClientError::Unavailable(e)),
        // Unknown sender (no registry record) is a rejection, not an outage.
        Err(_) => {
            return Err(ClientError::Rejected(format!(
                "sender {} is not a verified organization",
                header.sender_org
            )));
        }
    };
    let verified = svx_core::verify(BufReader::new(File::open(artifact)?), &trust)
        .map_err(|e| ClientError::Rejected(e.to_string()))?;
    let h = &verified.header;
    progress(Step::SignatureValid {
        sender: h.sender_org.to_string(),
    });

    // 2. Is this for us, from our service, and still valid?
    if h.recipient_org.as_str() != cfg.org_id {
        return Err(ClientError::NotRecipient {
            recipient: h.recipient_org.to_string(),
            mine: cfg.org_id.clone(),
        });
    }
    if verified.is_expired(crate::now()) {
        return Err(ClientError::Expired);
    }
    progress(Step::Connecting);
    let service = registry.service().await?;
    if h.service_id.as_str() != service.service_id {
        return Err(ClientError::Rejected(format!(
            "artifact is managed by {}, not {}",
            h.service_id, service.service_id
        )));
    }
    let me = registry.org(&cfg.org_id).await?;
    let agent_url = me.key_agent_url.clone().ok_or_else(|| {
        ClientError::Config(format!("{} has no key agent configured", cfg.org_id))
    })?;

    // 3. Authenticate, bound to a fresh ephemeral key and transaction.
    let session = ReleaseSession::new();
    progress(Step::Authenticating);
    let token = auth.id_token(&session.nonce()).await?;

    // 4. Authorization and key release.
    progress(Step::CheckingAuthorization);
    let (svc_share, org_share) = client
        .release(
            &cfg.service_url,
            &agent_url,
            &session,
            verified.head(),
            &token,
        )
        .await?;
    progress(Step::AccessApproved);

    // 5. Decrypt locally.
    progress(Step::Decrypting);
    let input = BufReader::new(File::open(artifact)?);
    let artifact_id = hex::encode(h.artifact_id);
    let sender_org = h.sender_org.to_string();
    match output {
        Output::Writer(mut w) => {
            let manifest = verified
                .decrypt(input, &svc_share, &org_share, &mut w)
                .map_err(|e| ClientError::Rejected(e.to_string()))?;
            w.flush()?;
            Ok(OpenOutcome {
                manifest,
                path: None,
                sender_org,
                artifact_id,
            })
        }
        Output::Dir { dir, overwrite } => {
            if !dir.exists() {
                let mut b = std::fs::DirBuilder::new();
                b.recursive(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    b.mode(0o700);
                }
                b.create(&dir)?;
            }
            let tmp = tempfile::Builder::new()
                .prefix(".svx-partial-")
                .tempfile_in(&dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tmp.as_file()
                    .set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            // On any error `tmp` is dropped, which deletes the partial file.
            let manifest = {
                let mut w = BufWriter::new(tmp.as_file());
                let m = verified
                    .decrypt(input, &svc_share, &org_share, &mut w)
                    .map_err(|e| ClientError::Rejected(e.to_string()))?;
                w.flush()?;
                m
            };
            tmp.as_file().sync_all()?;
            let entry = &manifest.files[0];
            if entry.content_type.as_deref() == Some(folder::FOLDER_CONTENT_TYPE) {
                // A zipped folder: extract it from the private temp file into
                // a new folder. The zip itself is never left on disk.
                let dest = output_path(&dir, folder::folder_name(&entry.name))?;
                if overwrite {
                    return Err(ClientError::Config(format!(
                        "{} is a folder; existing folders are never replaced, choose another directory",
                        entry.name
                    )));
                }
                let len = tmp.as_file().metadata()?.len();
                let mut f = tmp.reopen()?;
                f.seek(std::io::SeekFrom::Start(0))?;
                folder::extract(BufReader::new(f), len, &dest, folder::Limits::default())?;
                return Ok(OpenOutcome {
                    manifest,
                    path: Some(dest),
                    sender_org,
                    artifact_id,
                });
            }
            let dest = output_path(&dir, &entry.name)?;
            if overwrite {
                tmp.persist(&dest).map_err(|e| ClientError::Io(e.error))?;
            } else {
                tmp.persist_noclobber(&dest).map_err(|e| {
                    if e.error.kind() == std::io::ErrorKind::AlreadyExists {
                        ClientError::OutputExists(dest.clone())
                    } else {
                        ClientError::Io(e.error)
                    }
                })?;
            }
            Ok(OpenOutcome {
                manifest,
                path: Some(dest),
                sender_org,
                artifact_id,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_paths() {
        let d = Path::new("/out");
        assert_eq!(
            output_path(d, "evidence.zip").unwrap(),
            Path::new("/out/evidence.zip")
        );
        for bad in ["../x", "/etc/passwd", "a/b", "..", ".", "", "./x"] {
            assert!(output_path(d, bad).is_err(), "{bad:?}");
        }
    }
}
