//! Key management for administrators: the safe order of operations lives
//! here, not in a UI.
//!
//! * A **signing key** for this computer is created in the OS keychain and
//!   registered; if registration fails, the keychain entry is removed again.
//! * A new **encryption key** is written once to files for the key agent,
//!   and only activated in the registry after the key agent reports that it
//!   holds it, so senders never seal files the agent can't open. Older
//!   active encryption keys are then retired (they keep opening older files).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use svx_core::crypto::{KemSecretKey, KeyKind, os_rng};
use svx_core::format::Identifier;
use svx_core::keyfile;
use svx_protocol::admin::OrgOverview;
use svx_protocol::{KeyEntry, KeyKindWire, KeyStatus, ManagedClient};

use crate::admin;
use crate::config::ClientConfig;
use crate::error::{ClientError, Result};
use crate::keystore::{self, KeyRef, SecretStore};

/// A signing key created in this computer's keychain and registered.
#[derive(Clone, Debug, Serialize)]
pub struct NewSigningKey {
    /// `keychain:<org>/<key_id>`.
    pub key_ref: String,
    pub key_id: String,
}

pub async fn create_signing_key(
    cfg: &ClientConfig,
    client: &ManagedClient,
    bearer: &str,
    store: &dyn SecretStore,
) -> Result<NewSigningKey> {
    let (r, vk) = keystore::generate_in_keychain(store, &cfg.org_id)?;
    let registered = admin::put_key(
        cfg,
        client,
        bearer,
        KeyKindWire::Ed25519Mldsa65,
        vk.to_vec(),
        KeyStatus::Active,
    )
    .await;
    if let Err(e) = registered {
        // Don't leave an unregistered key behind.
        let _ = keystore::delete(store, &r);
        return Err(e);
    }
    Ok(NewSigningKey {
        key_ref: r.to_string(),
        key_id: hex::encode(vk.key_id()),
    })
}

/// Register another sender's public signing key (`*.sign.pub`) as active.
pub async fn register_signing_public(
    cfg: &ClientConfig,
    client: &ManagedClient,
    bearer: &str,
    path: &Path,
) -> Result<KeyEntry> {
    let (owner, vk) = keyfile::load_verifying_key(path)
        .map_err(|e| ClientError::Config(format!("loading {}: {e}", path.display())))?;
    if owner.as_str() != cfg.org_id {
        return Err(ClientError::Config(format!(
            "{} belongs to {owner}, not {}",
            path.display(),
            cfg.org_id
        )));
    }
    if vk.kind() != KeyKind::HybridSigning {
        return Err(ClientError::Config(
            "only post-quantum hybrid signing keys can be registered for new files".into(),
        ));
    }
    admin::put_key(
        cfg,
        client,
        bearer,
        KeyKindWire::Ed25519Mldsa65,
        vk.to_vec(),
        KeyStatus::Active,
    )
    .await
}

/// A new encryption key, written for the key agent but not yet active.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedKemKey {
    pub key_id: String,
    /// The secret key file to install on the key agent server.
    pub secret_file: PathBuf,
    /// Its public half (used to activate the key).
    pub public_file: PathBuf,
}

/// Generate an X-Wing encryption key into `dir` (owner-only secret file).
/// Nothing is registered yet: see [`activate_encryption_key`].
pub fn export_encryption_key(cfg: &ClientConfig, dir: &Path) -> Result<ExportedKemKey> {
    let owner =
        Identifier::new(&cfg.org_id).map_err(|_| ClientError::Config("invalid org_id".into()))?;
    let sk = KemSecretKey::generate_hybrid(&mut os_rng());
    let key_id = hex::encode(sk.public_key().key_id());
    let name = format!("{}-{}", cfg.org_id, &key_id[..8]);
    let prefix = dir.join(&name);
    keyfile::write_kem_pair(&prefix, &owner, &sk)
        .map_err(|e| ClientError::Other(format!("writing the key files: {e}")))?;
    Ok(ExportedKemKey {
        key_id,
        secret_file: dir.join(format!("{name}.kem.key")),
        public_file: dir.join(format!("{name}.kem.pub")),
    })
}

/// Activate the encryption key in `public_file` once the organization's key
/// agent reports holding it, then retire the previously active encryption
/// keys (they still open older files).
pub async fn activate_encryption_key(
    cfg: &ClientConfig,
    client: &ManagedClient,
    bearer: &str,
    public_file: &Path,
) -> Result<KeyEntry> {
    let (owner, pk) = keyfile::load_kem_public(public_file)
        .map_err(|e| ClientError::Config(format!("loading {}: {e}", public_file.display())))?;
    if owner.as_str() != cfg.org_id {
        return Err(ClientError::Config(format!(
            "{} belongs to {owner}, not {}",
            public_file.display(),
            cfg.org_id
        )));
    }
    if pk.kind() != KeyKind::XWingKem {
        return Err(ClientError::Config(
            "only post-quantum (X-Wing) encryption keys can be activated".into(),
        ));
    }
    let overview = admin::overview(cfg, client, bearer).await?;
    let agent_url = overview.key_agent_url.clone().ok_or_else(|| {
        ClientError::Config("set the key agent URL before activating an encryption key".into())
    })?;
    let held = admin::agent_keys(client, &agent_url).await?;
    if !held.keys.iter().any(|k| k.key_id == pk.key_id()) {
        return Err(ClientError::Config(format!(
            "the key agent doesn't have key {} yet: install {} on the agent server, restart it, \
             then activate again",
            hex::encode(pk.key_id()),
            public_file.with_extension("key").display()
        )));
    }
    let entry = admin::put_key(
        cfg,
        client,
        bearer,
        KeyKindWire::XWing,
        pk.to_vec(),
        KeyStatus::Active,
    )
    .await?;
    for old in active_kem_keys(&overview) {
        if old.0 != pk.key_id() {
            admin::put_key(cfg, client, bearer, old.1, old.2, KeyStatus::Retired).await?;
        }
    }
    Ok(entry)
}

fn active_kem_keys(o: &OrgOverview) -> Vec<([u8; 16], KeyKindWire, Vec<u8>)> {
    o.keys
        .iter()
        .filter(|k| !k.kind.is_signing() && k.status == KeyStatus::Active)
        .map(|k| (k.key_id, k.kind, k.public_key.clone()))
        .collect()
}

/// Retire or revoke a registered key by its hex ID.
pub async fn set_key_status(
    cfg: &ClientConfig,
    client: &ManagedClient,
    bearer: &str,
    key_id: &str,
    status: KeyStatus,
) -> Result<KeyEntry> {
    let overview = admin::overview(cfg, client, bearer).await?;
    let k = overview
        .keys
        .iter()
        .find(|k| hex::encode(k.key_id) == key_id.trim().to_ascii_lowercase())
        .ok_or_else(|| ClientError::Config(format!("no key {key_id} in the registry")))?;
    if status == KeyStatus::Active {
        return Err(ClientError::Config(
            "keys are activated by registering them".into(),
        ));
    }
    admin::put_key(cfg, client, bearer, k.kind, k.public_key.clone(), status).await
}

/// Import a signing key file into the keychain (it must be registered and
/// belong to this organization). The file is left for the user to delete.
pub fn import_signing_key(
    cfg: &ClientConfig,
    store: &dyn SecretStore,
    path: &Path,
) -> Result<NewSigningKey> {
    let (owner, _) = keyfile::load_signing_key(path)
        .map_err(|e| ClientError::Config(format!("loading {}: {e}", path.display())))?;
    if owner.as_str() != cfg.org_id {
        return Err(ClientError::Config(format!(
            "{} belongs to {owner}, not {}",
            path.display(),
            cfg.org_id
        )));
    }
    let (r, vk) = keystore::import_file(store, path)?;
    Ok(NewSigningKey {
        key_ref: r.to_string(),
        key_id: hex::encode(vk.key_id()),
    })
}

/// Whether `r` can be loaded (e.g. a keychain key still present).
pub fn check_signing_key(store: &dyn SecretStore, r: &KeyRef) -> Result<String> {
    let (_, sk) = keystore::load_signing(store, r)?;
    Ok(hex::encode(sk.verifying_key().key_id()))
}
