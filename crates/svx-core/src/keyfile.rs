//! Local key files (Phase 1 tooling and tests).
//!
//! ```json
//! {"svx_key":1,"type":"ed25519-public","owner":"acme-security","key_id":"…","key":"…"}
//! ```
//!
//! Types: `ed25519-secret`, `ed25519-public`, `x25519-secret`, `x25519-public`.
//! Secret files are created with mode 0600 on Unix. In production, long-term
//! secret keys belong in a KMS/HSM rather than files (`docs/key-hierarchy.md`).

use std::fs;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use svx_crypto::{KemPublicKey, KemSecretKey, SigningKey, VerifyingKey};
use svx_format::Identifier;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    #[serde(rename = "ed25519-secret")]
    Ed25519Secret,
    #[serde(rename = "ed25519-public")]
    Ed25519Public,
    #[serde(rename = "x25519-secret")]
    X25519Secret,
    #[serde(rename = "x25519-public")]
    X25519Public,
}

impl KeyType {
    fn is_secret(self) -> bool {
        matches!(self, KeyType::Ed25519Secret | KeyType::X25519Secret)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    svx_key: u32,
    #[serde(rename = "type")]
    key_type: KeyType,
    owner: String,
    key_id: String,
    key: String,
}

impl Drop for KeyFile {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}

const MAX_KEYFILE_LEN: u64 = 4096;

fn read(path: &Path, expected: KeyType) -> Result<(Identifier, Zeroizing<[u8; 32]>, String)> {
    let meta = fs::metadata(path)?;
    if meta.len() > MAX_KEYFILE_LEN {
        return Err(CoreError::KeyFile("file too large".into()));
    }
    let text = Zeroizing::new(fs::read_to_string(path)?);
    let kf: KeyFile = serde_json::from_str(&text).map_err(|e| CoreError::KeyFile(e.to_string()))?;
    if kf.svx_key != 1 {
        return Err(CoreError::KeyFile(format!(
            "unsupported key file version {}",
            kf.svx_key
        )));
    }
    if kf.key_type != expected {
        return Err(CoreError::KeyFile(format!(
            "expected {expected:?} key, found {:?}",
            kf.key_type
        )));
    }
    let owner =
        Identifier::new(&kf.owner).map_err(|_| CoreError::KeyFile("invalid owner".into()))?;
    let mut key = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(&kf.key, key.as_mut())
        .map_err(|_| CoreError::KeyFile("invalid key encoding".into()))?;
    Ok((owner, key, kf.key_id.clone()))
}

fn check_id(stated: &str, actual: &[u8; 16]) -> Result<()> {
    if stated != hex::encode(actual) {
        return Err(CoreError::KeyFile("key_id does not match key".into()));
    }
    Ok(())
}

fn write(
    path: &Path,
    key_type: KeyType,
    owner: &Identifier,
    key_id: &[u8; 16],
    key: &[u8; 32],
) -> Result<()> {
    let kf = KeyFile {
        svx_key: 1,
        key_type,
        owner: owner.to_string(),
        key_id: hex::encode(key_id),
        key: hex::encode(key),
    };
    let text = Zeroizing::new(
        serde_json::to_string_pretty(&kf).map_err(|e| CoreError::KeyFile(e.to_string()))?,
    );
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    if key_type.is_secret() {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(text.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    Ok(())
}

pub fn load_signing_key(path: &Path) -> Result<(Identifier, SigningKey)> {
    let (owner, key, id) = read(path, KeyType::Ed25519Secret)?;
    let sk = SigningKey::from_bytes(&key);
    check_id(&id, &sk.verifying_key().key_id())?;
    Ok((owner, sk))
}

pub fn load_verifying_key(path: &Path) -> Result<(Identifier, VerifyingKey)> {
    let (owner, key, id) = read(path, KeyType::Ed25519Public)?;
    let vk = VerifyingKey::from_bytes(&key)?;
    check_id(&id, &vk.key_id())?;
    Ok((owner, vk))
}

pub fn load_kem_secret(path: &Path) -> Result<(Identifier, KemSecretKey)> {
    let (owner, key, id) = read(path, KeyType::X25519Secret)?;
    let sk = KemSecretKey::from_bytes(&key)?;
    check_id(&id, &sk.public_key().key_id())?;
    Ok((owner, sk))
}

pub fn load_kem_public(path: &Path) -> Result<(Identifier, KemPublicKey)> {
    let (owner, key, id) = read(path, KeyType::X25519Public)?;
    let pk = KemPublicKey::from_bytes(&key)?;
    check_id(&id, &pk.key_id())?;
    Ok((owner, pk))
}

/// Write a signing key pair to `<prefix>.sign.key` (secret) and `<prefix>.sign.pub`.
pub fn write_signing_pair(prefix: &Path, owner: &Identifier, sk: &SigningKey) -> Result<()> {
    let vk = sk.verifying_key();
    write(
        &with_suffix(prefix, "sign.key"),
        KeyType::Ed25519Secret,
        owner,
        &vk.key_id(),
        &sk.to_bytes(),
    )?;
    write(
        &with_suffix(prefix, "sign.pub"),
        KeyType::Ed25519Public,
        owner,
        &vk.key_id(),
        &vk.to_bytes(),
    )
}

/// Write a KEM key pair to `<prefix>.kem.key` (secret) and `<prefix>.kem.pub`.
pub fn write_kem_pair(prefix: &Path, owner: &Identifier, sk: &KemSecretKey) -> Result<()> {
    let pk = sk.public_key();
    write(
        &with_suffix(prefix, "kem.key"),
        KeyType::X25519Secret,
        owner,
        &pk.key_id(),
        &sk.to_bytes(),
    )?;
    write(
        &with_suffix(prefix, "kem.pub"),
        KeyType::X25519Public,
        owner,
        &pk.key_id(),
        &pk.to_bytes(),
    )
}

fn with_suffix(prefix: &Path, suffix: &str) -> std::path::PathBuf {
    let mut s = prefix.as_os_str().to_owned();
    s.push(".");
    s.push(suffix);
    s.into()
}
