//! Local key files (Phase 1 tooling and tests).
//!
//! ```json
//! {"svx_key":1,"type":"ed25519-public","owner":"acme-security","key_id":"…","key":"…"}
//! ```
//!
//! Types:
//!
//! | Type | Key |
//! |------|-----|
//! | `ed25519-secret` / `ed25519-public` | Ed25519 signing key (suite SVX-1) |
//! | `ed25519-mldsa65-secret` / `ed25519-mldsa65-public` | hybrid Ed25519 + ML-DSA-65 signing key (suite SVX-1H) |
//! | `x25519-secret` / `x25519-public` | X25519 KEM key (suite SVX-1) |
//! | `xwing-secret` / `xwing-public` | X-Wing (X25519 + ML-KEM-768) KEM key (suite SVX-1H) |
//!
//! Secret files are created with mode 0600 on Unix. In production, long-term
//! secret keys belong in a KMS/HSM rather than files (`docs/key-hierarchy.md`).

use std::fs;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use svx_crypto::{KemPublicKey, KemSecretKey, KeyKind, SigningKey, VerifyingKey};
use svx_format::Identifier;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    #[serde(rename = "ed25519-secret")]
    Ed25519Secret,
    #[serde(rename = "ed25519-public")]
    Ed25519Public,
    #[serde(rename = "ed25519-mldsa65-secret")]
    HybridSigningSecret,
    #[serde(rename = "ed25519-mldsa65-public")]
    HybridSigningPublic,
    #[serde(rename = "x25519-secret")]
    X25519Secret,
    #[serde(rename = "x25519-public")]
    X25519Public,
    #[serde(rename = "xwing-secret")]
    XWingSecret,
    #[serde(rename = "xwing-public")]
    XWingPublic,
}

impl KeyType {
    #[cfg_attr(not(unix), allow(dead_code))]
    fn is_secret(self) -> bool {
        matches!(
            self,
            KeyType::Ed25519Secret
                | KeyType::HybridSigningSecret
                | KeyType::X25519Secret
                | KeyType::XWingSecret
        )
    }

    fn kind(self) -> KeyKind {
        match self {
            KeyType::Ed25519Secret | KeyType::Ed25519Public => KeyKind::Ed25519Signing,
            KeyType::HybridSigningSecret | KeyType::HybridSigningPublic => KeyKind::HybridSigning,
            KeyType::X25519Secret | KeyType::X25519Public => KeyKind::X25519Kem,
            KeyType::XWingSecret | KeyType::XWingPublic => KeyKind::XWingKem,
        }
    }

    fn of(kind: KeyKind, secret: bool) -> KeyType {
        match (kind, secret) {
            (KeyKind::Ed25519Signing, true) => KeyType::Ed25519Secret,
            (KeyKind::Ed25519Signing, false) => KeyType::Ed25519Public,
            (KeyKind::HybridSigning, true) => KeyType::HybridSigningSecret,
            (KeyKind::HybridSigning, false) => KeyType::HybridSigningPublic,
            (KeyKind::X25519Kem, true) => KeyType::X25519Secret,
            (KeyKind::X25519Kem, false) => KeyType::X25519Public,
            (KeyKind::XWingKem, true) => KeyType::XWingSecret,
            (KeyKind::XWingKem, false) => KeyType::XWingPublic,
        }
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

/// Large enough for a hybrid public key (1984 bytes, hex encoded).
const MAX_KEYFILE_LEN: u64 = 8192;

struct Loaded {
    owner: Identifier,
    key_type: KeyType,
    key: Zeroizing<Vec<u8>>,
    key_id: String,
}

fn read(path: &Path, accepted: &[KeyType]) -> Result<Loaded> {
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
    if !accepted.contains(&kf.key_type) {
        return Err(CoreError::KeyFile(format!(
            "expected one of {accepted:?}, found {:?}",
            kf.key_type
        )));
    }
    let owner =
        Identifier::new(&kf.owner).map_err(|_| CoreError::KeyFile("invalid owner".into()))?;
    let key = Zeroizing::new(
        hex::decode(&kf.key).map_err(|_| CoreError::KeyFile("invalid key encoding".into()))?,
    );
    Ok(Loaded {
        owner,
        key_type: kf.key_type,
        key,
        key_id: kf.key_id.clone(),
    })
}

fn check_id(stated: &str, actual: &[u8; 16]) -> Result<()> {
    if stated != hex::encode(actual) {
        return Err(CoreError::KeyFile("key_id does not match key".into()));
    }
    Ok(())
}

fn bad_key() -> CoreError {
    CoreError::KeyFile("invalid key".into())
}

fn write(
    path: &Path,
    key_type: KeyType,
    owner: &Identifier,
    key_id: &[u8; 16],
    key: &[u8],
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

/// Load a signing key (Ed25519 or hybrid Ed25519 + ML-DSA-65).
pub fn load_signing_key(path: &Path) -> Result<(Identifier, SigningKey)> {
    let l = read(
        path,
        &[KeyType::Ed25519Secret, KeyType::HybridSigningSecret],
    )?;
    let sk = SigningKey::from_secret_bytes(l.key_type.kind(), &l.key).map_err(|_| bad_key())?;
    check_id(&l.key_id, &sk.verifying_key().key_id())?;
    Ok((l.owner, sk))
}

/// Load a verification key (Ed25519 or hybrid).
pub fn load_verifying_key(path: &Path) -> Result<(Identifier, VerifyingKey)> {
    let l = read(
        path,
        &[KeyType::Ed25519Public, KeyType::HybridSigningPublic],
    )?;
    let vk = VerifyingKey::from_kind_bytes(l.key_type.kind(), &l.key)?;
    check_id(&l.key_id, &vk.key_id())?;
    Ok((l.owner, vk))
}

/// Load a KEM secret key (X25519 or X-Wing).
pub fn load_kem_secret(path: &Path) -> Result<(Identifier, KemSecretKey)> {
    let l = read(path, &[KeyType::X25519Secret, KeyType::XWingSecret])?;
    let bytes: &[u8; 32] = l.key.as_slice().try_into().map_err(|_| bad_key())?;
    let sk = KemSecretKey::from_kind_bytes(l.key_type.kind(), bytes)?;
    check_id(&l.key_id, &sk.public_key().key_id())?;
    Ok((l.owner, sk))
}

/// Load a KEM public key (X25519 or X-Wing).
pub fn load_kem_public(path: &Path) -> Result<(Identifier, KemPublicKey)> {
    let l = read(path, &[KeyType::X25519Public, KeyType::XWingPublic])?;
    let pk = KemPublicKey::from_kind_bytes(l.key_type.kind(), &l.key)?;
    check_id(&l.key_id, &pk.key_id())?;
    Ok((l.owner, pk))
}

/// Write a signing key pair to `<prefix>.sign.key` (secret) and `<prefix>.sign.pub`.
pub fn write_signing_pair(prefix: &Path, owner: &Identifier, sk: &SigningKey) -> Result<()> {
    let vk = sk.verifying_key();
    write(
        &with_suffix(prefix, "sign.key"),
        KeyType::of(sk.kind(), true),
        owner,
        &vk.key_id(),
        &sk.to_secret_bytes(),
    )?;
    write(
        &with_suffix(prefix, "sign.pub"),
        KeyType::of(vk.kind(), false),
        owner,
        &vk.key_id(),
        &vk.to_vec(),
    )
}

/// Write a KEM key pair to `<prefix>.kem.key` (secret) and `<prefix>.kem.pub`.
pub fn write_kem_pair(prefix: &Path, owner: &Identifier, sk: &KemSecretKey) -> Result<()> {
    let pk = sk.public_key();
    write(
        &with_suffix(prefix, "kem.key"),
        KeyType::of(sk.kind(), true),
        owner,
        &pk.key_id(),
        sk.to_bytes().as_ref(),
    )?;
    write(
        &with_suffix(prefix, "kem.pub"),
        KeyType::of(pk.kind(), false),
        owner,
        &pk.key_id(),
        &pk.to_vec(),
    )
}

fn with_suffix(prefix: &Path, suffix: &str) -> std::path::PathBuf {
    let mut s = prefix.as_os_str().to_owned();
    s.push(".");
    s.push(suffix);
    s.into()
}
