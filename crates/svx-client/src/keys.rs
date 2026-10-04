//! Key generation into SVX key files (`<prefix>.sign.key/.pub`,
//! `<prefix>.kem.key/.pub`). Secret files are written owner-only. New keys
//! are always suite SVX-2 keys; older (hybrid and classical) keys are only
//! kept to open older files.

use std::path::Path;

use svx_core::crypto::{KemSecretKey, SigningKey, os_rng};
use svx_core::format::Identifier;
use svx_core::keyfile;

use crate::error::{ClientError, Result};

fn owner_id(owner: &str) -> Result<Identifier> {
    Identifier::new(owner).map_err(|_| ClientError::Config(format!("invalid owner {owner:?}")))
}

/// Generate an SVX-2 signing key pair (Ed25519 + ML-DSA-87 +
/// SLH-DSA-SHA2-256s); returns the hex key ID. Used for artifacts and for the managed service's
/// own grant and registry keys.
pub fn generate_signing(prefix: &Path, owner: &str) -> Result<String> {
    let owner = owner_id(owner)?;
    let sk = SigningKey::generate_max(&mut os_rng());
    keyfile::write_signing_pair(prefix, &owner, &sk)
        .map_err(|e| ClientError::Other(e.to_string()))?;
    Ok(hex::encode(sk.verifying_key().key_id()))
}

/// Generate an SVX-2 KEM key pair (MLKEM1024-P384: ML-KEM-1024 + P-384,
/// used with HPKE); returns the hex key ID.
pub fn generate_kem(prefix: &Path, owner: &str) -> Result<String> {
    let owner = owner_id(owner)?;
    let sk = KemSecretKey::generate_max(&mut os_rng());
    keyfile::write_kem_pair(prefix, &owner, &sk).map_err(|e| ClientError::Other(e.to_string()))?;
    Ok(hex::encode(sk.public_key().key_id()))
}
