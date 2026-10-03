//! Key generation into SVX key files (`<prefix>.sign.key/.pub`,
//! `<prefix>.kem.key/.pub`). Secret files are written owner-only. New keys
//! are always post-quantum hybrids (suite SVX-1H); classical keys are only
//! kept to open older files.

use std::path::Path;

use svx_core::crypto::{KemSecretKey, SigningKey, os_rng};
use svx_core::format::Identifier;
use svx_core::keyfile;

use crate::error::{ClientError, Result};

fn owner_id(owner: &str) -> Result<Identifier> {
    Identifier::new(owner).map_err(|_| ClientError::Config(format!("invalid owner {owner:?}")))
}

/// Generate a post-quantum hybrid signing key pair (Ed25519 + ML-DSA-65);
/// returns the hex key ID. Used for artifacts and for the managed service's
/// own grant and registry keys.
pub fn generate_signing(prefix: &Path, owner: &str) -> Result<String> {
    let owner = owner_id(owner)?;
    let sk = SigningKey::generate_hybrid(&mut os_rng());
    keyfile::write_signing_pair(prefix, &owner, &sk)
        .map_err(|e| ClientError::Other(e.to_string()))?;
    Ok(hex::encode(sk.verifying_key().key_id()))
}

/// Generate a post-quantum hybrid KEM key pair (X-Wing: X25519 +
/// ML-KEM-768, used with HPKE); returns the hex key ID.
pub fn generate_kem(prefix: &Path, owner: &str) -> Result<String> {
    let owner = owner_id(owner)?;
    let sk = KemSecretKey::generate_hybrid(&mut os_rng());
    keyfile::write_kem_pair(prefix, &owner, &sk).map_err(|e| ClientError::Other(e.to_string()))?;
    Ok(hex::encode(sk.public_key().key_id()))
}
