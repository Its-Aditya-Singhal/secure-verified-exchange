//! Key generation into SVX key files (`<prefix>.sign.key/.pub`,
//! `<prefix>.kem.key/.pub`). Secret files are written owner-only.

use std::path::Path;

use svx_core::crypto::{KemSecretKey, SigningKey, os_rng};
use svx_core::format::Identifier;
use svx_core::keyfile;

use crate::error::{ClientError, Result};

fn owner_id(owner: &str) -> Result<Identifier> {
    Identifier::new(owner).map_err(|_| ClientError::Config(format!("invalid owner {owner:?}")))
}

/// Generate an Ed25519 signing key pair; returns the hex key ID.
pub fn generate_signing(prefix: &Path, owner: &str) -> Result<String> {
    let owner = owner_id(owner)?;
    let sk = SigningKey::generate(&mut os_rng());
    keyfile::write_signing_pair(prefix, &owner, &sk)
        .map_err(|e| ClientError::Other(e.to_string()))?;
    Ok(hex::encode(sk.verifying_key().key_id()))
}

/// Generate an X25519 (HPKE) key pair; returns the hex key ID.
pub fn generate_kem(prefix: &Path, owner: &str) -> Result<String> {
    let owner = owner_id(owner)?;
    let sk = KemSecretKey::generate(&mut os_rng());
    keyfile::write_kem_pair(prefix, &owner, &sk).map_err(|e| ClientError::Other(e.to_string()))?;
    Ok(hex::encode(sk.public_key().key_id()))
}
