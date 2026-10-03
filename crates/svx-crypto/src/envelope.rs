//! HPKE key envelopes.
//!
//! Each share is sealed with RFC 9180 single-shot HPKE (base mode) to one
//! party's KEM key: X25519 in suite SVX-1, X-Wing (X25519 + ML-KEM-768) in
//! suite SVX-1H. The HPKE `info` string binds the envelope to the suite, the
//! artifact, both organizations, the sender's signing key, the service and
//! the envelope's role, so an envelope lifted into a different artifact, or
//! presented for a different role or suite, fails to open.

use svx_format::{EnvelopeRole, Identifier};

use crate::SEALED_SHARE_LEN;
use crate::error::{CryptoError, Result};
use crate::keys::{KemPublicKey, KemSecretKey, hpke_ops};
use crate::schedule::Share;
use crate::suite::Suite;

/// Header fields every envelope is bound to.
#[derive(Clone, Debug)]
pub struct EnvelopeContext<'a> {
    pub artifact_id: &'a [u8; 16],
    pub sender_org: &'a Identifier,
    pub sender_key_id: &'a [u8; 16],
    pub recipient_org: &'a Identifier,
    pub service_id: &'a Identifier,
}

impl EnvelopeContext<'_> {
    /// `"<suite> envelope\0" ‖ role ‖ artifact_id ‖ sender_key_id ‖ key_id
    ///  ‖ lp(sender_org) ‖ lp(recipient_org) ‖ lp(service_id)`
    /// where `lp(x) = u8(len(x)) ‖ x`.
    fn info(&self, suite: Suite, role: EnvelopeRole, key_id: &[u8; 16]) -> Vec<u8> {
        let mut v = suite.label("envelope");
        v.push(role.to_byte());
        v.extend_from_slice(self.artifact_id);
        v.extend_from_slice(self.sender_key_id);
        v.extend_from_slice(key_id);
        for id in [self.sender_org, self.recipient_org, self.service_id] {
            // Identifiers are at most 128 bytes, so the length fits in a u8.
            v.push(id.as_str().len() as u8);
            v.extend_from_slice(id.as_str().as_bytes());
        }
        v
    }
}

/// Seal `share` to `recipient`, whose key kind must match `suite`.
/// Returns `(encapsulated_key, ciphertext)`.
pub fn seal_share(
    suite: Suite,
    role: EnvelopeRole,
    recipient: &KemPublicKey,
    ctx: &EnvelopeContext<'_>,
    share: &Share,
    rng: &mut impl rand_core::CryptoRng,
) -> Result<(Vec<u8>, Vec<u8>)> {
    if recipient.kind() != suite.kem_kind() {
        return Err(CryptoError::InvalidKey);
    }
    let info = ctx.info(suite, role, &recipient.key_id());
    hpke_ops::seal(recipient, &info, share.as_bytes(), rng)
}

/// Open an envelope with the holder's secret key.
pub fn open_share(
    suite: Suite,
    role: EnvelopeRole,
    secret: &KemSecretKey,
    ctx: &EnvelopeContext<'_>,
    encapped_key: &[u8],
    ciphertext: &[u8],
) -> Result<Share> {
    if secret.kind() != suite.kem_kind()
        || encapped_key.len() != suite.enc_len()
        || ciphertext.len() != SEALED_SHARE_LEN
    {
        return Err(CryptoError::EnvelopeOpen);
    }
    let info = ctx.info(suite, role, &secret.public_key().key_id());
    let pt = hpke_ops::open(secret, encapped_key, &info, ciphertext)?;
    let arr: [u8; 32] = pt
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::EnvelopeOpen)?;
    Ok(Share::from_bytes(arr))
}
