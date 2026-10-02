//! HPKE key envelopes.
//!
//! Each share is sealed with RFC 9180 single-shot HPKE (base mode) to one
//! party's X25519 key. The HPKE `info` string binds the envelope to the
//! artifact, both organizations, the sender's signing key, the service and
//! the envelope's role, so an envelope lifted into a different artifact, or
//! presented for a different role, fails to open.

use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use svx_format::{EnvelopeRole, Identifier};

use crate::SEALED_SHARE_LEN;
use crate::error::{CryptoError, Result};
use crate::keys::{HpkeKem, KemPublicKey, KemSecretKey};
use crate::schedule::Share;

type HpkeAead = hpke::aead::ChaCha20Poly1305;
type HpkeKdf = hpke::kdf::HkdfSha256;

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
    /// `"SVX-1 envelope\0" ‖ role ‖ artifact_id ‖ sender_key_id ‖ key_id
    ///  ‖ lp(sender_org) ‖ lp(recipient_org) ‖ lp(service_id)`
    /// where `lp(x) = u8(len(x)) ‖ x`.
    fn info(&self, role: EnvelopeRole, key_id: &[u8; 16]) -> Vec<u8> {
        let mut v = Vec::with_capacity(512);
        v.extend_from_slice(b"SVX-1 envelope\0");
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

/// Seal `share` to `recipient`. Returns `(encapsulated_key, ciphertext)`.
pub fn seal_share(
    role: EnvelopeRole,
    recipient: &KemPublicKey,
    ctx: &EnvelopeContext<'_>,
    share: &Share,
    rng: &mut impl rand_core::CryptoRng,
) -> Result<([u8; 32], Vec<u8>)> {
    let info = ctx.info(role, &recipient.key_id());
    let (enc, ct) = hpke::single_shot_seal_with_rng::<HpkeAead, HpkeKdf, HpkeKem>(
        &OpModeS::Base,
        recipient.inner(),
        &info,
        share.as_bytes(),
        b"",
        rng,
    )
    .map_err(|_| CryptoError::Encryption)?;
    let mut enc_bytes = [0u8; 32];
    enc_bytes.copy_from_slice(&enc.to_bytes());
    Ok((enc_bytes, ct))
}

/// Open an envelope with the holder's secret key.
pub fn open_share(
    role: EnvelopeRole,
    secret: &KemSecretKey,
    ctx: &EnvelopeContext<'_>,
    encapped_key: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Share> {
    if ciphertext.len() != SEALED_SHARE_LEN {
        return Err(CryptoError::EnvelopeOpen);
    }
    let info = ctx.info(role, &secret.public_key().key_id());
    let enc = <HpkeKem as hpke::Kem>::EncappedKey::from_bytes(encapped_key)
        .map_err(|_| CryptoError::EnvelopeOpen)?;
    let pt = zeroize::Zeroizing::new(
        hpke::single_shot_open::<HpkeAead, HpkeKdf, HpkeKem>(
            &OpModeR::Base,
            secret.inner(),
            &enc,
            &info,
            ciphertext,
            b"",
        )
        .map_err(|_| CryptoError::EnvelopeOpen)?,
    );
    let arr: [u8; 32] = pt
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::EnvelopeOpen)?;
    Ok(Share::from_bytes(arr))
}
