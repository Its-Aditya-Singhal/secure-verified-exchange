//! Hashes, signature transcript and manifest sealing.
//!
//! ```text
//! header_hash        = SHA-256("SVX-1 header\0"  ‖ prelude ‖ header)
//! payload_commitment = SHA-256("SVX-1 payload\0" ‖ header_hash ‖ Σ (flag ‖ LE32(ct_len) ‖ ct_i))
//! message            = "<suite> signature\0" ‖ header_hash ‖ LE64(chunk_count) ‖ payload_commitment
//! signature          = Ed25519(message)                       (SVX-1)
//!                    | Ed25519(message) ‖ ML-DSA-65(message)  (SVX-1H, both required)
//! ```

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use sha2::{Digest, Sha256};
use svx_format::ChunkInfo;

use crate::error::{CryptoError, Result};
use crate::keys::{SigningKey, VerifyingKey};
use crate::schedule::ArtifactKeys;
use crate::suite::Suite;

/// SHA-256 over the prelude and header bytes, domain separated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderHash([u8; 32]);

impl HeaderHash {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Hash the exact on-the-wire prelude ‖ header region.
pub fn header_hash(header_region: &[u8]) -> HeaderHash {
    let mut h = Sha256::new();
    h.update(b"SVX-1 header\0");
    h.update(header_region);
    HeaderHash(h.finalize().into())
}

/// Incrementally computes the payload commitment over chunk records.
pub struct PayloadHasher {
    h: Sha256,
    count: u64,
}

impl PayloadHasher {
    pub fn new(header_hash: &HeaderHash) -> Self {
        let mut h = Sha256::new();
        h.update(b"SVX-1 payload\0");
        h.update(header_hash.as_bytes());
        Self { h, count: 0 }
    }

    pub fn update(&mut self, info: &ChunkInfo, ciphertext: &[u8]) {
        self.h.update(info.record_prefix());
        self.h.update(ciphertext);
        self.count += 1;
    }

    /// Returns `(chunk_count, commitment)`.
    pub fn finalize(self) -> (u64, [u8; 32]) {
        (self.count, self.h.finalize().into())
    }
}

/// The exact message the sender signs.
pub fn signature_message(
    suite: Suite,
    header_hash: &HeaderHash,
    chunk_count: u64,
    commitment: &[u8; 32],
) -> Vec<u8> {
    let mut m = suite.label("signature");
    m.extend_from_slice(header_hash.as_bytes());
    m.extend_from_slice(&chunk_count.to_le_bytes());
    m.extend_from_slice(commitment);
    m
}

/// Sign the transcript with a key of the suite's signing kind. Returns
/// `(sig_alg, signature)`. `rng` hedges the ML-DSA half (SVX-1H).
pub fn sign_transcript(
    suite: Suite,
    key: &SigningKey,
    header_hash: &HeaderHash,
    chunk_count: u64,
    commitment: &[u8; 32],
    rng: &mut impl rand_core::CryptoRng,
) -> Result<(u16, Vec<u8>)> {
    if key.kind() != suite.signing_kind() {
        return Err(CryptoError::InvalidKey);
    }
    let msg = signature_message(suite, header_hash, chunk_count, commitment);
    Ok((suite.sig_alg(), key.sign_raw(&msg, rng)?))
}

/// Verify the transcript signature: strict Ed25519 (SVX-1), or strict
/// Ed25519 **and** ML-DSA-65 (SVX-1H). The key kind and `sig_alg` must both
/// match the suite.
pub fn verify_transcript(
    suite: Suite,
    key: &VerifyingKey,
    header_hash: &HeaderHash,
    chunk_count: u64,
    commitment: &[u8; 32],
    sig_alg: u16,
    signature: &[u8],
) -> Result<()> {
    if sig_alg != suite.sig_alg() {
        return Err(CryptoError::UnsupportedSignatureAlgorithm(sig_alg));
    }
    if key.kind() != suite.signing_kind() {
        return Err(CryptoError::BadSignature);
    }
    key.verify_raw(
        &signature_message(suite, header_hash, chunk_count, commitment),
        signature,
    )
}

fn manifest_aad(artifact_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = b"SVX-1 manifest\0".to_vec();
    aad.extend_from_slice(artifact_id);
    aad
}

/// Encrypt the manifest. The manifest key is unique per artifact and used
/// exactly once, so a fixed all-zero nonce is safe.
pub fn seal_manifest(
    keys: &ArtifactKeys,
    artifact_id: &[u8; 16],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(&keys.manifest_key).expect("32-byte key");
    cipher
        .encrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: plaintext,
                aad: &manifest_aad(artifact_id),
            },
        )
        .map_err(|_| CryptoError::Encryption)
}

pub fn open_manifest(
    keys: &ArtifactKeys,
    artifact_id: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(&keys.manifest_key).expect("32-byte key");
    cipher
        .decrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: ciphertext,
                aad: &manifest_aad(artifact_id),
            },
        )
        .map_err(|_| CryptoError::Decryption)
}
