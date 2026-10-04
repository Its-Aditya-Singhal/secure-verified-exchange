//! Hashes, signature transcript and manifest sealing.
//!
//! ```text
//! header_hash        = H("SVX-1 header\0"  ‖ prelude ‖ header)
//! payload_commitment = H("SVX-1 payload\0" ‖ header_hash ‖ Σ (flag ‖ LE32(ct_len) ‖ ct_i))
//! message            = "<suite> signature\0" ‖ header_hash ‖ LE64(chunk_count) ‖ payload_commitment
//! signature          = Ed25519(message)                                    (SVX-1)
//!                    | Ed25519(message) ‖ ML-DSA-65(message)               (SVX-1H, both required)
//!                    | Ed25519 ‖ ML-DSA-87 ‖ SLH-DSA-SHA2-256s (message)   (SVX-2, all required)
//! ```
//!
//! `H` is SHA-256 in suites SVX-1 and SVX-1H and SHA-512 in SVX-2 (the
//! suite is in the prelude, so it is fixed before anything is hashed).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use sha2::{Digest, Sha256, Sha512};
use svx_format::ChunkInfo;

use crate::error::{CryptoError, Result};
use crate::keys::{SigSet, SigningKey, VerifyingKey};
use crate::schedule::ArtifactKeys;
use crate::suite::Suite;

/// The domain-separated hash of the prelude and header bytes: 32 bytes
/// (SHA-256) or 64 bytes (SHA-512, suite SVX-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeaderHash {
    bytes: [u8; 64],
    len: usize,
}

impl HeaderHash {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// The suite's hash function, domain separated by a label.
#[derive(Clone)]
enum Hasher {
    Sha256(Sha256),
    Sha512(Sha512),
}

impl Hasher {
    fn new(suite: Suite, label: &[u8]) -> Self {
        let mut h = if suite.wide_hash() {
            Hasher::Sha512(Sha512::new())
        } else {
            Hasher::Sha256(Sha256::new())
        };
        h.update(label);
        h
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            Hasher::Sha256(h) => h.finalize().to_vec(),
            Hasher::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

/// Hash the exact on-the-wire prelude ‖ header region with `suite`'s hash.
pub fn header_hash(suite: Suite, header_region: &[u8]) -> HeaderHash {
    let mut h = Hasher::new(suite, b"SVX-1 header\0");
    h.update(header_region);
    let d = h.finalize();
    let mut bytes = [0u8; 64];
    bytes[..d.len()].copy_from_slice(&d);
    HeaderHash {
        bytes,
        len: d.len(),
    }
}

/// Length of `suite`'s header hash and payload commitment.
pub fn commitment_len(suite: Suite) -> usize {
    if suite.wide_hash() { 64 } else { 32 }
}

/// Incrementally computes the payload commitment over chunk records.
pub struct PayloadHasher {
    h: Hasher,
    count: u64,
}

impl PayloadHasher {
    pub fn new(suite: Suite, header_hash: &HeaderHash) -> Self {
        let mut h = Hasher::new(suite, b"SVX-1 payload\0");
        h.update(header_hash.as_bytes());
        Self { h, count: 0 }
    }

    pub fn update(&mut self, info: &ChunkInfo, ciphertext: &[u8]) {
        self.h.update(&info.record_prefix());
        self.h.update(ciphertext);
        self.count += 1;
    }

    /// Returns `(chunk_count, commitment)`; the commitment is
    /// [`commitment_len`] bytes.
    pub fn finalize(self) -> (u64, Vec<u8>) {
        (self.count, self.h.finalize())
    }
}

/// The exact message the sender signs.
pub fn signature_message(
    suite: Suite,
    header_hash: &HeaderHash,
    chunk_count: u64,
    commitment: &[u8],
) -> Vec<u8> {
    let mut m = suite.label("signature");
    m.extend_from_slice(header_hash.as_bytes());
    m.extend_from_slice(&chunk_count.to_le_bytes());
    m.extend_from_slice(commitment);
    m
}

/// Sign the transcript with a key of the suite's signing kind. Returns
/// `(sig_alg, signature)`. `rng` hedges ML-DSA and SLH-DSA.
pub fn sign_transcript(
    suite: Suite,
    key: &SigningKey,
    header_hash: &HeaderHash,
    chunk_count: u64,
    commitment: &[u8],
    rng: &mut impl rand_core::CryptoRng,
) -> Result<(u16, Vec<u8>)> {
    if key.kind() != suite.signing_kind()
        || header_hash.as_bytes().len() != commitment_len(suite)
        || commitment.len() != commitment_len(suite)
    {
        return Err(CryptoError::InvalidKey);
    }
    let msg = signature_message(suite, header_hash, chunk_count, commitment);
    Ok((suite.sig_alg(), key.sign_raw(&msg, SigSet::Full, rng)?))
}

/// Verify the transcript signature: strict Ed25519 (SVX-1); Ed25519 **and**
/// ML-DSA-65 (SVX-1H); Ed25519 **and** ML-DSA-87 **and** SLH-DSA (SVX-2).
/// The key kind, `sig_alg` and hash lengths must all match the suite.
pub fn verify_transcript(
    suite: Suite,
    key: &VerifyingKey,
    header_hash: &HeaderHash,
    chunk_count: u64,
    commitment: &[u8],
    sig_alg: u16,
    signature: &[u8],
) -> Result<()> {
    if sig_alg != suite.sig_alg() {
        return Err(CryptoError::UnsupportedSignatureAlgorithm(sig_alg));
    }
    if key.kind() != suite.signing_kind()
        || header_hash.as_bytes().len() != commitment_len(suite)
        || commitment.len() != commitment_len(suite)
    {
        return Err(CryptoError::BadSignature);
    }
    key.verify_raw(
        &signature_message(suite, header_hash, chunk_count, commitment),
        signature,
        SigSet::Full,
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
