//! The SVX-1 cryptographic profile (see `spec/crypto-profile.md`).
//!
//! This crate composes well-reviewed primitives; it implements none itself:
//!
//! | Purpose            | Primitive                                              |
//! |--------------------|--------------------------------------------------------|
//! | Payload / manifest | ChaCha20-Poly1305 (RFC 8439) in the STREAM construction |
//! | Key envelopes      | HPKE base mode (RFC 9180): DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 |
//! | Key schedule       | HKDF-SHA256 (RFC 5869)                                 |
//! | Signatures         | Ed25519 (RFC 8032), strict verification                |
//! | Hashing            | SHA-256                                                |
//!
//! There is exactly one suite in SVX 1.0. A container naming any other suite
//! is rejected; there is no negotiation and therefore no downgrade path.
//!
//! The public API exposes purpose-built operations (seal a share, encrypt a
//! chunk, sign a transcript) rather than raw primitives, and every secret
//! type zeroizes on drop and has a redacted `Debug`.

#![forbid(unsafe_code)]

mod envelope;
mod error;
mod keys;
mod schedule;
mod stream;
mod transcript;

pub use envelope::{EnvelopeContext, open_share, seal_share};
pub use error::{CryptoError, Result};
pub use keys::{KemPublicKey, KemSecretKey, KeyKind, SigningKey, VerifyingKey, key_id};
pub use schedule::{ArtifactKeys, Share};
pub use stream::{StreamDecryptor, StreamEncryptor};
pub use transcript::{
    HeaderHash, PayloadHasher, header_hash, open_manifest, seal_manifest, sign_transcript,
    signature_message, verify_transcript,
};

/// Re-exported so callers can supply their own RNG (e.g. seeded for test vectors).
pub use rand_core::CryptoRng;

/// Suite identifier for SVX-1: ChaCha20-Poly1305 / HPKE-X25519 / Ed25519 / SHA-256.
pub const SUITE_SVX1: u16 = 0x0001;
/// Signature algorithm identifier for Ed25519.
pub const SIG_ALG_ED25519: u16 = 0x0001;
/// Length of a key share.
pub const SHARE_LEN: usize = 32;
/// Length of a sealed share (share + AEAD tag).
pub const SEALED_SHARE_LEN: usize = SHARE_LEN + 16;

/// Reject any suite other than the one this implementation supports.
pub fn check_suite(suite_id: u16) -> Result<()> {
    if suite_id == SUITE_SVX1 {
        Ok(())
    } else {
        Err(CryptoError::UnsupportedSuite(suite_id))
    }
}

/// The operating-system CSPRNG.
pub fn os_rng() -> impl CryptoRng {
    rand_core::UnwrapErr(getrandom::SysRng)
}
