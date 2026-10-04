//! The SVX-1 cryptographic profile (see `spec/crypto-profile.md`).
//!
//! This crate composes well-reviewed primitives; it implements none itself:
//!
//! | Purpose            | Primitive                                              |
//! |--------------------|--------------------------------------------------------|
//! | Payload / manifest | ChaCha20-Poly1305 (RFC 8439) in the STREAM construction |
//! | Key envelopes      | HPKE base mode (RFC 9180) with ChaCha20-Poly1305; KEM DHKEM(X25519) (SVX-1), X-Wing = X25519 + ML-KEM-768 (SVX-1H), or MLKEM1024-P384 with HKDF-SHA512 (SVX-2) |
//! | Key schedule       | HKDF-SHA256 (RFC 5869); HKDF-SHA512 in SVX-2           |
//! | Signatures         | Ed25519 (RFC 8032), strict verification; SVX-1H adds ML-DSA-65 (FIPS 204); SVX-2 uses Ed25519 + ML-DSA-87 + SLH-DSA-SHA2-256s (FIPS 205), all required |
//! | Hashing            | SHA-256; SHA-512 in SVX-2                              |
//!
//! Three suites exist (see [`Suite`]): SVX-1, the post-quantum hybrid
//! SVX-1H and the maximum-strength SVX-2, which every writer produces. A
//! container naming any other suite is rejected; there is no negotiation,
//! and the suite is bound into every label and the header hash.
//!
//! The public API exposes purpose-built operations (seal a share, encrypt a
//! chunk, sign a transcript) rather than raw primitives, and every secret
//! type zeroizes on drop and has a redacted `Debug`.

#![forbid(unsafe_code)]

mod backup;
mod context;
mod envelope;
mod error;
mod keys;
mod password;
mod release;
mod schedule;
mod stream;
mod suite;
mod transcript;

pub use backup::{BackupParams, open_with_password, seal_with_password};
pub use context::{SignContext, sign_context, verify_context};
pub use envelope::{EnvelopeContext, open_share, seal_share};
pub use error::{CryptoError, Result};
pub use keys::{
    ED25519_SIG_LEN, HYBRID_PUBLIC_LEN, HYBRID_SIG_LEN, KemPublicKey, KemSecretKey, KeyKind,
    MAX_FAST_SIG_LEN, MAX_KEM_ENC_LEN, MAX_KEM_PUBLIC_LEN, MAX_PUBLIC_LEN, MAX_SECRET_LEN,
    MAX_SIG_LEN, MLDSA65_PUBLIC_LEN, MLDSA65_SIG_LEN, MLDSA87_PUBLIC_LEN, MLDSA87_SIG_LEN,
    SLHDSA_PUBLIC_LEN, SLHDSA_SIG_LEN, SigningKey, VerifyingKey, X25519_PUBLIC_LEN, XWING_ENC_LEN,
    XWING_PUBLIC_LEN, key_fingerprint, key_id,
};
pub use password::{
    PASSWORD_HASH_PARAMS, hash_password, hash_password_with, needs_rehash, verify_password,
};
pub use release::{TXN_LEN, nonce_binding, open_released_share, seal_released_share};
pub use schedule::{ArtifactKeys, Share};
pub use stream::{StreamDecryptor, StreamEncryptor};
pub use suite::{
    SIG_ALG_ED25519, SIG_ALG_ED25519_MLDSA65, SIG_ALG_MAX, SUITE_SVX1, SUITE_SVX1H, SUITE_SVX2,
    Suite,
};
pub use transcript::{
    HeaderHash, PayloadHasher, commitment_len, header_hash, open_manifest, seal_manifest,
    sign_transcript, signature_message, verify_transcript,
};

/// Re-exported so callers can supply their own RNG (e.g. seeded for test vectors).
pub use rand_core::CryptoRng;

/// Length of a key share.
pub const SHARE_LEN: usize = 32;
/// Length of a sealed share (share + AEAD tag).
pub const SEALED_SHARE_LEN: usize = SHARE_LEN + 16;

/// Reject any suite other than SVX-1, SVX-1H and SVX-2.
pub fn check_suite(suite_id: u16) -> Result<Suite> {
    Suite::from_id(suite_id)
}

/// The operating-system CSPRNG.
pub fn os_rng() -> impl CryptoRng {
    rand_core::UnwrapErr(getrandom::SysRng)
}

/// `N` bytes from the operating-system CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    use rand_core::Rng;
    let mut out = [0u8; N];
    os_rng().fill_bytes(&mut out);
    out
}
