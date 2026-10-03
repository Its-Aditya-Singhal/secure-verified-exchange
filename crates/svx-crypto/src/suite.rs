//! Cipher suites.
//!
//! | `suite_id` | Name | Envelopes and key release | Signature (`sig_alg`) |
//! |-----------|------|---------------------------|-----------------------|
//! | `0x0001` | SVX-1 | HPKE DHKEM(X25519) | Ed25519 (`0x0001`) |
//! | `0x0003` | SVX-1H (post-quantum hybrid) | HPKE X-Wing (X25519 + ML-KEM-768) | Ed25519 + ML-DSA-65 (`0x0002`) |
//!
//! Both use ChaCha20-Poly1305, HKDF-SHA256 and SHA-256. A reader accepts
//! exactly these; there is no negotiation. Every domain-separation label of
//! SVX-1H starts with `"SVX-1H"`, so nothing produced under one suite can be
//! accepted under the other.

use crate::error::{CryptoError, Result};
use crate::keys::KeyKind;

/// Suite identifier for SVX-1.
pub const SUITE_SVX1: u16 = 0x0001;
/// Suite identifier for SVX-1H (post-quantum hybrid).
pub const SUITE_SVX1H: u16 = 0x0003;
/// Signature algorithm: Ed25519.
pub const SIG_ALG_ED25519: u16 = 0x0001;
/// Signature algorithm: Ed25519 and ML-DSA-65, both required.
pub const SIG_ALG_ED25519_MLDSA65: u16 = 0x0002;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Suite {
    /// X25519 / Ed25519.
    Svx1,
    /// X-Wing / Ed25519 + ML-DSA-65.
    Svx1H,
}

impl Suite {
    pub fn from_id(id: u16) -> Result<Self> {
        match id {
            SUITE_SVX1 => Ok(Suite::Svx1),
            SUITE_SVX1H => Ok(Suite::Svx1H),
            other => Err(CryptoError::UnsupportedSuite(other)),
        }
    }

    pub fn id(self) -> u16 {
        match self {
            Suite::Svx1 => SUITE_SVX1,
            Suite::Svx1H => SUITE_SVX1H,
        }
    }

    pub fn sig_alg(self) -> u16 {
        match self {
            Suite::Svx1 => SIG_ALG_ED25519,
            Suite::Svx1H => SIG_ALG_ED25519_MLDSA65,
        }
    }

    /// The KEM kind for this suite's envelopes.
    pub fn kem_kind(self) -> KeyKind {
        match self {
            Suite::Svx1 => KeyKind::X25519Kem,
            Suite::Svx1H => KeyKind::XWingKem,
        }
    }

    /// The signing key kind this suite requires.
    pub fn signing_kind(self) -> KeyKind {
        match self {
            Suite::Svx1 => KeyKind::Ed25519Signing,
            Suite::Svx1H => KeyKind::HybridSigning,
        }
    }

    /// Length of an envelope's encapsulated key.
    pub fn enc_len(self) -> usize {
        match self {
            Suite::Svx1 => crate::keys::X25519_PUBLIC_LEN,
            Suite::Svx1H => crate::keys::XWING_ENC_LEN,
        }
    }

    pub fn is_post_quantum(self) -> bool {
        self == Suite::Svx1H
    }

    /// A short human-readable description.
    pub fn description(self) -> &'static str {
        match self {
            Suite::Svx1 => "classical (X25519, Ed25519)",
            Suite::Svx1H => "post-quantum hybrid (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65)",
        }
    }

    /// `"<SVX-1|SVX-1H> <what>\0"`
    pub(crate) fn label(self, what: &str) -> Vec<u8> {
        let mut v = Vec::with_capacity(8 + what.len());
        v.extend_from_slice(match self {
            Suite::Svx1 => b"SVX-1 ",
            Suite::Svx1H => b"SVX-1H ",
        });
        v.extend_from_slice(what.as_bytes());
        v.push(0);
        v
    }
}

/// The suite whose key-release KEM matches `kind` (X25519 → SVX-1, X-Wing → SVX-1H).
pub(crate) fn suite_of_kem(kind: KeyKind) -> Result<Suite> {
    match kind {
        KeyKind::X25519Kem => Ok(Suite::Svx1),
        KeyKind::XWingKem => Ok(Suite::Svx1H),
        _ => Err(CryptoError::InvalidKey),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_disjoint() {
        assert_eq!(Suite::Svx1.label("envelope"), b"SVX-1 envelope\0");
        assert_eq!(Suite::Svx1H.label("envelope"), b"SVX-1H envelope\0");
        assert!(Suite::from_id(0x0002).is_err());
        assert!(Suite::from_id(0x0000).is_err());
        for s in [Suite::Svx1, Suite::Svx1H] {
            assert_eq!(Suite::from_id(s.id()).unwrap(), s);
        }
    }
}
