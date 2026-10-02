//! Split-key artifact key schedule.
//!
//! ```text
//! prk            = HKDF-Extract(salt = "SVX-1 artifact\0" ‖ artifact_id,
//!                               ikm  = share_service ‖ share_recipient)
//! payload_key    = HKDF-Expand(prk, "svx/1/payload",    32)
//! manifest_key   = HKDF-Expand(prk, "svx/1/manifest",   32)
//! key_commitment = HKDF-Expand(prk, "svx/1/commitment", 32)
//! ```
//!
//! Both shares are required. Neither the managed service (which can unwrap
//! only `share_service`) nor the recipient organization's key agent (which
//! can unwrap only `share_recipient`) can derive the payload key alone.

use std::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::SHARE_LEN;
use crate::error::{CryptoError, Result};

/// One 32-byte key share. Zeroized on drop; `Debug` is redacted.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Share([u8; SHARE_LEN]);

impl Share {
    pub fn generate(rng: &mut impl rand_core::CryptoRng) -> Self {
        let mut b = [0u8; SHARE_LEN];
        rng.fill_bytes(&mut b);
        Self(b)
    }

    pub fn from_bytes(b: [u8; SHARE_LEN]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; SHARE_LEN] {
        &self.0
    }
}

impl fmt::Debug for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Share(<redacted>)")
    }
}

/// Keys derived for one artifact.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ArtifactKeys {
    pub(crate) payload_key: [u8; 32],
    pub(crate) manifest_key: [u8; 32],
    key_commitment: [u8; 32],
}

impl ArtifactKeys {
    pub fn derive(artifact_id: &[u8; 16], service_share: &Share, recipient_share: &Share) -> Self {
        let mut salt = Vec::with_capacity(32);
        salt.extend_from_slice(b"SVX-1 artifact\0");
        salt.extend_from_slice(artifact_id);
        let mut ikm = zeroize::Zeroizing::new([0u8; 2 * SHARE_LEN]);
        ikm[..SHARE_LEN].copy_from_slice(service_share.as_bytes());
        ikm[SHARE_LEN..].copy_from_slice(recipient_share.as_bytes());

        let hk = Hkdf::<Sha256>::new(Some(&salt), ikm.as_ref());
        let mut keys = ArtifactKeys {
            payload_key: [0; 32],
            manifest_key: [0; 32],
            key_commitment: [0; 32],
        };
        // 32-byte outputs are far below the HKDF-SHA256 limit, so expand cannot fail.
        hk.expand(b"svx/1/payload", &mut keys.payload_key)
            .expect("valid HKDF length");
        hk.expand(b"svx/1/manifest", &mut keys.manifest_key)
            .expect("valid HKDF length");
        hk.expand(b"svx/1/commitment", &mut keys.key_commitment)
            .expect("valid HKDF length");
        keys
    }

    /// The value stored in the header so a reader can detect a wrong or
    /// substituted share before attempting any decryption. ChaCha20-Poly1305
    /// is not key-committing on its own; this closes that gap.
    pub fn key_commitment(&self) -> [u8; 32] {
        self.key_commitment
    }

    /// Constant-time check against the header's commitment.
    pub fn check_commitment(&self, expected: &[u8; 32]) -> Result<()> {
        if bool::from(self.key_commitment.ct_eq(expected)) {
            Ok(())
        } else {
            Err(CryptoError::KeyCommitmentMismatch)
        }
    }
}

impl fmt::Debug for ArtifactKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArtifactKeys(<redacted>)")
    }
}
