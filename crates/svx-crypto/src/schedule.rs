//! Split-key artifact key schedule.
//!
//! ```text
//! prk            = HKDF-Extract(salt = "<suite> artifact\0" ‖ artifact_id,
//!                               ikm  = share_service ‖ share_recipient)
//! payload_key    = HKDF-Expand(prk, "svx/1/payload",    32)
//! manifest_key   = HKDF-Expand(prk, "svx/1/manifest",   32)
//! key_commitment = HKDF-Expand(prk, "svx/1/commitment", 32)
//! ```
//!
//! HKDF uses SHA-256 in suites SVX-1 and SVX-1H and SHA-512 in SVX-2.
//!
//! Both shares are required. Neither the managed service (which can unwrap
//! only `share_service`) nor the recipient organization's key agent (which
//! can unwrap only `share_recipient`) can derive the payload key alone.

use std::fmt;

use hkdf::Hkdf;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::SHARE_LEN;
use crate::error::{CryptoError, Result};
use crate::suite::Suite;

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
    pub fn derive(
        suite: Suite,
        artifact_id: &[u8; 16],
        service_share: &Share,
        recipient_share: &Share,
    ) -> Self {
        let mut salt = suite.label("artifact");
        salt.extend_from_slice(artifact_id);
        let mut ikm = zeroize::Zeroizing::new([0u8; 2 * SHARE_LEN]);
        ikm[..SHARE_LEN].copy_from_slice(service_share.as_bytes());
        ikm[SHARE_LEN..].copy_from_slice(recipient_share.as_bytes());

        let mut keys = ArtifactKeys {
            payload_key: [0; 32],
            manifest_key: [0; 32],
            key_commitment: [0; 32],
        };
        // 32-byte outputs are far below the HKDF limit, so expand cannot fail.
        let mut expand = |f: &dyn Fn(&[u8], &mut [u8])| {
            f(b"svx/1/payload", &mut keys.payload_key);
            f(b"svx/1/manifest", &mut keys.manifest_key);
            f(b"svx/1/commitment", &mut keys.key_commitment);
        };
        if suite.wide_hash() {
            let hk = Hkdf::<Sha512>::new(Some(&salt), ikm.as_ref());
            expand(&|info, out| hk.expand(info, out).expect("valid HKDF length"));
        } else {
            let hk = Hkdf::<Sha256>::new(Some(&salt), ikm.as_ref());
            expand(&|info, out| hk.expand(info, out).expect("valid HKDF length"));
        }
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
