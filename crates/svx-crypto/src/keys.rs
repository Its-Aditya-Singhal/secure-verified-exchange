//! Long-term key types.
//!
//! | Kind | Purpose | Public key | Secret |
//! |------|---------|-----------|--------|
//! | Ed25519 signing | suite SVX-1 signatures | 32 B | 32 B seed |
//! | Hybrid signing | suite SVX-1H: Ed25519 **and** ML-DSA-65 (FIPS 204) | 32 + 1952 B | two 32 B seeds |
//! | X25519 KEM | suite SVX-1 envelopes | 32 B | 32 B |
//! | X-Wing KEM | suite SVX-1H envelopes: X25519 **and** ML-KEM-768 (FIPS 203) | 1216 B | 32 B seed |
//! | Max signing | suite SVX-2: Ed25519 **and** ML-DSA-87 **and** SLH-DSA-SHA2-256s (FIPS 205) | 32 + 2592 + 64 B | 32 + 32 + 96 B seeds |
//! | Max KEM | suite SVX-2 envelopes and key release: MLKEM1024-P384 (`draft-ietf-hpke-pq`) | 1665 B | 32 B seed |
//!
//! The hybrid kinds are only as weak as the *strongest* of their parts: an
//! attacker must break every algorithm in them. Max signing keys add a
//! hash-based signature, so forging one needs elliptic curves, lattices and
//! hash functions all broken at once.

use std::fmt;

use ed25519_dalek::Signer;
use hpke::{Deserializable, Kem as _, Serializable};
use ml_dsa::signature::Keypair as _;
use ml_dsa::{EncodedVerifyingKey, MlDsa65, MlDsa87};
use sha2::{Digest, Sha256};
use slh_dsa::Sha2_256s;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

pub(crate) type X25519Kem = hpke::kem::X25519HkdfSha256;
pub(crate) type XWingKem = hpke::kem::XWing;
pub(crate) type MaxKem = hpke::kem::MlKem1024P384;
/// SLH-DSA parameter set of suite SVX-2 (NIST category 5, small signatures).
type Slh = Sha2_256s;

/// Ed25519 public key length.
pub const ED25519_PUBLIC_LEN: usize = 32;
/// ML-DSA-65 public key length (FIPS 204).
pub const MLDSA65_PUBLIC_LEN: usize = 1952;
/// Hybrid verifying key: `Ed25519 (32) ‖ ML-DSA-65 (1952)`.
pub const HYBRID_PUBLIC_LEN: usize = ED25519_PUBLIC_LEN + MLDSA65_PUBLIC_LEN;
/// Ed25519 signature length.
pub const ED25519_SIG_LEN: usize = 64;
/// ML-DSA-65 signature length (FIPS 204).
pub const MLDSA65_SIG_LEN: usize = 3309;
/// Hybrid signature: `Ed25519 (64) ‖ ML-DSA-65 (3309)`.
pub const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + MLDSA65_SIG_LEN;
/// X25519 public key / encapsulated key length.
pub const X25519_PUBLIC_LEN: usize = 32;
/// X-Wing public key length.
pub const XWING_PUBLIC_LEN: usize = 1216;
/// X-Wing encapsulated key (ciphertext) length.
pub const XWING_ENC_LEN: usize = 1120;
/// FIPS 204 context string for SVX-1H ML-DSA signatures.
pub(crate) const MLDSA_CONTEXT: &[u8] = b"SVX-1H";
/// ML-DSA-87 public key length (FIPS 204).
pub const MLDSA87_PUBLIC_LEN: usize = 2592;
/// ML-DSA-87 signature length (FIPS 204).
pub const MLDSA87_SIG_LEN: usize = 4627;
/// SLH-DSA-SHA2-256s public key length (FIPS 205).
pub const SLHDSA_PUBLIC_LEN: usize = 64;
/// SLH-DSA-SHA2-256s signature length (FIPS 205).
pub const SLHDSA_SIG_LEN: usize = 29792;
/// Max verifying key: `Ed25519 (32) ‖ ML-DSA-87 (2592) ‖ SLH-DSA (64)`.
pub const MAX_PUBLIC_LEN: usize = ED25519_PUBLIC_LEN + MLDSA87_PUBLIC_LEN + SLHDSA_PUBLIC_LEN;
/// Max secret: `Ed25519 seed (32) ‖ ML-DSA-87 seed (32) ‖ SLH-DSA sk_seed ‖ sk_prf ‖ pk_seed (96)`.
pub const MAX_SECRET_LEN: usize = 32 + 32 + 96;
/// Full Max signature: `Ed25519 (64) ‖ ML-DSA-87 (4627) ‖ SLH-DSA (29792)`.
pub const MAX_SIG_LEN: usize = ED25519_SIG_LEN + MLDSA87_SIG_LEN + SLHDSA_SIG_LEN;
/// Fast Max signature (short-lived objects): `Ed25519 (64) ‖ ML-DSA-87 (4627)`.
pub const MAX_FAST_SIG_LEN: usize = ED25519_SIG_LEN + MLDSA87_SIG_LEN;
/// MLKEM1024-P384 public key and encapsulated key length.
pub const MAX_KEM_PUBLIC_LEN: usize = 1665;
/// MLKEM1024-P384 encapsulated key (ciphertext) length.
pub const MAX_KEM_ENC_LEN: usize = 1665;
/// FIPS 204 and FIPS 205 context string for SVX-2 signatures.
pub(crate) const MAX_CONTEXT: &[u8] = b"SVX-2";

/// What a key is for; mixed into the key identifier so that keys of
/// different kinds can never share an ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyKind {
    Ed25519Signing,
    X25519Kem,
    XWingKem,
    /// Ed25519 + ML-DSA-65.
    HybridSigning,
    /// MLKEM1024-P384 (suite SVX-2).
    MaxKem,
    /// Ed25519 + ML-DSA-87 + SLH-DSA-SHA2-256s (suite SVX-2).
    MaxSigning,
}

impl KeyKind {
    pub fn byte(self) -> u8 {
        match self {
            KeyKind::Ed25519Signing => 0x01,
            KeyKind::X25519Kem => 0x02,
            KeyKind::XWingKem => 0x03,
            KeyKind::HybridSigning => 0x04,
            KeyKind::MaxKem => 0x05,
            KeyKind::MaxSigning => 0x06,
        }
    }

    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => KeyKind::Ed25519Signing,
            0x02 => KeyKind::X25519Kem,
            0x03 => KeyKind::XWingKem,
            0x04 => KeyKind::HybridSigning,
            0x05 => KeyKind::MaxKem,
            0x06 => KeyKind::MaxSigning,
            _ => return None,
        })
    }

    /// Whether this is a post-quantum hybrid kind (SVX-1H or SVX-2).
    pub fn is_hybrid(self) -> bool {
        matches!(
            self,
            KeyKind::XWingKem | KeyKind::HybridSigning | KeyKind::MaxKem | KeyKind::MaxSigning
        )
    }

    /// Whether this is a suite SVX-2 kind.
    pub fn is_max(self) -> bool {
        matches!(self, KeyKind::MaxKem | KeyKind::MaxSigning)
    }

    /// Whether this is a signing kind.
    pub fn is_signing(self) -> bool {
        matches!(
            self,
            KeyKind::Ed25519Signing | KeyKind::HybridSigning | KeyKind::MaxSigning
        )
    }
}

/// `SHA-256("SVX-1 key-id\0" ‖ kind ‖ public_key)[..16]`
pub fn key_id(kind: KeyKind, public_key: &[u8]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"SVX-1 key-id\0");
    h.update([kind.byte()]);
    h.update(public_key);
    let d = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

/// `SHA-256("SVX-1 key-fingerprint\0" ‖ kind ‖ public_key)`: the full
/// 256-bit digest that users pin in place of a key too long to paste (the
/// registry key). Unlike [`key_id`] it is not truncated, so a second
/// preimage stays out of reach even for a quantum attacker.
pub fn key_fingerprint(kind: KeyKind, public_key: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SVX-1 key-fingerprint\0");
    h.update([kind.byte()]);
    h.update(public_key);
    h.finalize().into()
}

// ----- Signing -----

/// An organization's signing key: Ed25519 (suite SVX-1), hybrid
/// Ed25519 + ML-DSA-65 (suite SVX-1H) or Max Ed25519 + ML-DSA-87 +
/// SLH-DSA-SHA2-256s (suite SVX-2).
// Few, long-lived values: the size difference between variants is irrelevant.
#[allow(clippy::large_enum_variant)]
pub enum SigningKey {
    Ed25519(ed25519_dalek::SigningKey),
    Hybrid(Box<HybridSigningKey>),
    Max(Box<MaxSigningKey>),
}

/// The two halves of a hybrid signing key (both zeroize on drop).
pub struct HybridSigningKey {
    ed: ed25519_dalek::SigningKey,
    ml: ml_dsa::SigningKey<MlDsa65>,
}

/// The three parts of a Max signing key (all zeroize on drop).
pub struct MaxSigningKey {
    ed: ed25519_dalek::SigningKey,
    ml: ml_dsa::SigningKey<MlDsa87>,
    slh: slh_dsa::SigningKey<Slh>,
}

/// Which parts of a Max key sign. Hybrid and Ed25519 keys always sign with
/// all their parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SigSet {
    /// Every algorithm: artifacts and long-lived records.
    Full,
    /// Ed25519 + ML-DSA-87 only: short-lived objects verified within
    /// minutes (release grants, account requests), where a hash-based
    /// hedge adds nothing and SLH-DSA's signing time would be in the way.
    Fast,
}

impl SigningKey {
    /// A new Ed25519 key (suite SVX-1).
    pub fn generate(rng: &mut impl rand_core::CryptoRng) -> Self {
        Self::Ed25519(ed25519_dalek::SigningKey::generate(rng))
    }

    /// A new hybrid Ed25519 + ML-DSA-65 key (suite SVX-1H).
    pub fn generate_hybrid(rng: &mut impl rand_core::CryptoRng) -> Self {
        let mut ed = Zeroizing::new([0u8; 32]);
        let mut ml = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(ed.as_mut());
        rng.fill_bytes(ml.as_mut());
        Self::hybrid_from_seeds(&ed, &ml)
    }

    /// A new Max key: Ed25519 + ML-DSA-87 + SLH-DSA-SHA2-256s (suite SVX-2).
    pub fn generate_max(rng: &mut impl rand_core::CryptoRng) -> Self {
        let mut seed = Zeroizing::new([0u8; MAX_SECRET_LEN]);
        rng.fill_bytes(seed.as_mut());
        Self::from_secret_bytes(KeyKind::MaxSigning, seed.as_ref()).expect("valid length")
    }

    /// An Ed25519 key from its 32-byte seed.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(bytes))
    }

    /// A hybrid key from its Ed25519 seed and ML-DSA-65 seed (FIPS 204 `ξ`).
    pub fn hybrid_from_seeds(ed_seed: &[u8; 32], ml_seed: &[u8; 32]) -> Self {
        let ml = ml_dsa::SigningKey::<MlDsa65>::from_seed(&(*ml_seed).into());
        Self::Hybrid(Box::new(HybridSigningKey {
            ed: ed25519_dalek::SigningKey::from_bytes(ed_seed),
            ml,
        }))
    }

    /// Decode secret bytes of the given kind (see [`SigningKey::to_secret_bytes`]).
    pub fn from_secret_bytes(kind: KeyKind, bytes: &[u8]) -> Result<Self> {
        match (kind, bytes.len()) {
            (KeyKind::Ed25519Signing, 32) => {
                Ok(Self::from_bytes(bytes.try_into().expect("checked length")))
            }
            (KeyKind::HybridSigning, 64) => {
                let ed: [u8; 32] = bytes[..32].try_into().expect("checked length");
                let ml: [u8; 32] = bytes[32..].try_into().expect("checked length");
                let ed = Zeroizing::new(ed);
                let ml = Zeroizing::new(ml);
                Ok(Self::hybrid_from_seeds(&ed, &ml))
            }
            (KeyKind::MaxSigning, MAX_SECRET_LEN) => {
                let ed: [u8; 32] = bytes[..32].try_into().expect("checked length");
                let ml: [u8; 32] = bytes[32..64].try_into().expect("checked length");
                let ed = Zeroizing::new(ed);
                let ml = Zeroizing::new(ml);
                let slh = &bytes[64..];
                Ok(Self::Max(Box::new(MaxSigningKey {
                    ed: ed25519_dalek::SigningKey::from_bytes(&ed),
                    ml: ml_dsa::SigningKey::<MlDsa87>::from_seed(&(*ml).into()),
                    // FIPS 205 slh_keygen_internal(SK.seed, SK.prf, PK.seed).
                    slh: slh_dsa::SigningKey::<Slh>::slh_keygen_internal(
                        &slh[..32],
                        &slh[32..64],
                        &slh[64..],
                    ),
                })))
            }
            _ => Err(CryptoError::InvalidKey),
        }
    }

    /// Ed25519: the 32-byte seed. Hybrid: `Ed25519 seed ‖ ML-DSA-65 seed`.
    /// Max: `Ed25519 seed ‖ ML-DSA-87 seed ‖ SK.seed ‖ SK.prf ‖ PK.seed`.
    pub fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        match self {
            Self::Ed25519(k) => Zeroizing::new(k.to_bytes().to_vec()),
            Self::Hybrid(h) => {
                let mut v = Zeroizing::new(Vec::with_capacity(64));
                v.extend_from_slice(&h.ed.to_bytes());
                v.extend_from_slice(h.ml.as_seed().as_slice());
                v
            }
            Self::Max(m) => {
                let mut v = Zeroizing::new(Vec::with_capacity(MAX_SECRET_LEN));
                v.extend_from_slice(&m.ed.to_bytes());
                v.extend_from_slice(m.ml.as_seed().as_slice());
                // SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root: keep the three seeds.
                let mut slh = m.slh.to_bytes();
                v.extend_from_slice(&slh[..96]);
                zeroize::Zeroize::zeroize(slh.as_mut_slice());
                v
            }
        }
    }

    /// The Ed25519 seed. Only for Ed25519 keys.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        match self {
            Self::Ed25519(k) => Zeroizing::new(k.to_bytes()),
            // Callers of the 32-byte form only handle Ed25519 keys.
            Self::Hybrid(h) => Zeroizing::new(h.ed.to_bytes()),
            Self::Max(m) => Zeroizing::new(m.ed.to_bytes()),
        }
    }

    pub fn kind(&self) -> KeyKind {
        match self {
            Self::Ed25519(_) => KeyKind::Ed25519Signing,
            Self::Hybrid(_) => KeyKind::HybridSigning,
            Self::Max(_) => KeyKind::MaxSigning,
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        match self {
            Self::Ed25519(k) => VerifyingKey::Ed25519(k.verifying_key()),
            Self::Hybrid(h) => {
                let ml = h.ml.verifying_key();
                let mut bytes = Vec::with_capacity(HYBRID_PUBLIC_LEN);
                bytes.extend_from_slice(&h.ed.verifying_key().to_bytes());
                bytes.extend_from_slice(&ml.encode());
                VerifyingKey::Hybrid(Box::new(HybridVerifyingKey {
                    ed: h.ed.verifying_key(),
                    ml,
                    bytes,
                }))
            }
            Self::Max(m) => {
                let ml = m.ml.verifying_key();
                let slh = m.slh.as_ref().clone();
                let mut bytes = Vec::with_capacity(MAX_PUBLIC_LEN);
                bytes.extend_from_slice(&m.ed.verifying_key().to_bytes());
                bytes.extend_from_slice(&ml.encode());
                bytes.extend_from_slice(&slh.to_bytes());
                VerifyingKey::Max(Box::new(MaxVerifyingKey {
                    ed: m.ed.verifying_key(),
                    ml,
                    slh,
                    bytes,
                }))
            }
        }
    }

    /// Sign `msg`. Hybrid keys produce `Ed25519 sig ‖ ML-DSA-65 sig`; Max
    /// keys `Ed25519 sig ‖ ML-DSA-87 sig ‖ SLH-DSA sig` ([`SigSet::Full`]) or
    /// `Ed25519 sig ‖ ML-DSA-87 sig` ([`SigSet::Fast`]). ML-DSA and SLH-DSA
    /// are hedged (randomized, the FIPS default) with `rng`.
    pub(crate) fn sign_raw(
        &self,
        msg: &[u8],
        set: SigSet,
        rng: &mut impl rand_core::CryptoRng,
    ) -> Result<Vec<u8>> {
        match self {
            Self::Ed25519(k) => Ok(k.sign(msg).to_bytes().to_vec()),
            Self::Hybrid(h) => {
                let ml =
                    h.ml.expanded_key()
                        .sign_randomized(msg, MLDSA_CONTEXT, rng)
                        .map_err(|_| CryptoError::Encryption)?;
                let mut sig = Vec::with_capacity(HYBRID_SIG_LEN);
                sig.extend_from_slice(&h.ed.sign(msg).to_bytes());
                sig.extend_from_slice(&ml.encode());
                debug_assert_eq!(sig.len(), HYBRID_SIG_LEN);
                Ok(sig)
            }
            Self::Max(m) => {
                let ml =
                    m.ml.expanded_key()
                        .sign_randomized(msg, MAX_CONTEXT, rng)
                        .map_err(|_| CryptoError::Encryption)?;
                let mut sig = Vec::with_capacity(MAX_SIG_LEN);
                sig.extend_from_slice(&m.ed.sign(msg).to_bytes());
                sig.extend_from_slice(&ml.encode());
                if set == SigSet::Full {
                    let mut opt_rand = Zeroizing::new([0u8; 32]);
                    rng.fill_bytes(opt_rand.as_mut());
                    sig.extend_from_slice(&slh_sign(&m.slh, msg, &opt_rand)?);
                    debug_assert_eq!(sig.len(), MAX_SIG_LEN);
                } else {
                    debug_assert_eq!(sig.len(), MAX_FAST_SIG_LEN);
                }
                Ok(sig)
            }
        }
    }
}

/// SLH-DSA signing, kept out of the generic [`SigningKey::sign_raw`] so it
/// is always compiled (optimized) in this crate rather than in each caller.
#[inline(never)]
fn slh_sign(key: &slh_dsa::SigningKey<Slh>, msg: &[u8], opt_rand: &[u8; 32]) -> Result<Vec<u8>> {
    key.try_sign_with_context(msg, MAX_CONTEXT, Some(opt_rand))
        .map(|s| s.to_bytes().to_vec())
        .map_err(|_| CryptoError::Encryption)
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SigningKey({:?}, key_id={})",
            self.kind(),
            hex16(&self.verifying_key().key_id())
        )
    }
}

/// An organization's public verification key.
#[derive(Clone)]
pub enum VerifyingKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    Hybrid(Box<HybridVerifyingKey>),
    Max(Box<MaxVerifyingKey>),
}

#[derive(Clone)]
pub struct HybridVerifyingKey {
    ed: ed25519_dalek::VerifyingKey,
    ml: ml_dsa::VerifyingKey<MlDsa65>,
    /// `Ed25519 (32) ‖ ML-DSA-65 (1952)`, as published.
    bytes: Vec<u8>,
}

#[derive(Clone)]
pub struct MaxVerifyingKey {
    ed: ed25519_dalek::VerifyingKey,
    ml: ml_dsa::VerifyingKey<MlDsa87>,
    slh: slh_dsa::VerifyingKey<Slh>,
    /// `Ed25519 (32) ‖ ML-DSA-87 (2592) ‖ SLH-DSA (64)`, as published.
    bytes: Vec<u8>,
}

fn ed25519_public(bytes: &[u8; 32]) -> Result<ed25519_dalek::VerifyingKey> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| CryptoError::InvalidKey)?;
    // Reject small-order / weak keys outright.
    if vk.is_weak() {
        return Err(CryptoError::InvalidKey);
    }
    Ok(vk)
}

impl VerifyingKey {
    /// An Ed25519 key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        Ok(Self::Ed25519(ed25519_public(bytes)?))
    }

    /// Decode a public key of the given kind.
    pub fn from_kind_bytes(kind: KeyKind, bytes: &[u8]) -> Result<Self> {
        match kind {
            KeyKind::Ed25519Signing => {
                let b: &[u8; 32] = bytes.try_into().map_err(|_| CryptoError::InvalidKey)?;
                Self::from_bytes(b)
            }
            KeyKind::HybridSigning => {
                if bytes.len() != HYBRID_PUBLIC_LEN {
                    return Err(CryptoError::InvalidKey);
                }
                let ed = ed25519_public(bytes[..32].try_into().expect("checked length"))?;
                let enc = EncodedVerifyingKey::<MlDsa65>::try_from(&bytes[32..])
                    .map_err(|_| CryptoError::InvalidKey)?;
                let ml = ml_dsa::VerifyingKey::<MlDsa65>::decode(&enc);
                // pkDecode is total; re-encoding must give back the same bytes.
                if ml.encode().as_slice() != &bytes[32..] {
                    return Err(CryptoError::InvalidKey);
                }
                Ok(Self::Hybrid(Box::new(HybridVerifyingKey {
                    ed,
                    ml,
                    bytes: bytes.to_vec(),
                })))
            }
            KeyKind::MaxSigning => {
                if bytes.len() != MAX_PUBLIC_LEN {
                    return Err(CryptoError::InvalidKey);
                }
                let (ed, rest) = bytes.split_at(ED25519_PUBLIC_LEN);
                let (ml, slh) = rest.split_at(MLDSA87_PUBLIC_LEN);
                let ed = ed25519_public(ed.try_into().expect("checked length"))?;
                let enc = EncodedVerifyingKey::<MlDsa87>::try_from(ml)
                    .map_err(|_| CryptoError::InvalidKey)?;
                let ml_key = ml_dsa::VerifyingKey::<MlDsa87>::decode(&enc);
                if ml_key.encode().as_slice() != ml {
                    return Err(CryptoError::InvalidKey);
                }
                let slh = slh_dsa::VerifyingKey::<Slh>::try_from(slh)
                    .map_err(|_| CryptoError::InvalidKey)?;
                Ok(Self::Max(Box::new(MaxVerifyingKey {
                    ed,
                    ml: ml_key,
                    slh,
                    bytes: bytes.to_vec(),
                })))
            }
            _ => Err(CryptoError::InvalidKey),
        }
    }

    pub fn kind(&self) -> KeyKind {
        match self {
            Self::Ed25519(_) => KeyKind::Ed25519Signing,
            Self::Hybrid(_) => KeyKind::HybridSigning,
            Self::Max(_) => KeyKind::MaxSigning,
        }
    }

    /// The published public key bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(k) => k.to_bytes().to_vec(),
            Self::Hybrid(h) => h.bytes.clone(),
            Self::Max(m) => m.bytes.clone(),
        }
    }

    /// The Ed25519 key bytes (for Ed25519 keys; the Ed25519 half of a hybrid key).
    pub fn to_bytes(&self) -> [u8; 32] {
        match self {
            Self::Ed25519(k) => k.to_bytes(),
            Self::Hybrid(h) => h.ed.to_bytes(),
            Self::Max(m) => m.ed.to_bytes(),
        }
    }

    pub fn key_id(&self) -> [u8; 16] {
        key_id(self.kind(), &self.to_vec())
    }

    /// See [`key_fingerprint`].
    pub fn fingerprint(&self) -> [u8; 32] {
        key_fingerprint(self.kind(), &self.to_vec())
    }

    /// Strict verification. A hybrid signature is valid only if **both**
    /// the Ed25519 and the ML-DSA-65 halves verify; a Max signature only if
    /// **every** part in `set` verifies. Every part is checked (no early
    /// exit), and the length must be exact.
    pub(crate) fn verify_raw(&self, msg: &[u8], sig: &[u8], set: SigSet) -> Result<()> {
        let ok = match self {
            Self::Ed25519(k) => ed25519_verify(k, msg, sig).is_ok(),
            Self::Hybrid(h) => {
                if sig.len() != HYBRID_SIG_LEN {
                    return Err(CryptoError::BadSignature);
                }
                let (ed_sig, ml_sig) = sig.split_at(ED25519_SIG_LEN);
                let ed_ok = ed25519_verify(&h.ed, msg, ed_sig).is_ok();
                let ml_ok = ml_dsa::Signature::<MlDsa65>::try_from(ml_sig)
                    .map(|s| h.ml.verify_with_context(msg, MLDSA_CONTEXT, &s))
                    .unwrap_or(false);
                ed_ok & ml_ok
            }
            Self::Max(m) => {
                let want = match set {
                    SigSet::Full => MAX_SIG_LEN,
                    SigSet::Fast => MAX_FAST_SIG_LEN,
                };
                if sig.len() != want {
                    return Err(CryptoError::BadSignature);
                }
                let (ed_sig, rest) = sig.split_at(ED25519_SIG_LEN);
                let (ml_sig, slh_sig) = rest.split_at(MLDSA87_SIG_LEN);
                let ed_ok = ed25519_verify(&m.ed, msg, ed_sig).is_ok();
                let ml_ok = ml_dsa::Signature::<MlDsa87>::try_from(ml_sig)
                    .map(|s| m.ml.verify_with_context(msg, MAX_CONTEXT, &s))
                    .unwrap_or(false);
                let slh_ok = match set {
                    SigSet::Fast => true,
                    SigSet::Full => slh_dsa::Signature::<Slh>::try_from(slh_sig)
                        .map(|s| m.slh.try_verify_with_context(msg, MAX_CONTEXT, &s).is_ok())
                        .unwrap_or(false),
                };
                ed_ok & ml_ok & slh_ok
            }
        };
        if ok {
            Ok(())
        } else {
            Err(CryptoError::BadSignature)
        }
    }
}

fn ed25519_verify(k: &ed25519_dalek::VerifyingKey, msg: &[u8], sig: &[u8]) -> Result<()> {
    let sig: [u8; 64] = sig.try_into().map_err(|_| CryptoError::BadSignature)?;
    k.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig))
        .map_err(|_| CryptoError::BadSignature)
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.kind() == other.kind() && self.to_vec() == other.to_vec()
    }
}

impl Eq for VerifyingKey {}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VerifyingKey({:?}, key_id={})",
            self.kind(),
            hex16(&self.key_id())
        )
    }
}

// ----- KEM -----

/// An HPKE private key: X25519 (suite SVX-1), X-Wing (suite SVX-1H) or
/// MLKEM1024-P384 (suite SVX-2 and key release).
pub enum KemSecretKey {
    X25519 {
        sk: <X25519Kem as hpke::Kem>::PrivateKey,
        pk: KemPublicKey,
    },
    XWing {
        sk: Box<<XWingKem as hpke::Kem>::PrivateKey>,
        pk: KemPublicKey,
    },
    Max {
        sk: Box<<MaxKem as hpke::Kem>::PrivateKey>,
        pk: KemPublicKey,
    },
}

impl KemSecretKey {
    /// A new X25519 key (suite SVX-1).
    pub fn generate(rng: &mut impl rand_core::CryptoRng) -> Self {
        let (sk, pk) = X25519Kem::gen_keypair_with_rng(rng);
        Self::X25519 {
            sk,
            pk: KemPublicKey::X25519(pk),
        }
    }

    /// A new X-Wing key (suite SVX-1H, key release).
    pub fn generate_hybrid(rng: &mut impl rand_core::CryptoRng) -> Self {
        let (sk, pk) = XWingKem::gen_keypair_with_rng(rng);
        Self::XWing {
            sk: Box::new(sk),
            pk: KemPublicKey::XWing(Box::new(pk)),
        }
    }

    /// A new MLKEM1024-P384 key (suite SVX-2, key release).
    pub fn generate_max(rng: &mut impl rand_core::CryptoRng) -> Self {
        let (sk, pk) = MaxKem::gen_keypair_with_rng(rng);
        Self::Max {
            sk: Box::new(sk),
            pk: KemPublicKey::Max(Box::new(pk)),
        }
    }

    /// Deterministically derive an X25519 key pair (RFC 9180
    /// `DeriveKeyPair`). Used for test vectors.
    pub fn derive(ikm: &[u8]) -> Self {
        Self::derive_kind(KeyKind::X25519Kem, ikm).expect("KEM kind")
    }

    /// Deterministically derive a key pair of `kind` (test vectors).
    pub fn derive_kind(kind: KeyKind, ikm: &[u8]) -> Result<Self> {
        match kind {
            KeyKind::X25519Kem => {
                let (sk, pk) = X25519Kem::derive_keypair(ikm);
                Ok(Self::X25519 {
                    sk,
                    pk: KemPublicKey::X25519(pk),
                })
            }
            KeyKind::XWingKem => {
                let (sk, pk) = XWingKem::derive_keypair(ikm);
                Ok(Self::XWing {
                    sk: Box::new(sk),
                    pk: KemPublicKey::XWing(Box::new(pk)),
                })
            }
            KeyKind::MaxKem => {
                let (sk, pk) = MaxKem::derive_keypair(ikm);
                Ok(Self::Max {
                    sk: Box::new(sk),
                    pk: KemPublicKey::Max(Box::new(pk)),
                })
            }
            _ => Err(CryptoError::InvalidKey),
        }
    }

    /// An X25519 secret key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        Self::from_kind_bytes(KeyKind::X25519Kem, bytes)
    }

    /// A secret key of `kind` (all kinds are 32 bytes; X-Wing and
    /// MLKEM1024-P384 store their seed).
    pub fn from_kind_bytes(kind: KeyKind, bytes: &[u8; 32]) -> Result<Self> {
        match kind {
            KeyKind::X25519Kem => {
                let sk = <X25519Kem as hpke::Kem>::PrivateKey::from_bytes(bytes)
                    .map_err(|_| CryptoError::InvalidKey)?;
                let pk = X25519Kem::sk_to_pk(&sk);
                Ok(Self::X25519 {
                    sk,
                    pk: KemPublicKey::X25519(pk),
                })
            }
            KeyKind::XWingKem => {
                let sk = <XWingKem as hpke::Kem>::PrivateKey::from_bytes(bytes)
                    .map_err(|_| CryptoError::InvalidKey)?;
                let pk = XWingKem::sk_to_pk(&sk);
                Ok(Self::XWing {
                    sk: Box::new(sk),
                    pk: KemPublicKey::XWing(Box::new(pk)),
                })
            }
            KeyKind::MaxKem => {
                let sk = <MaxKem as hpke::Kem>::PrivateKey::from_bytes(bytes)
                    .map_err(|_| CryptoError::InvalidKey)?;
                let pk = MaxKem::sk_to_pk(&sk);
                Ok(Self::Max {
                    sk: Box::new(sk),
                    pk: KemPublicKey::Max(Box::new(pk)),
                })
            }
            _ => Err(CryptoError::InvalidKey),
        }
    }

    /// The 32-byte secret (X-Wing and MLKEM1024-P384: the seed), wiped on drop.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        let bytes = match self {
            Self::X25519 { sk, .. } => sk.to_bytes().to_vec(),
            Self::XWing { sk, .. } => sk.to_bytes().to_vec(),
            Self::Max { sk, .. } => sk.to_bytes().to_vec(),
        };
        let bytes = Zeroizing::new(bytes);
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&bytes);
        out
    }

    pub fn kind(&self) -> KeyKind {
        self.public_key().kind()
    }

    pub fn public_key(&self) -> &KemPublicKey {
        match self {
            Self::X25519 { pk, .. } | Self::XWing { pk, .. } | Self::Max { pk, .. } => pk,
        }
    }
}

impl fmt::Debug for KemSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KemSecretKey({:?}, key_id={})",
            self.kind(),
            hex16(&self.public_key().key_id())
        )
    }
}

/// An HPKE public key.
#[derive(Clone, PartialEq, Eq)]
pub enum KemPublicKey {
    X25519(<X25519Kem as hpke::Kem>::PublicKey),
    XWing(Box<<XWingKem as hpke::Kem>::PublicKey>),
    Max(Box<<MaxKem as hpke::Kem>::PublicKey>),
}

impl KemPublicKey {
    /// An X25519 public key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        Self::from_kind_bytes(KeyKind::X25519Kem, bytes)
    }

    /// A public key of `kind`.
    pub fn from_kind_bytes(kind: KeyKind, bytes: &[u8]) -> Result<Self> {
        match kind {
            KeyKind::X25519Kem => Ok(Self::X25519(
                <X25519Kem as hpke::Kem>::PublicKey::from_bytes(bytes)
                    .map_err(|_| CryptoError::InvalidKey)?,
            )),
            KeyKind::XWingKem => Ok(Self::XWing(Box::new(
                <XWingKem as hpke::Kem>::PublicKey::from_bytes(bytes)
                    .map_err(|_| CryptoError::InvalidKey)?,
            ))),
            KeyKind::MaxKem => Ok(Self::Max(Box::new(
                <MaxKem as hpke::Kem>::PublicKey::from_bytes(bytes)
                    .map_err(|_| CryptoError::InvalidKey)?,
            ))),
            _ => Err(CryptoError::InvalidKey),
        }
    }

    pub fn kind(&self) -> KeyKind {
        match self {
            Self::X25519(_) => KeyKind::X25519Kem,
            Self::XWing(_) => KeyKind::XWingKem,
            Self::Max(_) => KeyKind::MaxKem,
        }
    }

    /// The published public key bytes (32, 1216 or 1665 bytes).
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::X25519(pk) => pk.to_bytes().to_vec(),
            Self::XWing(pk) => pk.to_bytes().to_vec(),
            Self::Max(pk) => pk.to_bytes().to_vec(),
        }
    }

    pub fn key_id(&self) -> [u8; 16] {
        key_id(self.kind(), &self.to_vec())
    }
}

impl fmt::Debug for KemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KemPublicKey({:?}, key_id={})",
            self.kind(),
            hex16(&self.key_id())
        )
    }
}

/// HPKE base-mode single-shot seal/open with ChaCha20-Poly1305: HKDF-SHA256
/// with X25519 and X-Wing (suites SVX-1, SVX-1H), HKDF-SHA512 with
/// MLKEM1024-P384 (suite SVX-2).
pub(crate) mod hpke_ops {
    use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
    use zeroize::Zeroizing;

    use super::{KemPublicKey, KemSecretKey, MaxKem, X25519Kem, XWingKem};
    use crate::error::{CryptoError, Result};

    type Aead = hpke::aead::ChaCha20Poly1305;
    type Sha256 = hpke::kdf::HkdfSha256;
    type Sha512 = hpke::kdf::HkdfSha512;

    /// Returns `(encapsulated_key, ciphertext)`.
    pub fn seal(
        pk: &KemPublicKey,
        info: &[u8],
        pt: &[u8],
        rng: &mut impl rand_core::CryptoRng,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        fn go<Kdf: hpke::kdf::Kdf, K: hpke::Kem>(
            pk: &K::PublicKey,
            info: &[u8],
            pt: &[u8],
            rng: &mut impl rand_core::CryptoRng,
        ) -> Result<(Vec<u8>, Vec<u8>)> {
            let (enc, ct) = hpke::single_shot_seal_with_rng::<Aead, Kdf, K>(
                &OpModeS::Base,
                pk,
                info,
                pt,
                b"",
                rng,
            )
            .map_err(|_| CryptoError::Encryption)?;
            Ok((enc.to_bytes().to_vec(), ct))
        }
        match pk {
            KemPublicKey::X25519(pk) => go::<Sha256, X25519Kem>(pk, info, pt, rng),
            KemPublicKey::XWing(pk) => go::<Sha256, XWingKem>(pk, info, pt, rng),
            KemPublicKey::Max(pk) => go::<Sha512, MaxKem>(pk, info, pt, rng),
        }
    }

    pub fn open(
        sk: &KemSecretKey,
        enc: &[u8],
        info: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        fn go<Kdf: hpke::kdf::Kdf, K: hpke::Kem>(
            sk: &K::PrivateKey,
            enc: &[u8],
            info: &[u8],
            ct: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>> {
            let enc = K::EncappedKey::from_bytes(enc).map_err(|_| CryptoError::EnvelopeOpen)?;
            hpke::single_shot_open::<Aead, Kdf, K>(&OpModeR::Base, sk, &enc, info, ct, b"")
                .map(Zeroizing::new)
                .map_err(|_| CryptoError::EnvelopeOpen)
        }
        match sk {
            KemSecretKey::X25519 { sk, .. } => go::<Sha256, X25519Kem>(sk, enc, info, ct),
            KemSecretKey::XWing { sk, .. } => go::<Sha256, XWingKem>(sk, enc, info, ct),
            KemSecretKey::Max { sk, .. } => go::<Sha512, MaxKem>(sk, enc, info, ct),
        }
    }
}

fn hex16(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
