//! Long-term key types: Ed25519 signing keys and X25519 HPKE keys.

use std::fmt;

use ed25519_dalek::Signer;
use hpke::{Deserializable, Kem as _, Serializable};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

pub(crate) type HpkeKem = hpke::kem::X25519HkdfSha256;

/// What a key is for; mixed into the key identifier so that a signing key
/// and a KEM key with the same bytes can never share an ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    Ed25519Signing,
    X25519Kem,
}

impl KeyKind {
    fn byte(self) -> u8 {
        match self {
            KeyKind::Ed25519Signing => 0x01,
            KeyKind::X25519Kem => 0x02,
        }
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

/// An organization's Ed25519 signing key.
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    pub fn generate(rng: &mut impl rand_core::CryptoRng) -> Self {
        Self(ed25519_dalek::SigningKey::generate(rng))
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(bytes))
    }

    /// Secret key bytes, wrapped so they are wiped when dropped.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    pub(crate) fn sign_raw(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SigningKey(key_id={})",
            hex16(&self.verifying_key().key_id())
        )
    }
}

/// An organization's Ed25519 public verification key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

impl VerifyingKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let vk =
            ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| CryptoError::InvalidKey)?;
        // Reject small-order / weak keys outright.
        if vk.is_weak() {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self(vk))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn key_id(&self) -> [u8; 16] {
        key_id(KeyKind::Ed25519Signing, &self.to_bytes())
    }

    pub(crate) fn verify_raw(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        let sig: [u8; 64] = sig.try_into().map_err(|_| CryptoError::BadSignature)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig);
        self.0
            .verify_strict(msg, &sig)
            .map_err(|_| CryptoError::BadSignature)
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey(key_id={})", hex16(&self.key_id()))
    }
}

/// An X25519 HPKE private key (service key-release key or recipient org key).
pub struct KemSecretKey {
    sk: <HpkeKem as hpke::Kem>::PrivateKey,
    pk: KemPublicKey,
}

impl KemSecretKey {
    pub fn generate(rng: &mut impl rand_core::CryptoRng) -> Self {
        let (sk, pk) = HpkeKem::gen_keypair_with_rng(rng);
        Self {
            sk,
            pk: KemPublicKey(pk),
        }
    }

    /// Deterministically derive a key pair from input keying material
    /// (RFC 9180 `DeriveKeyPair`). Used for test vectors.
    pub fn derive(ikm: &[u8]) -> Self {
        let (sk, pk) = HpkeKem::derive_keypair(ikm);
        Self {
            sk,
            pk: KemPublicKey(pk),
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let sk = <HpkeKem as hpke::Kem>::PrivateKey::from_bytes(bytes)
            .map_err(|_| CryptoError::InvalidKey)?;
        let pk = HpkeKem::sk_to_pk(&sk);
        Ok(Self {
            sk,
            pk: KemPublicKey(pk),
        })
    }

    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&self.sk.to_bytes());
        out
    }

    pub fn public_key(&self) -> &KemPublicKey {
        &self.pk
    }

    pub(crate) fn inner(&self) -> &<HpkeKem as hpke::Kem>::PrivateKey {
        &self.sk
    }
}

impl fmt::Debug for KemSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KemSecretKey(key_id={})", hex16(&self.pk.key_id()))
    }
}

/// An X25519 HPKE public key.
#[derive(Clone, PartialEq, Eq)]
pub struct KemPublicKey(<HpkeKem as hpke::Kem>::PublicKey);

impl KemPublicKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let pk = <HpkeKem as hpke::Kem>::PublicKey::from_bytes(bytes)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self(pk))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.0.to_bytes());
        out
    }

    pub fn key_id(&self) -> [u8; 16] {
        key_id(KeyKind::X25519Kem, &self.to_bytes())
    }

    pub(crate) fn inner(&self) -> &<HpkeKem as hpke::Kem>::PublicKey {
        &self.0
    }
}

impl fmt::Debug for KemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KemPublicKey(key_id={})", hex16(&self.key_id()))
    }
}

fn hex16(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
