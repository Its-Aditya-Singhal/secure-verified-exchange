//! Signed organization registry records.
//!
//! The registry is the managed service's statement of which keys and which
//! IdP belong to an organization. Clients pin the fingerprint of the
//! registry's Max (Ed25519 + ML-DSA-87 + SLH-DSA, suite SVX-2) public key
//! and accept sender signing keys only from a correctly signed, fresh
//! record.

use serde::{Deserialize, Serialize};
use svx_core::TrustStore;
use svx_core::crypto::{
    CryptoError, KemPublicKey, KeyKind, SignContext, SigningKey, VerifyingKey, sign_context,
    verify_context,
};
use svx_core::format::Identifier;

use crate::encoding::{b64, hex_array, hex_vec};
use crate::personal::{OrgKind, PersonalIdp};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyKindWire {
    /// Ed25519 artifact signing key (suite SVX-1; verifies older files).
    #[serde(rename = "ed25519")]
    Ed25519,
    /// X25519 HPKE key-agreement key (suite SVX-1; opens older files).
    #[serde(rename = "x25519")]
    X25519,
    /// X-Wing (X25519 + ML-KEM-768) HPKE key (suite SVX-1H; opens older files).
    #[serde(rename = "xwing")]
    XWing,
    /// Ed25519 + ML-DSA-65 composite signing key (suite SVX-1H; verifies older files).
    #[serde(rename = "ed25519-mldsa65")]
    Ed25519Mldsa65,
    /// MLKEM1024-P384 HPKE key (suite SVX-2): where new files are sealed.
    #[serde(rename = "mlkem1024-p384")]
    MlKem1024P384,
    /// Ed25519 + ML-DSA-87 + SLH-DSA-SHA2-256s signing key (suite SVX-2): signs new files.
    #[serde(rename = "ed25519-mldsa87-slhdsa")]
    Max,
}

impl KeyKindWire {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyKindWire::Ed25519 => "ed25519",
            KeyKindWire::X25519 => "x25519",
            KeyKindWire::XWing => "xwing",
            KeyKindWire::Ed25519Mldsa65 => "ed25519-mldsa65",
            KeyKindWire::MlKem1024P384 => "mlkem1024-p384",
            KeyKindWire::Max => "ed25519-mldsa87-slhdsa",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ed25519" => Some(KeyKindWire::Ed25519),
            "x25519" => Some(KeyKindWire::X25519),
            "xwing" => Some(KeyKindWire::XWing),
            "ed25519-mldsa65" => Some(KeyKindWire::Ed25519Mldsa65),
            "mlkem1024-p384" => Some(KeyKindWire::MlKem1024P384),
            "ed25519-mldsa87-slhdsa" => Some(KeyKindWire::Max),
            _ => None,
        }
    }

    /// The matching `svx-crypto` key kind.
    pub fn key_kind(self) -> KeyKind {
        match self {
            KeyKindWire::Ed25519 => KeyKind::Ed25519Signing,
            KeyKindWire::X25519 => KeyKind::X25519Kem,
            KeyKindWire::XWing => KeyKind::XWingKem,
            KeyKindWire::Ed25519Mldsa65 => KeyKind::HybridSigning,
            KeyKindWire::MlKem1024P384 => KeyKind::MaxKem,
            KeyKindWire::Max => KeyKind::MaxSigning,
        }
    }

    pub fn from_key_kind(kind: KeyKind) -> Self {
        match kind {
            KeyKind::Ed25519Signing => KeyKindWire::Ed25519,
            KeyKind::X25519Kem => KeyKindWire::X25519,
            KeyKind::XWingKem => KeyKindWire::XWing,
            KeyKind::HybridSigning => KeyKindWire::Ed25519Mldsa65,
            KeyKind::MaxKem => KeyKindWire::MlKem1024P384,
            KeyKind::MaxSigning => KeyKindWire::Max,
        }
    }

    pub fn is_signing(self) -> bool {
        self.key_kind().is_signing()
    }

    /// Whether new files use this kind (suite SVX-2).
    pub fn is_current(self) -> bool {
        self.key_kind().is_max()
    }

    /// Whether this is a post-quantum hybrid key kind.
    pub fn is_hybrid(self) -> bool {
        self.key_kind().is_hybrid()
    }

    /// Parse `public_key` as a key of this kind (exact length and encoding
    /// checks) and return its key ID.
    pub fn key_id_of(self, public_key: &[u8]) -> Option<[u8; 16]> {
        let kind = self.key_kind();
        if self.is_signing() {
            VerifyingKey::from_kind_bytes(kind, public_key)
                .ok()
                .map(|k| k.key_id())
        } else {
            KemPublicKey::from_kind_bytes(kind, public_key)
                .ok()
                .map(|k| k.key_id())
        }
    }
}

/// Key lifecycle: `active` keys sign/receive new artifacts; `retired` keys
/// still verify/unwrap existing ones; `revoked` keys are rejected outright.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    Active,
    Retired,
    Revoked,
}

impl KeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyStatus::Active => "active",
            KeyStatus::Retired => "retired",
            KeyStatus::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(KeyStatus::Active),
            "retired" => Some(KeyStatus::Retired),
            "revoked" => Some(KeyStatus::Revoked),
            _ => None,
        }
    }

    /// Whether a transition is allowed. Revocation is terminal and keys
    /// never become active again once retired.
    pub fn can_become(self, next: KeyStatus) -> bool {
        matches!(
            (self, next),
            (KeyStatus::Active, _)
                | (KeyStatus::Retired, KeyStatus::Retired | KeyStatus::Revoked)
                | (KeyStatus::Revoked, KeyStatus::Revoked)
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    #[serde(with = "hex_array")]
    pub key_id: [u8; 16],
    pub kind: KeyKindWire,
    /// 32 bytes for classical keys; 1216 (X-Wing) or 1984 (Ed25519 +
    /// ML-DSA-65) for SVX-1H keys; 1665 (MLKEM1024-P384) or 2688 (Ed25519 +
    /// ML-DSA-87 + SLH-DSA) for SVX-2 keys.
    #[serde(with = "hex_vec")]
    pub public_key: Vec<u8>,
    pub status: KeyStatus,
}

impl KeyEntry {
    /// The entry's signing key, checked against its kind and key ID.
    pub fn verifying_key(&self) -> Result<VerifyingKey, RecordError> {
        if !self.kind.is_signing() {
            return Err(RecordError::Malformed);
        }
        let vk = VerifyingKey::from_kind_bytes(self.kind.key_kind(), &self.public_key)
            .map_err(|_| RecordError::Malformed)?;
        if vk.key_id() != self.key_id {
            return Err(RecordError::Malformed);
        }
        Ok(vk)
    }

    /// The entry's KEM public key, checked against its kind and key ID.
    pub fn kem_public_key(&self) -> Result<KemPublicKey, RecordError> {
        if self.kind.is_signing() {
            return Err(RecordError::Malformed);
        }
        let pk = KemPublicKey::from_kind_bytes(self.kind.key_kind(), &self.public_key)
            .map_err(|_| RecordError::Malformed)?;
        if pk.key_id() != self.key_id {
            return Err(RecordError::Malformed);
        }
        Ok(pk)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgRecord {
    pub v: u32,
    pub org_id: String,
    pub display_name: String,
    pub domain: String,
    pub idp_issuer: String,
    pub key_agent_url: Option<String>,
    pub keys: Vec<KeyEntry>,
    pub issued_at: i64,
    /// A company or a personal account.
    #[serde(default)]
    pub kind: OrgKind,
    /// A personal account's verified email: the registry signs the binding
    /// between this email and the keys above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_email: Option<String>,
}

impl OrgRecord {
    /// Add this org's usable (active or retired) signing keys, classical
    /// and hybrid, to `trust`.
    pub fn add_signing_keys_to(&self, trust: &mut TrustStore) -> Result<(), RecordError> {
        let org = Identifier::new(&self.org_id).map_err(|_| RecordError::Malformed)?;
        for k in &self.keys {
            if k.kind.is_signing() && k.status != KeyStatus::Revoked {
                trust.add(org.clone(), k.verifying_key()?);
            }
        }
        Ok(())
    }

    /// The org's active SVX-2 (MLKEM1024-P384) KEM key, where new artifacts
    /// are sealed. Older X-Wing and X25519 keys only open older files.
    pub fn active_kem_key(&self) -> Option<&KeyEntry> {
        self.keys
            .iter()
            .find(|k| k.kind == KeyKindWire::MlKem1024P384 && k.status == KeyStatus::Active)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOrgRecord {
    #[serde(with = "b64")]
    pub record: Vec<u8>,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecordError {
    #[error("registry record signature invalid")]
    BadSignature,
    #[error("registry record malformed")]
    Malformed,
    #[error("registry record is for a different organization")]
    WrongOrg,
    #[error("registry record is stale")]
    Stale,
    #[error("the service's registry key does not match the pinned fingerprint")]
    WrongRegistryKey,
}

/// Records older than this are refused, so a captured record cannot be
/// replayed indefinitely to resurrect a revoked key.
pub const MAX_RECORD_AGE_SECS: i64 = 15 * 60;

impl SignedOrgRecord {
    /// Sign with the registry key (a post-quantum key; others are refused).
    pub fn sign(record: &OrgRecord, registry_key: &SigningKey) -> Result<Self, CryptoError> {
        let bytes = serde_json::to_vec(record).expect("record serializes");
        let signature = sign_context(registry_key, SignContext::RegistryRecord, &bytes)?;
        Ok(SignedOrgRecord {
            record: bytes,
            signature,
        })
    }

    pub fn verify(
        &self,
        registry_key: &VerifyingKey,
        expected_org: &str,
        now: i64,
    ) -> Result<OrgRecord, RecordError> {
        verify_context(
            registry_key,
            SignContext::RegistryRecord,
            &self.record,
            &self.signature,
        )
        .map_err(|_| RecordError::BadSignature)?;
        let r: OrgRecord =
            serde_json::from_slice(&self.record).map_err(|_| RecordError::Malformed)?;
        if r.v != crate::PROTOCOL_VERSION {
            return Err(RecordError::Malformed);
        }
        if r.org_id != expected_org {
            return Err(RecordError::WrongOrg);
        }
        if now - r.issued_at > MAX_RECORD_AGE_SECS || r.issued_at - now > 60 {
            return Err(RecordError::Stale);
        }
        Ok(r)
    }

    /// Verify a directory answer (`GET /v1/directory?email=`): a signed
    /// record of a personal account whose verified email is `email`
    /// (compared case-insensitively).
    pub fn verify_for_email(
        &self,
        registry_key: &VerifyingKey,
        email: &str,
        now: i64,
    ) -> Result<OrgRecord, RecordError> {
        // Only to learn which org to expect; `verify` checks the signature.
        let org = serde_json::from_slice::<OrgRecord>(&self.record)
            .map_err(|_| RecordError::Malformed)?
            .org_id;
        let r = self.verify(registry_key, &org, now)?;
        let matches = r
            .account_email
            .as_deref()
            .is_some_and(|e| e.eq_ignore_ascii_case(email.trim()));
        if r.kind != OrgKind::Personal || !matches {
            return Err(RecordError::WrongOrg);
        }
        Ok(r)
    }
}

/// `GET /v1/service`: public keys of the managed service. Nothing here is
/// trusted by itself: clients accept `registry_public` only if it matches
/// the fingerprint they pinned ([`ServiceInfo::pinned_registry_key`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceInfo {
    pub service_id: String,
    /// The service's MLKEM1024-P384 KEM key.
    #[serde(with = "hex_vec")]
    pub kem_public: Vec<u8>,
    /// Max (Ed25519 + ML-DSA-87 + SLH-DSA) grant key.
    #[serde(with = "hex_vec")]
    pub grant_public: Vec<u8>,
    /// Max (Ed25519 + ML-DSA-87 + SLH-DSA) registry key.
    #[serde(with = "hex_vec")]
    pub registry_public: Vec<u8>,
    /// Fingerprint of `registry_public`, the value users pin.
    #[serde(with = "hex_array")]
    pub registry_fingerprint: [u8; 32],
}

impl ServiceInfo {
    /// The registry key, if it is a Max key whose fingerprint is `pinned`.
    pub fn pinned_registry_key(&self, pinned: &[u8; 32]) -> Result<VerifyingKey, RecordError> {
        let key = VerifyingKey::from_kind_bytes(KeyKind::MaxSigning, &self.registry_public)
            .map_err(|_| RecordError::Malformed)?;
        if &key.fingerprint() != pinned {
            return Err(RecordError::WrongRegistryKey);
        }
        Ok(key)
    }
}

/// `GET /v1/service/record`: the service's public keys, signed with the
/// registry key. Senders use it to learn the service KEM key safely; they
/// pin only the registry key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRecord {
    pub v: u32,
    pub service_id: String,
    /// The service's active MLKEM1024-P384 KEM key, where new artifacts seal
    /// the service share. Older X-Wing and X25519 keys stay with the service
    /// to open older files and are not published.
    #[serde(with = "hex_vec")]
    pub kem_public: Vec<u8>,
    /// The service's Max (Ed25519 + ML-DSA-87 + SLH-DSA) grant key.
    #[serde(with = "hex_vec")]
    pub grant_public: Vec<u8>,
    pub issued_at: i64,
    /// Sign-in providers for personal accounts (Google).
    #[serde(default)]
    pub personal_idps: Vec<PersonalIdp>,
}

impl ServiceRecord {
    /// The service KEM key (always MLKEM1024-P384).
    pub fn kem_public_key(&self) -> Result<KemPublicKey, RecordError> {
        KemPublicKey::from_kind_bytes(KeyKind::MaxKem, &self.kem_public)
            .map_err(|_| RecordError::Malformed)
    }

    /// The service grant key (always a Max key).
    pub fn grant_key(&self) -> Result<VerifyingKey, RecordError> {
        VerifyingKey::from_kind_bytes(KeyKind::MaxSigning, &self.grant_public)
            .map_err(|_| RecordError::Malformed)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedServiceRecord {
    #[serde(with = "b64")]
    pub record: Vec<u8>,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

impl SignedServiceRecord {
    /// Sign with the registry key (a hybrid key; others are refused).
    pub fn sign(record: &ServiceRecord, registry_key: &SigningKey) -> Result<Self, CryptoError> {
        let bytes = serde_json::to_vec(record).expect("record serializes");
        let signature = sign_context(registry_key, SignContext::ServiceRecord, &bytes)?;
        Ok(SignedServiceRecord {
            record: bytes,
            signature,
        })
    }

    pub fn verify(
        &self,
        registry_key: &VerifyingKey,
        now: i64,
    ) -> Result<ServiceRecord, RecordError> {
        verify_context(
            registry_key,
            SignContext::ServiceRecord,
            &self.record,
            &self.signature,
        )
        .map_err(|_| RecordError::BadSignature)?;
        let r: ServiceRecord =
            serde_json::from_slice(&self.record).map_err(|_| RecordError::Malformed)?;
        if r.v != crate::PROTOCOL_VERSION {
            return Err(RecordError::Malformed);
        }
        if now - r.issued_at > MAX_RECORD_AGE_SECS || r.issued_at - now > 60 {
            return Err(RecordError::Stale);
        }
        r.kem_public_key()?;
        r.grant_key()?;
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use svx_core::crypto::{KemSecretKey, os_rng};

    fn grant() -> Vec<u8> {
        SigningKey::generate_max(&mut os_rng())
            .verifying_key()
            .to_vec()
    }

    fn entry(kind: KeyKindWire, public_key: Vec<u8>, status: KeyStatus) -> KeyEntry {
        KeyEntry {
            key_id: kind.key_id_of(&public_key).unwrap(),
            kind,
            public_key,
            status,
        }
    }

    #[test]
    fn record_sign_verify() {
        let reg = SigningKey::generate_max(&mut os_rng());
        let classical = SigningKey::generate(&mut os_rng()).verifying_key();
        let hybrid = SigningKey::generate_hybrid(&mut os_rng()).verifying_key();
        let max = SigningKey::generate_max(&mut os_rng()).verifying_key();
        let rec = OrgRecord {
            v: crate::PROTOCOL_VERSION,
            org_id: "acme-security".into(),
            display_name: "Acme Security".into(),
            domain: "acme.example".into(),
            idp_issuer: "https://idp.acme.example".into(),
            key_agent_url: None,
            keys: vec![
                entry(KeyKindWire::Ed25519, classical.to_vec(), KeyStatus::Retired),
                entry(
                    KeyKindWire::Ed25519Mldsa65,
                    hybrid.to_vec(),
                    KeyStatus::Retired,
                ),
                entry(KeyKindWire::Max, max.to_vec(), KeyStatus::Active),
            ],
            issued_at: 1000,
            kind: Default::default(),
            account_email: None,
        };
        let s = SignedOrgRecord::sign(&rec, &reg).unwrap();
        let got = s
            .verify(&reg.verifying_key(), "acme-security", 1001)
            .unwrap();
        let mut t = TrustStore::new();
        got.add_signing_keys_to(&mut t).unwrap();
        let org = Identifier::new("acme-security").unwrap();
        assert_eq!(t.resolve(&org, &classical.key_id()).unwrap(), &classical);
        assert_eq!(t.resolve(&org, &hybrid.key_id()).unwrap(), &hybrid);
        assert_eq!(t.resolve(&org, &max.key_id()).unwrap(), &max);
        assert_eq!(
            s.verify(&reg.verifying_key(), "example-corp", 1001),
            Err(RecordError::WrongOrg)
        );
        assert_eq!(
            s.verify(&reg.verifying_key(), "acme-security", 1000 + 3600),
            Err(RecordError::Stale)
        );
        let other = SigningKey::generate_max(&mut os_rng());
        assert_eq!(
            s.verify(&other.verifying_key(), "acme-security", 1001),
            Err(RecordError::BadSignature)
        );
    }

    #[test]
    fn service_record_sign_verify() {
        let reg = SigningKey::generate_max(&mut os_rng());
        let kem = KemSecretKey::generate_max(&mut os_rng());
        let rec = ServiceRecord {
            v: crate::PROTOCOL_VERSION,
            service_id: "svx.example".into(),
            kem_public: kem.public_key().to_vec(),
            grant_public: grant(),
            issued_at: 1000,
            personal_idps: vec![],
        };
        let s = SignedServiceRecord::sign(&rec, &reg).unwrap();
        assert_eq!(s.verify(&reg.verifying_key(), 1001).unwrap(), rec);
        assert_eq!(
            s.verify(&reg.verifying_key(), 5000),
            Err(RecordError::Stale)
        );
        let other = SigningKey::generate_max(&mut os_rng());
        assert_eq!(
            s.verify(&other.verifying_key(), 1001),
            Err(RecordError::BadSignature)
        );
        // An org-record signature is not a service-record signature.
        let as_org = SignedOrgRecord {
            record: s.record.clone(),
            signature: s.signature.clone(),
        };
        assert!(
            as_org
                .verify(&reg.verifying_key(), "svx.example", 1001)
                .is_err()
        );
    }

    #[test]
    fn service_record_requires_an_svx2_kem_key() {
        let reg = SigningKey::generate_max(&mut os_rng());
        for old in [
            KemSecretKey::generate(&mut os_rng()),
            KemSecretKey::generate_hybrid(&mut os_rng()),
        ] {
            let rec = ServiceRecord {
                v: crate::PROTOCOL_VERSION,
                service_id: "svx.example".into(),
                kem_public: old.public_key().to_vec(),
                grant_public: grant(),
                issued_at: 1000,
                personal_idps: vec![],
            };
            let s = SignedServiceRecord::sign(&rec, &reg).unwrap();
            assert_eq!(
                s.verify(&reg.verifying_key(), 1001),
                Err(RecordError::Malformed)
            );
        }
    }

    #[test]
    fn key_entries_are_checked() {
        let hybrid_kem = KemSecretKey::generate_hybrid(&mut os_rng());
        let pk = hybrid_kem.public_key().to_vec();
        let good = entry(KeyKindWire::XWing, pk.clone(), KeyStatus::Active);
        assert_eq!(good.kem_public_key().unwrap(), *hybrid_kem.public_key());
        // The wrong kind, a truncated key, a mismatched key ID: all refused.
        assert!(good.verifying_key().is_err());
        let mut bad = good.clone();
        bad.kind = KeyKindWire::X25519;
        assert!(bad.kem_public_key().is_err());
        let mut bad = good.clone();
        bad.public_key.truncate(32);
        assert!(bad.kem_public_key().is_err());
        let mut bad = good.clone();
        bad.key_id[0] ^= 1;
        assert!(bad.kem_public_key().is_err());
        assert_eq!(KeyKindWire::XWing.key_id_of(&pk[..1215]), None);
        assert_eq!(KeyKindWire::Ed25519Mldsa65.key_id_of(&pk), None);
        // The wire names round-trip.
        let max_kem = KemSecretKey::generate_max(&mut os_rng())
            .public_key()
            .to_vec();
        let e = entry(
            KeyKindWire::MlKem1024P384,
            max_kem.clone(),
            KeyStatus::Active,
        );
        e.kem_public_key().unwrap();
        assert_eq!(KeyKindWire::XWing.key_id_of(&max_kem), None);
        assert!(KeyKindWire::MlKem1024P384.is_current() && !KeyKindWire::XWing.is_current());
        assert!(KeyKindWire::Max.is_signing() && !KeyKindWire::MlKem1024P384.is_signing());
        for k in [
            KeyKindWire::Ed25519,
            KeyKindWire::X25519,
            KeyKindWire::XWing,
            KeyKindWire::Ed25519Mldsa65,
            KeyKindWire::MlKem1024P384,
            KeyKindWire::Max,
        ] {
            assert_eq!(KeyKindWire::parse(k.as_str()), Some(k));
            let json = serde_json::to_string(&k).unwrap();
            assert_eq!(json, format!("\"{}\"", k.as_str()));
            assert_eq!(KeyKindWire::from_key_kind(k.key_kind()), k);
        }
    }

    #[test]
    fn records_of_another_protocol_version_are_refused() {
        let reg = SigningKey::generate_max(&mut os_rng());
        let rec = OrgRecord {
            v: 2,
            org_id: "acme-security".into(),
            display_name: "Acme Security".into(),
            domain: "acme.example".into(),
            idp_issuer: "https://idp.acme.example".into(),
            key_agent_url: None,
            keys: vec![],
            issued_at: 1000,
            kind: Default::default(),
            account_email: None,
        };
        let s = SignedOrgRecord::sign(&rec, &reg).unwrap();
        assert_eq!(
            s.verify(&reg.verifying_key(), "acme-security", 1001),
            Err(RecordError::Malformed)
        );
    }

    #[test]
    fn classical_registry_keys_are_refused() {
        let ed = SigningKey::generate(&mut os_rng());
        let rec = ServiceRecord {
            v: crate::PROTOCOL_VERSION,
            service_id: "svx.example".into(),
            kem_public: KemSecretKey::generate_max(&mut os_rng())
                .public_key()
                .to_vec(),
            grant_public: grant(),
            issued_at: 1000,
            personal_idps: vec![],
        };
        assert!(SignedServiceRecord::sign(&rec, &ed).is_err());
        // An Ed25519-only signature under a Max key: refused.
        let reg = SigningKey::generate_max(&mut os_rng());
        let mut s = SignedServiceRecord::sign(&rec, &reg).unwrap();
        s.signature.truncate(64);
        assert_eq!(
            s.verify(&reg.verifying_key(), 1001),
            Err(RecordError::BadSignature)
        );
        // A classical grant key in the record: malformed.
        let mut classical_grant = rec.clone();
        classical_grant.grant_public = ed.verifying_key().to_vec();
        let s = SignedServiceRecord::sign(&classical_grant, &reg).unwrap();
        assert_eq!(
            s.verify(&reg.verifying_key(), 1001),
            Err(RecordError::Malformed)
        );
    }

    #[test]
    fn registry_key_must_match_the_pinned_fingerprint() {
        let reg = SigningKey::generate_max(&mut os_rng()).verifying_key();
        let info = ServiceInfo {
            service_id: "svx.example".into(),
            kem_public: vec![],
            grant_public: grant(),
            registry_public: reg.to_vec(),
            registry_fingerprint: reg.fingerprint(),
        };
        assert_eq!(info.pinned_registry_key(&reg.fingerprint()).unwrap(), reg);
        let mut wrong = reg.fingerprint();
        wrong[31] ^= 1;
        assert_eq!(
            info.pinned_registry_key(&wrong),
            Err(RecordError::WrongRegistryKey)
        );
        // The advertised fingerprint is not trusted: only the pin counts.
        let other = SigningKey::generate_max(&mut os_rng()).verifying_key();
        let swapped = ServiceInfo {
            registry_public: other.to_vec(),
            ..info.clone()
        };
        assert_eq!(
            swapped.pinned_registry_key(&reg.fingerprint()),
            Err(RecordError::WrongRegistryKey)
        );
        // A v3 hybrid registry key no longer matches.
        let hybrid = SigningKey::generate_hybrid(&mut os_rng()).verifying_key();
        let v3 = ServiceInfo {
            registry_public: hybrid.to_vec(),
            ..info.clone()
        };
        assert_eq!(
            v3.pinned_registry_key(&hybrid.fingerprint()),
            Err(RecordError::Malformed)
        );
        // A classical registry key never matches.
        let ed = SigningKey::generate(&mut os_rng()).verifying_key();
        let classical = ServiceInfo {
            registry_public: ed.to_vec(),
            ..info
        };
        assert_eq!(
            classical.pinned_registry_key(&ed.fingerprint()),
            Err(RecordError::Malformed)
        );
    }

    #[test]
    fn status_transitions() {
        use KeyStatus::*;
        assert!(Active.can_become(Retired));
        assert!(Active.can_become(Revoked));
        assert!(Retired.can_become(Revoked));
        assert!(!Retired.can_become(Active));
        assert!(!Revoked.can_become(Active));
        assert!(!Revoked.can_become(Retired));
    }
}
