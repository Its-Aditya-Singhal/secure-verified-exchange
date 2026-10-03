//! Signed organization registry records.
//!
//! The registry is the managed service's statement of which keys and which
//! IdP belong to an organization. Clients pin the registry public key and
//! accept sender signing keys only from a correctly signed, fresh record.

use serde::{Deserialize, Serialize};
use svx_core::TrustStore;
use svx_core::crypto::{
    KemPublicKey, KeyKind, SignContext, SigningKey, VerifyingKey, sign_context, verify_context,
};
use svx_core::format::Identifier;

use crate::encoding::{b64, hex_array, hex_vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyKindWire {
    /// Ed25519 artifact signing key (suite SVX-1; verifies older files).
    #[serde(rename = "ed25519")]
    Ed25519,
    /// X25519 HPKE key-agreement key (suite SVX-1; opens older files).
    #[serde(rename = "x25519")]
    X25519,
    /// X-Wing (X25519 + ML-KEM-768) HPKE key: where new files are sealed.
    #[serde(rename = "xwing")]
    XWing,
    /// Ed25519 + ML-DSA-65 composite signing key: signs new files.
    #[serde(rename = "ed25519-mldsa65")]
    Ed25519Mldsa65,
}

impl KeyKindWire {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyKindWire::Ed25519 => "ed25519",
            KeyKindWire::X25519 => "x25519",
            KeyKindWire::XWing => "xwing",
            KeyKindWire::Ed25519Mldsa65 => "ed25519-mldsa65",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ed25519" => Some(KeyKindWire::Ed25519),
            "x25519" => Some(KeyKindWire::X25519),
            "xwing" => Some(KeyKindWire::XWing),
            "ed25519-mldsa65" => Some(KeyKindWire::Ed25519Mldsa65),
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
        }
    }

    pub fn from_key_kind(kind: KeyKind) -> Self {
        match kind {
            KeyKind::Ed25519Signing => KeyKindWire::Ed25519,
            KeyKind::X25519Kem => KeyKindWire::X25519,
            KeyKind::XWingKem => KeyKindWire::XWing,
            KeyKind::HybridSigning => KeyKindWire::Ed25519Mldsa65,
        }
    }

    pub fn is_signing(self) -> bool {
        matches!(self, KeyKindWire::Ed25519 | KeyKindWire::Ed25519Mldsa65)
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
    /// ML-DSA-65) for hybrid keys.
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

    /// The org's active post-quantum hybrid (X-Wing) KEM key, where new
    /// artifacts are sealed. Classical X25519 keys only open older files.
    pub fn active_hybrid_kem_key(&self) -> Option<&KeyEntry> {
        self.keys
            .iter()
            .find(|k| k.kind == KeyKindWire::XWing && k.status == KeyStatus::Active)
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
}

/// Records older than this are refused, so a captured record cannot be
/// replayed indefinitely to resurrect a revoked key.
pub const MAX_RECORD_AGE_SECS: i64 = 15 * 60;

impl SignedOrgRecord {
    pub fn sign(record: &OrgRecord, registry_key: &SigningKey) -> Self {
        let bytes = serde_json::to_vec(record).expect("record serializes");
        let signature = sign_context(registry_key, SignContext::RegistryRecord, &bytes).to_vec();
        SignedOrgRecord {
            record: bytes,
            signature,
        }
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
}

/// `GET /v1/service`: public keys of the managed service.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceInfo {
    pub service_id: String,
    /// The service's X-Wing (X25519 + ML-KEM-768) KEM key.
    #[serde(with = "hex_vec")]
    pub kem_public: Vec<u8>,
    #[serde(with = "hex_array")]
    pub grant_public: [u8; 32],
    #[serde(with = "hex_array")]
    pub registry_public: [u8; 32],
}

/// `GET /v1/service/record`: the service's public keys, signed with the
/// registry key. Senders use it to learn the service KEM key safely; they
/// pin only the registry key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRecord {
    pub v: u32,
    pub service_id: String,
    /// The service's active X-Wing (X25519 + ML-KEM-768) KEM key, where new
    /// artifacts seal the service share. Older X25519 keys stay with the
    /// service to open older files and are not published.
    #[serde(with = "hex_vec")]
    pub kem_public: Vec<u8>,
    #[serde(with = "hex_array")]
    pub grant_public: [u8; 32],
    pub issued_at: i64,
}

impl ServiceRecord {
    /// The service KEM key (always X-Wing).
    pub fn kem_public_key(&self) -> Result<KemPublicKey, RecordError> {
        KemPublicKey::from_kind_bytes(KeyKind::XWingKem, &self.kem_public)
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
    pub fn sign(record: &ServiceRecord, registry_key: &SigningKey) -> Self {
        let bytes = serde_json::to_vec(record).expect("record serializes");
        let signature = sign_context(registry_key, SignContext::ServiceRecord, &bytes).to_vec();
        SignedServiceRecord {
            record: bytes,
            signature,
        }
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
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use svx_core::crypto::{KemSecretKey, os_rng};

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
        let reg = SigningKey::generate(&mut os_rng());
        let classical = SigningKey::generate(&mut os_rng()).verifying_key();
        let hybrid = SigningKey::generate_hybrid(&mut os_rng()).verifying_key();
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
                    KeyStatus::Active,
                ),
            ],
            issued_at: 1000,
        };
        let s = SignedOrgRecord::sign(&rec, &reg);
        let got = s
            .verify(&reg.verifying_key(), "acme-security", 1001)
            .unwrap();
        let mut t = TrustStore::new();
        got.add_signing_keys_to(&mut t).unwrap();
        let org = Identifier::new("acme-security").unwrap();
        assert_eq!(t.resolve(&org, &classical.key_id()).unwrap(), &classical);
        assert_eq!(t.resolve(&org, &hybrid.key_id()).unwrap(), &hybrid);
        assert_eq!(
            s.verify(&reg.verifying_key(), "example-corp", 1001),
            Err(RecordError::WrongOrg)
        );
        assert_eq!(
            s.verify(&reg.verifying_key(), "acme-security", 1000 + 3600),
            Err(RecordError::Stale)
        );
        let other = SigningKey::generate(&mut os_rng());
        assert_eq!(
            s.verify(&other.verifying_key(), "acme-security", 1001),
            Err(RecordError::BadSignature)
        );
    }

    #[test]
    fn service_record_sign_verify() {
        let reg = SigningKey::generate(&mut os_rng());
        let kem = KemSecretKey::generate_hybrid(&mut os_rng());
        let rec = ServiceRecord {
            v: crate::PROTOCOL_VERSION,
            service_id: "svx.example".into(),
            kem_public: kem.public_key().to_vec(),
            grant_public: [2; 32],
            issued_at: 1000,
        };
        let s = SignedServiceRecord::sign(&rec, &reg);
        assert_eq!(s.verify(&reg.verifying_key(), 1001).unwrap(), rec);
        assert_eq!(
            s.verify(&reg.verifying_key(), 5000),
            Err(RecordError::Stale)
        );
        let other = SigningKey::generate(&mut os_rng());
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
    fn service_record_requires_xwing_key() {
        let reg = SigningKey::generate(&mut os_rng());
        let classical = KemSecretKey::generate(&mut os_rng());
        let rec = ServiceRecord {
            v: crate::PROTOCOL_VERSION,
            service_id: "svx.example".into(),
            kem_public: classical.public_key().to_vec(),
            grant_public: [2; 32],
            issued_at: 1000,
        };
        let s = SignedServiceRecord::sign(&rec, &reg);
        assert_eq!(
            s.verify(&reg.verifying_key(), 1001),
            Err(RecordError::Malformed)
        );
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
        for k in [
            KeyKindWire::Ed25519,
            KeyKindWire::X25519,
            KeyKindWire::XWing,
            KeyKindWire::Ed25519Mldsa65,
        ] {
            assert_eq!(KeyKindWire::parse(k.as_str()), Some(k));
            let json = serde_json::to_string(&k).unwrap();
            assert_eq!(json, format!("\"{}\"", k.as_str()));
            assert_eq!(KeyKindWire::from_key_kind(k.key_kind()), k);
        }
    }

    #[test]
    fn records_of_another_protocol_version_are_refused() {
        let reg = SigningKey::generate(&mut os_rng());
        let rec = OrgRecord {
            v: 1,
            org_id: "acme-security".into(),
            display_name: "Acme Security".into(),
            domain: "acme.example".into(),
            idp_issuer: "https://idp.acme.example".into(),
            key_agent_url: None,
            keys: vec![],
            issued_at: 1000,
        };
        let s = SignedOrgRecord::sign(&rec, &reg);
        assert_eq!(
            s.verify(&reg.verifying_key(), "acme-security", 1001),
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
