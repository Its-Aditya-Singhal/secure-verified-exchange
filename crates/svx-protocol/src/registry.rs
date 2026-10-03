//! Signed organization registry records.
//!
//! The registry is the managed service's statement of which keys and which
//! IdP belong to an organization. Clients pin the registry public key and
//! accept sender signing keys only from a correctly signed, fresh record.

use serde::{Deserialize, Serialize};
use svx_core::TrustStore;
use svx_core::crypto::{SignContext, SigningKey, VerifyingKey, sign_context, verify_context};
use svx_core::format::Identifier;

use crate::encoding::{b64, hex_array};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyKindWire {
    /// Ed25519 artifact signing key.
    Ed25519,
    /// X25519 HPKE key-agreement key.
    X25519,
}

impl KeyKindWire {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyKindWire::Ed25519 => "ed25519",
            KeyKindWire::X25519 => "x25519",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ed25519" => Some(KeyKindWire::Ed25519),
            "x25519" => Some(KeyKindWire::X25519),
            _ => None,
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
    #[serde(with = "hex_array")]
    pub public_key: [u8; 32],
    pub status: KeyStatus,
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
    /// Add this org's usable (active or retired) signing keys to `trust`.
    pub fn add_signing_keys_to(&self, trust: &mut TrustStore) -> Result<(), RecordError> {
        let org = Identifier::new(&self.org_id).map_err(|_| RecordError::Malformed)?;
        for k in &self.keys {
            if k.kind == KeyKindWire::Ed25519 && k.status != KeyStatus::Revoked {
                let vk =
                    VerifyingKey::from_bytes(&k.public_key).map_err(|_| RecordError::Malformed)?;
                if vk.key_id() != k.key_id {
                    return Err(RecordError::Malformed);
                }
                trust.add(org.clone(), vk);
            }
        }
        Ok(())
    }

    /// The org's active KEM public key (where new artifacts are sealed).
    pub fn active_kem_key(&self) -> Option<&KeyEntry> {
        self.keys
            .iter()
            .find(|k| k.kind == KeyKindWire::X25519 && k.status == KeyStatus::Active)
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
    #[serde(with = "hex_array")]
    pub kem_public: [u8; 32],
    #[serde(with = "hex_array")]
    pub grant_public: [u8; 32],
    #[serde(with = "hex_array")]
    pub registry_public: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    use svx_core::crypto::os_rng;

    #[test]
    fn record_sign_verify() {
        let reg = SigningKey::generate(&mut os_rng());
        let org_sign = SigningKey::generate(&mut os_rng());
        let vk = org_sign.verifying_key();
        let rec = OrgRecord {
            v: 1,
            org_id: "acme-security".into(),
            display_name: "Acme Security".into(),
            domain: "acme.example".into(),
            idp_issuer: "https://idp.acme.example".into(),
            key_agent_url: None,
            keys: vec![KeyEntry {
                key_id: vk.key_id(),
                kind: KeyKindWire::Ed25519,
                public_key: vk.to_bytes(),
                status: KeyStatus::Active,
            }],
            issued_at: 1000,
        };
        let s = SignedOrgRecord::sign(&rec, &reg);
        let got = s
            .verify(&reg.verifying_key(), "acme-security", 1001)
            .unwrap();
        let mut t = TrustStore::new();
        got.add_signing_keys_to(&mut t).unwrap();
        assert!(!t.is_empty());
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
