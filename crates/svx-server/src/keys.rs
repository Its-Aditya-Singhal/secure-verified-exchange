//! The service's own secret keys, behind [`KeyProvider`] so that a KMS/HSM
//! implementation (where secrets never enter process memory) can replace
//! [`LocalKeys`] without touching handlers.

use std::path::Path;

use anyhow::bail;
use svx_core::crypto::{
    CryptoError, KemPublicKey, KemSecretKey, KeyKind, Share, SigningKey, VerifyingKey,
};
use svx_core::format::EnvelopeRole;
use svx_core::{CoreError, VerifiedHead, keyfile};
use svx_protocol::{
    Grant, OrgRecord, ServiceRecord, SignedGrant, SignedOrgRecord, SignedServiceRecord,
};

pub trait KeyProvider: Send + Sync {
    /// The active X-Wing (X25519 + ML-KEM-768) key new artifacts seal the
    /// service share to.
    fn service_kem_public(&self) -> KemPublicKey;
    fn grant_public(&self) -> VerifyingKey;
    fn registry_public(&self) -> VerifyingKey;
    /// Unwrap the service's key-share envelope of a verified artifact.
    fn unwrap_service_share(&self, head: &VerifiedHead) -> Result<Share, CoreError>;
    /// Hybrid (Ed25519 + ML-DSA-65) signatures with the grant and registry keys.
    fn sign_grant(&self, grant: &Grant) -> Result<SignedGrant, CryptoError>;
    fn sign_record(&self, record: &OrgRecord) -> Result<SignedOrgRecord, CryptoError>;
    fn sign_service_record(
        &self,
        record: &ServiceRecord,
    ) -> Result<SignedServiceRecord, CryptoError>;
}

/// Keys held in process memory, loaded from 0600 key files.
pub struct LocalKeys {
    /// Every KEM key the service still opens envelopes with, chosen per
    /// artifact by key ID: the X-Wing key and any older X25519 keys.
    kems: Vec<KemSecretKey>,
    /// Index into `kems` of the active X-Wing key.
    active: usize,
    grant: SigningKey,
    registry: SigningKey,
}

impl LocalKeys {
    /// `kems` must hold an X-Wing key; the first one is published for new
    /// artifacts. X25519 keys only open older (suite SVX-1) files.
    pub fn new(
        kems: Vec<KemSecretKey>,
        grant: SigningKey,
        registry: SigningKey,
    ) -> anyhow::Result<Self> {
        let Some(active) = kems.iter().position(|k| k.kind() == KeyKind::XWingKem) else {
            bail!("the service needs an X-Wing (post-quantum hybrid) KEM key");
        };
        if grant.kind() != KeyKind::HybridSigning || registry.kind() != KeyKind::HybridSigning {
            bail!(
                "grant and registry keys must be post-quantum hybrid keys \
                 (Ed25519 + ML-DSA-65, svx keygen --kind sign)"
            );
        }
        Ok(LocalKeys {
            kems,
            active,
            grant,
            registry,
        })
    }

    pub fn load(kems: &[impl AsRef<Path>], grant: &Path, registry: &Path) -> anyhow::Result<Self> {
        let kems = kems
            .iter()
            .map(|p| Ok(keyfile::load_kem_secret(p.as_ref())?.1))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Self::new(
            kems,
            keyfile::load_signing_key(grant)?.1,
            keyfile::load_signing_key(registry)?.1,
        )
    }
}

impl KeyProvider for LocalKeys {
    fn service_kem_public(&self) -> KemPublicKey {
        self.kems[self.active].public_key().clone()
    }

    fn grant_public(&self) -> VerifyingKey {
        self.grant.verifying_key()
    }

    fn registry_public(&self) -> VerifyingKey {
        self.registry.verifying_key()
    }

    fn unwrap_service_share(&self, head: &VerifiedHead) -> Result<Share, CoreError> {
        head.unwrap_share_from(EnvelopeRole::Service, &self.kems)
    }

    fn sign_grant(&self, grant: &Grant) -> Result<SignedGrant, CryptoError> {
        SignedGrant::sign(grant, &self.grant)
    }

    fn sign_record(&self, record: &OrgRecord) -> Result<SignedOrgRecord, CryptoError> {
        SignedOrgRecord::sign(record, &self.registry)
    }

    fn sign_service_record(
        &self,
        record: &ServiceRecord,
    ) -> Result<SignedServiceRecord, CryptoError> {
        SignedServiceRecord::sign(record, &self.registry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use svx_core::crypto::os_rng;

    #[test]
    fn key_kinds_are_checked() {
        let mut rng = os_rng();
        let ed = || SigningKey::generate(&mut os_rng());
        // No X-Wing key: refused.
        assert!(LocalKeys::new(vec![KemSecretKey::generate(&mut rng)], ed(), ed()).is_err());
        // Classical grant or registry keys: refused (service signatures are hybrid).
        let xwing = || vec![KemSecretKey::generate_hybrid(&mut os_rng())];
        let hybrid = || SigningKey::generate_hybrid(&mut os_rng());
        assert!(LocalKeys::new(xwing(), hybrid(), ed()).is_err());
        assert!(LocalKeys::new(xwing(), ed(), hybrid()).is_err());
        assert!(LocalKeys::new(xwing(), ed(), ed()).is_err());
        // An X25519 key for older files plus an X-Wing key: the X-Wing key is published.
        let classical = KemSecretKey::generate(&mut rng);
        let pq = KemSecretKey::generate_hybrid(&mut rng);
        let pq_pub = pq.public_key().clone();
        let keys = LocalKeys::new(vec![classical, pq], hybrid(), hybrid()).unwrap();
        assert_eq!(keys.service_kem_public(), pq_pub);
        assert_eq!(keys.registry_public().kind(), KeyKind::HybridSigning);
    }
}
