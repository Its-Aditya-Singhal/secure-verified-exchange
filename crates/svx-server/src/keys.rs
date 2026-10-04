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
    /// The active MLKEM1024-P384 (suite SVX-2) key new artifacts seal the
    /// service share to.
    fn service_kem_public(&self) -> KemPublicKey;
    fn grant_public(&self) -> VerifyingKey;
    fn registry_public(&self) -> VerifyingKey;
    /// Unwrap the service's key-share envelope of a verified artifact.
    fn unwrap_service_share(&self, head: &VerifiedHead) -> Result<Share, CoreError>;
    /// Max (Ed25519 + ML-DSA-87 + SLH-DSA) signatures with the grant and
    /// registry keys: all three parts on records, Ed25519 + ML-DSA-87 on grants.
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
    /// artifact by key ID: the MLKEM1024-P384 key and any older X-Wing or
    /// X25519 keys.
    kems: Vec<KemSecretKey>,
    /// Index into `kems` of the active MLKEM1024-P384 key.
    active: usize,
    grant: SigningKey,
    registry: SigningKey,
}

impl LocalKeys {
    /// `kems` must hold an MLKEM1024-P384 key; the first one is published
    /// for new artifacts. X-Wing and X25519 keys only open older (SVX-1H and
    /// SVX-1) files.
    pub fn new(
        kems: Vec<KemSecretKey>,
        grant: SigningKey,
        registry: SigningKey,
    ) -> anyhow::Result<Self> {
        let Some(active) = kems.iter().position(|k| k.kind() == KeyKind::MaxKem) else {
            bail!(
                "the service needs an MLKEM1024-P384 (suite SVX-2) KEM key (svx keygen --kind kem)"
            );
        };
        if grant.kind() != KeyKind::MaxSigning || registry.kind() != KeyKind::MaxSigning {
            bail!(
                "grant and registry keys must be SVX-2 keys \
                 (Ed25519 + ML-DSA-87 + SLH-DSA, svx keygen --kind sign)"
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
        let hybrid = || SigningKey::generate_hybrid(&mut os_rng());
        let max = || SigningKey::generate_max(&mut os_rng());
        let max_kem = || vec![KemSecretKey::generate_max(&mut os_rng())];
        // No MLKEM1024-P384 key (only X-Wing): refused.
        assert!(
            LocalKeys::new(vec![KemSecretKey::generate_hybrid(&mut rng)], max(), max()).is_err()
        );
        // Older grant or registry keys: refused (service signatures are SVX-2).
        assert!(LocalKeys::new(max_kem(), max(), hybrid()).is_err());
        assert!(LocalKeys::new(max_kem(), hybrid(), max()).is_err());
        assert!(LocalKeys::new(max_kem(), SigningKey::generate(&mut rng), max()).is_err());
        // Older keys for older files plus an SVX-2 key: the SVX-2 key is published.
        let classical = KemSecretKey::generate(&mut rng);
        let xwing = KemSecretKey::generate_hybrid(&mut rng);
        let current = KemSecretKey::generate_max(&mut rng);
        let current_pub = current.public_key().clone();
        let keys = LocalKeys::new(vec![classical, xwing, current], max(), max()).unwrap();
        assert_eq!(keys.service_kem_public(), current_pub);
        assert_eq!(keys.registry_public().kind(), KeyKind::MaxSigning);
    }
}
