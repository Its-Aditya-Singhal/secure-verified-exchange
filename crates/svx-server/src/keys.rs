//! The service's own secret keys, behind [`KeyProvider`] so that a KMS/HSM
//! implementation (where secrets never enter process memory) can replace
//! [`LocalKeys`] without touching handlers.

use std::path::Path;

use svx_core::crypto::{KemPublicKey, KemSecretKey, Share, SigningKey, VerifyingKey};
use svx_core::format::EnvelopeRole;
use svx_core::{CoreError, VerifiedHead, keyfile};
use svx_protocol::{Grant, OrgRecord, SignedGrant, SignedOrgRecord};

pub trait KeyProvider: Send + Sync {
    fn service_kem_public(&self) -> KemPublicKey;
    fn grant_public(&self) -> VerifyingKey;
    fn registry_public(&self) -> VerifyingKey;
    /// Unwrap the service's key-share envelope of a verified artifact.
    fn unwrap_service_share(&self, head: &VerifiedHead) -> Result<Share, CoreError>;
    fn sign_grant(&self, grant: &Grant) -> SignedGrant;
    fn sign_record(&self, record: &OrgRecord) -> SignedOrgRecord;
}

/// Keys held in process memory, loaded from 0600 key files.
pub struct LocalKeys {
    kem: KemSecretKey,
    grant: SigningKey,
    registry: SigningKey,
}

impl LocalKeys {
    pub fn new(kem: KemSecretKey, grant: SigningKey, registry: SigningKey) -> Self {
        LocalKeys {
            kem,
            grant,
            registry,
        }
    }

    pub fn load(kem: &Path, grant: &Path, registry: &Path) -> anyhow::Result<Self> {
        Ok(LocalKeys {
            kem: keyfile::load_kem_secret(kem)?.1,
            grant: keyfile::load_signing_key(grant)?.1,
            registry: keyfile::load_signing_key(registry)?.1,
        })
    }
}

impl KeyProvider for LocalKeys {
    fn service_kem_public(&self) -> KemPublicKey {
        self.kem.public_key().clone()
    }

    fn grant_public(&self) -> VerifyingKey {
        self.grant.verifying_key()
    }

    fn registry_public(&self) -> VerifyingKey {
        self.registry.verifying_key()
    }

    fn unwrap_service_share(&self, head: &VerifiedHead) -> Result<Share, CoreError> {
        head.unwrap_share(EnvelopeRole::Service, &self.kem)
    }

    fn sign_grant(&self, grant: &Grant) -> SignedGrant {
        SignedGrant::sign(grant, &self.grant)
    }

    fn sign_record(&self, record: &OrgRecord) -> SignedOrgRecord {
        SignedOrgRecord::sign(record, &self.registry)
    }
}
