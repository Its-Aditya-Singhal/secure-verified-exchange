//! Verified registry lookups (all signatures checked against the pinned
//! registry key).

use svx_core::TrustStore;
use svx_core::crypto::{KemPublicKey, VerifyingKey};
use svx_protocol::{ManagedClient, OrgRecord, ServiceRecord};

use crate::config::ClientConfig;
use crate::error::{ClientError, Result};

pub struct Registry<'a> {
    pub client: &'a ManagedClient,
    pub service_url: &'a str,
    pub key: VerifyingKey,
}

impl<'a> Registry<'a> {
    pub fn new(cfg: &'a ClientConfig, client: &'a ManagedClient) -> Result<Self> {
        Ok(Registry {
            client,
            service_url: &cfg.service_url,
            key: cfg.registry_key()?,
        })
    }

    pub async fn org(&self, org: &str) -> Result<OrgRecord> {
        Ok(self
            .client
            .org_record(self.service_url, org, &self.key)
            .await?)
    }

    pub async fn service(&self) -> Result<ServiceRecord> {
        Ok(self
            .client
            .service_record(self.service_url, &self.key)
            .await?)
    }

    /// Trust store with the sender org's non-revoked signing keys.
    pub async fn sender_trust(&self, sender_org: &str) -> Result<TrustStore> {
        let mut t = TrustStore::new();
        self.org(sender_org)
            .await?
            .add_signing_keys_to(&mut t)
            .map_err(|e| ClientError::Other(e.to_string()))?;
        Ok(t)
    }
}

/// The org's active SVX-2 (MLKEM1024-P384) key, where new artifacts must be
/// sealed. There is no fallback to an older key.
pub fn active_kem_key(rec: &OrgRecord) -> Result<KemPublicKey> {
    let k = rec.active_kem_key().ok_or_else(|| {
        ClientError::Config(format!(
            "{} has no active SVX-2 encryption key (mlkem1024-p384); its administrator must \
             create a new encryption key before it can receive files",
            rec.org_id
        ))
    })?;
    k.kem_public_key()
        .map_err(|_| ClientError::Other("invalid encryption key in registry record".into()))
}
