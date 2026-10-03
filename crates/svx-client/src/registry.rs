//! Verified registry lookups (all signatures checked against the pinned
//! registry key).

use svx_core::TrustStore;
use svx_core::crypto::{KemPublicKey, VerifyingKey};
use svx_protocol::{KeyKindWire, KeyStatus, ManagedClient, OrgRecord, ServiceRecord};

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

/// The org's active KEM key, where new artifacts must be sealed.
pub fn active_kem_key(rec: &OrgRecord) -> Result<KemPublicKey> {
    let k = rec
        .keys
        .iter()
        .find(|k| k.kind == KeyKindWire::X25519 && k.status == KeyStatus::Active)
        .ok_or_else(|| {
            ClientError::Config(format!("{} has no active encryption key", rec.org_id))
        })?;
    let pk = KemPublicKey::from_bytes(&k.public_key)
        .map_err(|_| ClientError::Other("invalid KEM key in registry record".into()))?;
    if pk.key_id() != k.key_id {
        return Err(ClientError::Other("registry key_id mismatch".into()));
    }
    Ok(pk)
}
