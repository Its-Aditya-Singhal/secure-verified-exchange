//! Sender trust store: which organizations' signing keys are accepted.
//!
//! In Phase 1 this is populated from local public key files. In Managed Mode
//! it is populated from the organization registry, whose records are
//! themselves signed (see `docs/architecture.md`).

use std::collections::BTreeMap;

use svx_crypto::VerifyingKey;
use svx_format::Identifier;

use crate::error::{CoreError, Result};

#[derive(Clone, Debug, Default)]
pub struct TrustStore {
    keys: BTreeMap<(Identifier, [u8; 16]), VerifyingKey>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Trust `key` as a signing key of `org`.
    pub fn add(&mut self, org: Identifier, key: VerifyingKey) -> &mut Self {
        self.keys.insert((org, key.key_id()), key);
        self
    }

    /// Find the key for `(org, key_id)`. Both must match: a valid signature
    /// from a key trusted for a *different* organization is rejected.
    pub fn resolve(&self, org: &Identifier, key_id: &[u8; 16]) -> Result<&VerifyingKey> {
        self.keys
            .get(&(org.clone(), *key_id))
            .ok_or_else(|| CoreError::UntrustedSender {
                org: org.to_string(),
                key_id: hex::encode(key_id),
            })
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}
