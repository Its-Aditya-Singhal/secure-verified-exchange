//! Release grants.
//!
//! After authorizing a release, the managed service signs a grant that the
//! client presents to the recipient key agent. The agent pins the service's
//! grant key and independently validates the user's ID token, so it relies
//! on the service only for the *policy* decision, never for user identity.
//!
//! The signature covers the exact JSON payload bytes (no canonicalization),
//! under the `"SVX-1 grant\0"` signing context.

use serde::{Deserialize, Serialize};
use svx_core::crypto::{SignContext, SigningKey, VerifyingKey, sign_context, verify_context};

use crate::encoding::{b64, hex_array};

/// Upper bound on a grant payload.
const MAX_GRANT_LEN: usize = 8 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub v: u32,
    pub service_id: String,
    #[serde(with = "hex_array")]
    pub artifact_id: [u8; 16],
    /// Header hash of the artifact the service verified.
    #[serde(with = "hex_array")]
    pub header_hash: [u8; 32],
    pub recipient_org: String,
    /// `iss` and `sub` of the user the service authorized.
    pub issuer: String,
    pub sub: String,
    /// `key_id` of the client's ephemeral release key.
    #[serde(with = "hex_array")]
    pub client_key_id: [u8; 16],
    #[serde(with = "hex_array")]
    pub txn: [u8; 16],
    pub iat: i64,
    pub exp: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGrant {
    #[serde(with = "b64")]
    pub payload: Vec<u8>,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
    #[serde(with = "hex_array")]
    pub key_id: [u8; 16],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GrantError {
    #[error("grant signed by an unexpected key")]
    WrongKey,
    #[error("grant signature invalid")]
    BadSignature,
    #[error("grant malformed")]
    Malformed,
    #[error("grant expired or not yet valid")]
    Expired,
}

impl SignedGrant {
    pub fn sign(grant: &Grant, key: &SigningKey) -> Self {
        let payload = serde_json::to_vec(grant).expect("grant serializes");
        let signature = sign_context(key, SignContext::ReleaseGrant, &payload).to_vec();
        SignedGrant {
            payload,
            signature,
            key_id: key.verifying_key().key_id(),
        }
    }

    /// Verify the signature with the pinned service grant key, then parse
    /// and check the validity window against `now` (±30 s clock skew).
    pub fn verify(&self, key: &VerifyingKey, now: i64) -> Result<Grant, GrantError> {
        if self.key_id != key.key_id() {
            return Err(GrantError::WrongKey);
        }
        if self.payload.len() > MAX_GRANT_LEN {
            return Err(GrantError::Malformed);
        }
        verify_context(
            key,
            SignContext::ReleaseGrant,
            &self.payload,
            &self.signature,
        )
        .map_err(|_| GrantError::BadSignature)?;
        let g: Grant = serde_json::from_slice(&self.payload).map_err(|_| GrantError::Malformed)?;
        if g.v != crate::PROTOCOL_VERSION {
            return Err(GrantError::Malformed);
        }
        if now + 30 < g.iat || now >= g.exp {
            return Err(GrantError::Expired);
        }
        Ok(g)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use svx_core::crypto::os_rng;

    fn grant(now: i64) -> Grant {
        Grant {
            v: crate::PROTOCOL_VERSION,
            service_id: "svx.example".into(),
            artifact_id: [1; 16],
            header_hash: [2; 32],
            recipient_org: "example-corp".into(),
            issuer: "https://idp.example".into(),
            sub: "alice".into(),
            client_key_id: [3; 16],
            txn: [4; 16],
            iat: now,
            exp: now + 60,
        }
    }

    #[test]
    fn sign_verify_and_tamper() {
        let sk = SigningKey::generate(&mut os_rng());
        let other = SigningKey::generate(&mut os_rng());
        let g = grant(1000);
        let sg = SignedGrant::sign(&g, &sk);
        assert_eq!(sg.verify(&sk.verifying_key(), 1010).unwrap(), g);
        assert_eq!(
            sg.verify(&other.verifying_key(), 1010),
            Err(GrantError::WrongKey)
        );
        assert_eq!(
            sg.verify(&sk.verifying_key(), 1060),
            Err(GrantError::Expired)
        );
        let mut t = sg.clone();
        let i = t.payload.iter().position(|&b| b == b'a').unwrap();
        t.payload[i] = b'b';
        assert_eq!(
            t.verify(&sk.verifying_key(), 1010),
            Err(GrantError::BadSignature)
        );
    }
}
