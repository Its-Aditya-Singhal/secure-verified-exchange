//! Release request and response bodies.

use serde::{Deserialize, Serialize};

use crate::encoding::{b64, hex_array};
use crate::grant::SignedGrant;

/// `POST /v1/release` on the managed service.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRequest {
    /// The artifact's prelude ‖ header, verbatim.
    #[serde(with = "b64")]
    pub header_region: Vec<u8>,
    /// The artifact's trailer, verbatim.
    #[serde(with = "b64")]
    pub trailer: Vec<u8>,
    /// ID token from the recipient organization's IdP, issued with
    /// `nonce = nonce_binding(client_key, txn)`.
    pub id_token: String,
    /// Client's ephemeral X25519 public key for this request.
    #[serde(with = "hex_array")]
    pub client_key: [u8; 32],
    /// Random, single-use transaction identifier.
    #[serde(with = "hex_array")]
    pub txn: [u8; 16],
}

/// A key share re-sealed to the client's ephemeral key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedShare {
    #[serde(with = "hex_array")]
    pub encapped_key: [u8; 32],
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseResponse {
    pub share: SealedShare,
    pub grant: SignedGrant,
}

/// `POST /v1/agent/release` on the recipient organization's key agent.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentReleaseRequest {
    #[serde(with = "b64")]
    pub header_region: Vec<u8>,
    pub id_token: String,
    #[serde(with = "hex_array")]
    pub client_key: [u8; 32],
    #[serde(with = "hex_array")]
    pub txn: [u8; 16],
    pub grant: SignedGrant,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentReleaseResponse {
    pub share: SealedShare,
}

/// Deliberately coarse denial reasons. Precise reasons go to the audit log
/// only, so responses do not help an attacker map policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    InvalidRequest,
    InvalidArtifact,
    NotAuthorized,
    ExpiredOrRevoked,
    Unavailable,
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DenyReason::InvalidRequest => "invalid request",
            DenyReason::InvalidArtifact => "invalid or untrusted artifact",
            DenyReason::NotAuthorized => "not authorized",
            DenyReason::ExpiredOrRevoked => "artifact expired or revoked",
            DenyReason::Unavailable => "service unavailable",
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: DenyReason,
    /// Human-readable detail for administrative endpoints only. Release
    /// endpoints never set it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}
