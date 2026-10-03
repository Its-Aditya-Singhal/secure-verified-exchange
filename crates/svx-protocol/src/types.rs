//! Release request and response bodies.

use serde::{Deserialize, Serialize};
use svx_core::crypto::{KemPublicKey, KeyKind};

use crate::encoding::{b64, hex_array, hex_vec};
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
    /// Client's one-time X-Wing (X25519 + ML-KEM-768) public key for this
    /// request (1216 bytes). Classical keys are refused, so a recorded
    /// release can't be decrypted later by a quantum computer.
    #[serde(with = "hex_vec")]
    pub client_key: Vec<u8>,
    /// Random, single-use transaction identifier.
    #[serde(with = "hex_array")]
    pub txn: [u8; 16],
}

/// A key share re-sealed to the client's ephemeral key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedShare {
    /// X-Wing encapsulated key (1120 bytes).
    #[serde(with = "b64")]
    pub encapped_key: Vec<u8>,
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
    /// The same one-time X-Wing key as in [`ReleaseRequest::client_key`].
    #[serde(with = "hex_vec")]
    pub client_key: Vec<u8>,
    #[serde(with = "hex_array")]
    pub txn: [u8; 16],
    pub grant: SignedGrant,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentReleaseResponse {
    pub share: SealedShare,
}

/// `GET /v1/agent/keys` on a key agent: the KEM keys it holds (public
/// information only). Administrators use it to activate a new encryption key
/// in the registry only once the agent can use it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentKeys {
    pub org_id: String,
    pub keys: Vec<AgentKey>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentKey {
    #[serde(with = "hex_array")]
    pub key_id: [u8; 16],
    pub kind: crate::registry::KeyKindWire,
}

/// Parse a release request's one-time client key. Only X-Wing keys are
/// accepted.
pub fn parse_client_key(bytes: &[u8]) -> Option<KemPublicKey> {
    KemPublicKey::from_kind_bytes(KeyKind::XWingKem, bytes).ok()
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
    /// A one-time file this recipient has already opened.
    AlreadyOpened,
    /// The sender declined this request to open the file.
    Declined,
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DenyReason::InvalidRequest => "invalid request",
            DenyReason::InvalidArtifact => "invalid or untrusted artifact",
            DenyReason::NotAuthorized => "not authorized",
            DenyReason::ExpiredOrRevoked => "artifact expired or revoked",
            DenyReason::Unavailable => "service unavailable",
            DenyReason::AlreadyOpened => "already opened (this file can be opened once)",
            DenyReason::Declined => "the sender declined",
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
