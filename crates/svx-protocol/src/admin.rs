//! Organization lifecycle and administration bodies.

use serde::{Deserialize, Serialize};

use crate::encoding::hex_array;
use crate::registry::{KeyKindWire, KeyStatus};

/// `POST /v1/orgs`
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterOrgRequest {
    pub org_id: String,
    pub display_name: String,
    /// Domain the org proves control of via a DNS TXT record.
    pub domain: String,
    /// OIDC issuer of the org's IdP (exact string, must be https outside dev).
    pub idp_issuer: String,
    /// Client ID registered for SVX at that IdP (expected `aud`).
    pub idp_client_id: String,
    /// Claim carrying group memberships (default `groups`).
    #[serde(default)]
    pub group_claim: Option<String>,
    /// URL of the org's key agent, if it receives artifacts.
    #[serde(default)]
    pub key_agent_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterOrgResponse {
    /// Create a TXT record with this name…
    pub txt_name: String,
    /// …containing this value, then call verify.
    pub txt_value: String,
}

/// `POST /v1/orgs/{org}/verify` — the caller becomes the first admin.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyOrgRequest {
    pub id_token: String,
}

/// `PUT /v1/admin/orgs/{org}/keys`
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutKeyRequest {
    pub kind: KeyKindWire,
    #[serde(with = "hex_array")]
    pub public_key: [u8; 32],
    pub status: KeyStatus,
}

/// `POST /v1/admin/orgs/{org}/admins`
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddAdminRequest {
    pub subject: String,
}

/// One audit record as returned to an org administrator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: i64,
    pub at: i64,
    pub event: String,
    /// The user's `sub` for this org's own users; a pseudonymous hash for
    /// users of other organizations.
    pub subject: Option<String>,
    pub artifact_id: Option<String>,
    pub txn: Option<String>,
    pub reason: Option<String>,
    pub hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditPage {
    pub entries: Vec<AuditEntry>,
    /// Whether the hash chain verified for the returned range.
    pub chain_valid: bool,
}
