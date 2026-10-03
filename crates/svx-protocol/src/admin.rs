//! Organization lifecycle and administration bodies.

use serde::{Deserialize, Serialize};

use crate::encoding::{hex_array, hex_vec};
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
    /// Exact length for `kind`: 32 bytes classical, 1216 X-Wing, 1984
    /// Ed25519 + ML-DSA-65.
    #[serde(with = "hex_vec")]
    pub public_key: Vec<u8>,
    pub status: KeyStatus,
}

/// `GET /v1/admin/orgs/{org}`: everything an administrator manages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgOverview {
    pub org_id: String,
    pub display_name: String,
    pub domain: String,
    pub idp_issuer: String,
    pub idp_client_id: String,
    pub group_claim: String,
    pub key_agent_url: Option<String>,
    pub verified_at: i64,
    pub admins: Vec<AdminEntry>,
    pub keys: Vec<KeyDetail>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminEntry {
    pub subject: String,
    pub added_at: i64,
}

/// A registered key with its lifecycle times (Unix seconds).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyDetail {
    #[serde(with = "hex_array")]
    pub key_id: [u8; 16],
    pub kind: KeyKindWire,
    #[serde(with = "hex_vec")]
    pub public_key: Vec<u8>,
    pub status: KeyStatus,
    pub created_at: i64,
    pub retired_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

/// `PATCH /v1/admin/orgs/{org}`. Omitted fields are unchanged. The IdP
/// can't be changed here: that would hand the organization to whoever
/// controls the new IdP.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateOrgRequest {
    #[serde(default)]
    pub display_name: Option<String>,
    /// New key agent URL (https outside dev).
    #[serde(default)]
    pub key_agent_url: Option<String>,
    /// Remove the key agent: the organization can then only send.
    #[serde(default)]
    pub remove_key_agent: bool,
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
