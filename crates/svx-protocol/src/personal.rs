//! Personal accounts (Phase 5d): sign-up with Google or Apple, the email
//! directory, per-file rules, sender approval and one-time opening.
//!
//! A personal account is a one-person organization (`u.<16 hex>`) whose
//! registry record carries its verified email. After sign-up, the account's
//! device authenticates every request with its hybrid signing key
//! ([`sign_request`]), so opening a file never needs a browser sign-in.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use svx_core::crypto::{
    CryptoError, SignContext, SigningKey, VerifyingKey, random_bytes, sign_context, verify_context,
};

use crate::encoding::{b64, hex_array, hex_vec};
use crate::types::SealedShare;

/// A sign-in provider for personal accounts, published in the signed
/// service record so the app knows how to sign in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalIdp {
    /// Shown on the button, e.g. "Google".
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    /// Google's "installed app" clients need this in the token exchange;
    /// it is not a secret (it ships in every copy of the app).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
}

/// Whether an organization is a company or a personal account.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgKind {
    #[default]
    Company,
    Personal,
}

/// `POST /v1/accounts`: create a personal account, or register this
/// device's keys for an existing one.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignUpRequest {
    /// The provider's issuer (one of the service's [`PersonalIdp`]s).
    pub issuer: String,
    /// An ID token whose `nonce` is [`signup_nonce`] of the two keys below,
    /// so a captured token can't register someone else's keys.
    pub id_token: String,
    /// Hybrid (Ed25519 + ML-DSA-65) signing key.
    #[serde(with = "hex_vec")]
    pub signing_public: Vec<u8>,
    /// X-Wing encryption key.
    #[serde(with = "hex_vec")]
    pub kem_public: Vec<u8>,
    /// Replace the account's keys (lost device without a backup). Files
    /// sent to the old keys can no longer be opened.
    #[serde(default)]
    pub reset: bool,
}

/// A personal account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    /// The account's organization ID (`u.<16 hex>`).
    pub account: String,
    pub email: String,
    pub issuer: String,
    pub created_at: i64,
}

/// The ID-token nonce that binds a sign-up to these exact keys:
/// `hex(SHA-256("SVX-1 sign-up\0" ‖ u16 len ‖ signing ‖ u16 len ‖ kem))`.
pub fn signup_nonce(signing_public: &[u8], kem_public: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"SVX-1 sign-up\0");
    for k in [signing_public, kem_public] {
        h.update((k.len() as u16).to_le_bytes());
        h.update(k);
    }
    hex::encode(h.finalize())
}

/// Rules the sender sets per file. They live on the service, so they can
/// change after the file is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRules {
    /// Every open waits for the sender's approval.
    pub require_approval: bool,
    /// Each recipient can open the file once.
    pub one_time: bool,
    /// Server-side expiry (Unix seconds). Never later than the expiry
    /// signed into the file.
    #[serde(default)]
    pub expires_at: Option<i64>,
}

impl Default for FileRules {
    fn default() -> Self {
        FileRules {
            require_approval: true,
            one_time: true,
            expires_at: None,
        }
    }
}

/// `POST /v1/me/files`: register a file just made (required before anyone
/// can open it).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterFileRequest {
    #[serde(with = "b64")]
    pub header_region: Vec<u8>,
    #[serde(with = "b64")]
    pub trailer: Vec<u8>,
    pub rules: FileRules,
}

/// `PATCH /v1/me/files/{artifact_id}`: change a file's rules. Absent
/// fields are unchanged.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateFileRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_approval: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_time: Option<bool>,
    /// A new server-side expiry; it can't be later than the signed one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// Revoke the whole file (permanent).
    #[serde(default)]
    pub revoke: bool,
    /// Revoke these recipients (account IDs) only (permanent).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoke_recipients: Vec<String>,
}

/// Where one recipient stands with a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientState {
    /// Hasn't tried to open it.
    NotOpened,
    /// Waiting for the sender's approval.
    Requested,
    /// Approved, not opened yet.
    Approved,
    /// Opened (used up if the file is one-time).
    Opened,
    Declined,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientStatus {
    pub account: String,
    pub email: Option<String>,
    pub state: RecipientState,
    pub requested_at: Option<i64>,
    pub opened_at: Option<i64>,
}

/// A file as its sender sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileStatus {
    #[serde(with = "hex_array")]
    pub artifact_id: [u8; 16],
    pub sender: String,
    pub sender_email: Option<String>,
    pub created_at: i64,
    /// Expiry signed into the file.
    pub signed_expires_at: Option<i64>,
    pub rules: FileRules,
    pub revoked_at: Option<i64>,
    pub recipients: Vec<RecipientStatus>,
}

/// `POST /v1/personal/release`: ask to open a file.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalReleaseRequest {
    #[serde(with = "b64")]
    pub header_region: Vec<u8>,
    #[serde(with = "b64")]
    pub trailer: Vec<u8>,
    /// The X-Wing one-time key the service share is sealed to.
    #[serde(with = "hex_vec")]
    pub client_key: Vec<u8>,
    #[serde(with = "hex_array")]
    pub txn: [u8; 16],
}

/// The answer to a release request or a poll.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum PersonalReleaseResponse {
    /// Waiting for the sender to approve. Poll by sending the same release
    /// request again (same one-time key and transaction, freshly signed).
    Pending {
        #[serde(with = "hex_array")]
        request_id: [u8; 16],
        sender_email: Option<String>,
        expires_at: i64,
    },
    /// The service share, sealed to the request's one-time key.
    Released { share: SealedShare },
}

/// `POST /v1/personal/opened`: the recipient finished decrypting (makes a
/// one-time open final at once instead of after the retry window).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenedReceipt {
    #[serde(with = "hex_array")]
    pub artifact_id: [u8; 16],
    #[serde(with = "hex_array")]
    pub txn: [u8; 16],
}

/// Someone asking the sender to open one of their files.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequest {
    #[serde(with = "hex_array")]
    pub request_id: [u8; 16],
    #[serde(with = "hex_array")]
    pub artifact_id: [u8; 16],
    pub requester: String,
    pub requester_email: Option<String>,
    pub requested_at: i64,
    pub expires_at: i64,
}

/// A file sent to this account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceivedFile {
    #[serde(with = "hex_array")]
    pub artifact_id: [u8; 16],
    pub sender: String,
    pub sender_email: Option<String>,
    pub created_at: i64,
    pub state: RecipientState,
    pub requested_at: Option<i64>,
    pub opened_at: Option<i64>,
}

/// `GET /v1/me/history`: newest first. File names are not here: they
/// never leave the device.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct History {
    pub sent: Vec<FileStatus>,
    pub received: Vec<ReceivedFile>,
}

// ----- Signed requests -----

pub const HDR_ACCOUNT: &str = "svx-account";
pub const HDR_KEY_ID: &str = "svx-key-id";
pub const HDR_TIME: &str = "svx-time";
pub const HDR_NONCE: &str = "svx-nonce";
pub const HDR_SIGNATURE: &str = "svx-signature";
/// Accepted clock difference for signed requests.
pub const REQUEST_SKEW_SECS: i64 = 60;

/// The authentication headers of a signed request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestAuth {
    pub account: String,
    pub key_id: [u8; 16],
    pub time: i64,
    pub nonce: [u8; 16],
    pub signature: Vec<u8>,
}

/// The exact bytes a device signs (under `SignContext::AccountRequest`):
/// `METHOD \n path?query \n hex(SHA-256(body)) \n time \n hex(nonce) \n
/// account \n hex(key_id)`.
pub fn request_message(
    method: &str,
    path_and_query: &str,
    body: &[u8],
    account: &str,
    key_id: &[u8; 16],
    time: i64,
    nonce: &[u8; 16],
) -> Vec<u8> {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        path_and_query,
        hex::encode(Sha256::digest(body)),
        time,
        hex::encode(nonce),
        account,
        hex::encode(key_id)
    )
    .into_bytes()
}

/// Sign a request as `account` with its device key.
pub fn sign_request(
    key: &SigningKey,
    account: &str,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    time: i64,
) -> Result<RequestAuth, CryptoError> {
    let key_id = key.verifying_key().key_id();
    let nonce = random_bytes::<16>();
    let msg = request_message(method, path_and_query, body, account, &key_id, time, &nonce);
    Ok(RequestAuth {
        account: account.to_owned(),
        key_id,
        time,
        nonce,
        signature: sign_context(key, SignContext::AccountRequest, &msg)?,
    })
}

impl RequestAuth {
    /// Header name/value pairs to send.
    pub fn headers(&self) -> [(&'static str, String); 5] {
        use base64::Engine;
        [
            (HDR_ACCOUNT, self.account.clone()),
            (HDR_KEY_ID, hex::encode(self.key_id)),
            (HDR_TIME, self.time.to_string()),
            (HDR_NONCE, hex::encode(self.nonce)),
            (
                HDR_SIGNATURE,
                base64::engine::general_purpose::STANDARD.encode(&self.signature),
            ),
        ]
    }

    /// Parse from a header lookup.
    pub fn from_headers<'a>(get: impl Fn(&str) -> Option<&'a str>) -> Option<Self> {
        use base64::Engine;
        let mut key_id = [0u8; 16];
        hex::decode_to_slice(get(HDR_KEY_ID)?, &mut key_id).ok()?;
        let mut nonce = [0u8; 16];
        hex::decode_to_slice(get(HDR_NONCE)?, &mut nonce).ok()?;
        let signature = base64::engine::general_purpose::STANDARD
            .decode(get(HDR_SIGNATURE)?)
            .ok()?;
        let account = get(HDR_ACCOUNT)?;
        if account.is_empty() || account.len() > 128 || signature.len() > 4096 {
            return None;
        }
        Some(RequestAuth {
            account: account.to_owned(),
            key_id,
            time: get(HDR_TIME)?.parse().ok()?,
            nonce,
            signature,
        })
    }

    /// Check the signature with the account's registered key `key` and the
    /// time window. Replay (the nonce) is checked by the service.
    pub fn verify(
        &self,
        key: &VerifyingKey,
        method: &str,
        path_and_query: &str,
        body: &[u8],
        now: i64,
    ) -> Result<(), CryptoError> {
        if (now - self.time).abs() > REQUEST_SKEW_SECS || key.key_id() != self.key_id {
            return Err(CryptoError::BadSignature);
        }
        let msg = request_message(
            method,
            path_and_query,
            body,
            &self.account,
            &self.key_id,
            self.time,
            &self.nonce,
        );
        verify_context(key, SignContext::AccountRequest, &msg, &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use svx_core::crypto::os_rng;

    #[test]
    fn signed_requests_bind_everything() {
        let k = SigningKey::generate_hybrid(&mut os_rng());
        let vk = k.verifying_key();
        let a = sign_request(&k, "u.0000000000000a11", "post", "/v1/x?y=1", b"{}", 1000).unwrap();
        a.verify(&vk, "POST", "/v1/x?y=1", b"{}", 1010).unwrap();
        // Round trip through headers.
        let h = a.headers();
        let back =
            RequestAuth::from_headers(|n| h.iter().find(|(k, _)| *k == n).map(|(_, v)| v.as_str()))
                .unwrap();
        assert_eq!(back, a);
        // Any change breaks it.
        assert!(a.verify(&vk, "GET", "/v1/x?y=1", b"{}", 1000).is_err());
        assert!(a.verify(&vk, "POST", "/v1/x?y=2", b"{}", 1000).is_err());
        assert!(a.verify(&vk, "POST", "/v1/x?y=1", b"{ }", 1000).is_err());
        let mut other = a.clone();
        other.account = "u.0000000000000b0b".into();
        assert!(other.verify(&vk, "POST", "/v1/x?y=1", b"{}", 1000).is_err());
        // Outside the clock window.
        assert!(a.verify(&vk, "POST", "/v1/x?y=1", b"{}", 1061).is_err());
        assert!(a.verify(&vk, "POST", "/v1/x?y=1", b"{}", 939).is_err());
        // Another key.
        let other_key = SigningKey::generate_hybrid(&mut os_rng()).verifying_key();
        assert!(
            a.verify(&other_key, "POST", "/v1/x?y=1", b"{}", 1000)
                .is_err()
        );
        // Classical keys can't sign requests.
        let ed = SigningKey::generate(&mut os_rng());
        assert!(sign_request(&ed, "u.1", "GET", "/", b"", 1000).is_err());
    }

    #[test]
    fn signup_nonce_binds_both_keys() {
        let n = signup_nonce(b"sign", b"kem");
        assert_eq!(n.len(), 64);
        assert_ne!(n, signup_nonce(b"sign", b"kem2"));
        assert_ne!(n, signup_nonce(b"signk", b"em"));
    }

    #[test]
    fn release_response_wire_shape() {
        let p = PersonalReleaseResponse::Pending {
            request_id: [1; 16],
            sender_email: Some("alice@example.test".into()),
            expires_at: 5,
        };
        let j = serde_json::to_value(&p).unwrap();
        assert_eq!(j["status"], "pending");
        let back: PersonalReleaseResponse = serde_json::from_value(j).unwrap();
        assert!(matches!(back, PersonalReleaseResponse::Pending { .. }));
    }
}
