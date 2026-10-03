//! The release client: everything a recipient needs to turn a verified
//! artifact plus an authenticated user into the two key shares.

use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use svx_core::VerifiedHead;
use svx_core::crypto::{
    CryptoError, KemPublicKey, KemSecretKey, Share, TXN_LEN, VerifyingKey, nonce_binding,
    open_released_share, os_rng, random_bytes,
};
use svx_core::format::EnvelopeRole;

use crate::grant::SignedGrant;
use crate::registry::{
    OrgRecord, ServiceInfo, ServiceRecord, SignedOrgRecord, SignedServiceRecord,
};
use crate::types::*;

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("refusing insecure URL {0} (https is required outside loopback dev mode)")]
    InsecureUrl(String),
    #[error("network error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("access denied: {0}")]
    Denied(DenyReason),
    #[error("unexpected HTTP status {0}")]
    Status(u16),
    #[error("invalid response: {0}")]
    BadResponse(String),
    #[error("{0}")]
    Crypto(#[from] CryptoError),
}

pub type Result<T> = std::result::Result<T, ProtocolError>;

/// Require `https://`, except `http://` to a loopback host when `allow_dev`
/// is set (local development and tests only).
pub fn check_url(raw: &str, allow_dev: bool) -> Result<url::Url> {
    let u = url::Url::parse(raw).map_err(|_| ProtocolError::InsecureUrl(raw.to_owned()))?;
    let loopback = match u.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d == "localhost",
        None => false,
    };
    match u.scheme() {
        "https" => Ok(u),
        "http" if allow_dev && loopback => Ok(u),
        _ => Err(ProtocolError::InsecureUrl(raw.to_owned())),
    }
}

fn join(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

/// Per-release ephemeral state. The secret key never leaves this process
/// and is zeroized on drop.
pub struct ReleaseSession {
    key: KemSecretKey,
    txn: [u8; TXN_LEN],
}

impl ReleaseSession {
    pub fn new() -> Self {
        ReleaseSession {
            key: KemSecretKey::generate(&mut os_rng()),
            txn: random_bytes(),
        }
    }

    /// The OIDC `nonce` to request when logging in for this release.
    pub fn nonce(&self) -> String {
        nonce_binding(self.key.public_key(), &self.txn)
    }

    pub fn client_key(&self) -> &KemPublicKey {
        self.key.public_key()
    }

    pub fn txn(&self) -> &[u8; TXN_LEN] {
        &self.txn
    }

    fn open(&self, role: EnvelopeRole, artifact_id: &[u8; 16], s: &SealedShare) -> Result<Share> {
        Ok(open_released_share(
            role,
            &self.key,
            artifact_id,
            &self.txn,
            &s.encapped_key,
            &s.ciphertext,
        )?)
    }
}

impl Default for ReleaseSession {
    fn default() -> Self {
        Self::new()
    }
}

/// HTTP client for the managed service and key agents.
#[derive(Clone)]
pub struct ManagedClient {
    http: reqwest::Client,
    allow_dev_http: bool,
}

impl ManagedClient {
    pub fn new(allow_dev_http: bool) -> Result<Self> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .https_only(!allow_dev_http)
            .build()?;
        Ok(ManagedClient {
            http,
            allow_dev_http,
        })
    }

    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    pub fn allow_dev_http(&self) -> bool {
        self.allow_dev_http
    }

    async fn decode<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        if status.is_success() {
            return resp
                .json::<T>()
                .await
                .map_err(|e| ProtocolError::BadResponse(e.to_string()));
        }
        match resp.json::<ErrorBody>().await {
            Ok(b) => Err(ProtocolError::Denied(b.error)),
            Err(_) => Err(ProtocolError::Status(status.as_u16())),
        }
    }

    pub async fn get_json<T: DeserializeOwned>(&self, base: &str, path: &str) -> Result<T> {
        check_url(base, self.allow_dev_http)?;
        Self::decode(self.http.get(join(base, path)).send().await?).await
    }

    pub async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        base: &str,
        path: &str,
        body: &B,
        bearer: Option<&str>,
    ) -> Result<T> {
        check_url(base, self.allow_dev_http)?;
        let mut req = self.http.post(join(base, path)).json(body);
        if let Some(t) = bearer {
            req = req.bearer_auth(t);
        }
        Self::decode(req.send().await?).await
    }

    pub async fn put_json<B: Serialize, T: DeserializeOwned>(
        &self,
        base: &str,
        path: &str,
        body: &B,
        bearer: &str,
    ) -> Result<T> {
        check_url(base, self.allow_dev_http)?;
        Self::decode(
            self.http
                .put(join(base, path))
                .json(body)
                .bearer_auth(bearer)
                .send()
                .await?,
        )
        .await
    }

    pub async fn get_json_auth<T: DeserializeOwned>(
        &self,
        base: &str,
        path: &str,
        bearer: &str,
    ) -> Result<T> {
        check_url(base, self.allow_dev_http)?;
        Self::decode(
            self.http
                .get(join(base, path))
                .bearer_auth(bearer)
                .send()
                .await?,
        )
        .await
    }

    pub async fn service_info(&self, service_url: &str) -> Result<ServiceInfo> {
        self.get_json(service_url, "/v1/service").await
    }

    /// Fetch and verify the service record against the pinned registry key.
    pub async fn service_record(
        &self,
        service_url: &str,
        registry_key: &VerifyingKey,
    ) -> Result<ServiceRecord> {
        let s: SignedServiceRecord = self.get_json(service_url, "/v1/service/record").await?;
        s.verify(registry_key, crate::unix_now())
            .map_err(|e| ProtocolError::BadResponse(e.to_string()))
    }

    /// Fetch and verify an organization record against the pinned registry key.
    pub async fn org_record(
        &self,
        service_url: &str,
        org: &str,
        registry_key: &VerifyingKey,
    ) -> Result<OrgRecord> {
        let s: SignedOrgRecord = self
            .get_json(service_url, &format!("/v1/registry/orgs/{org}"))
            .await?;
        s.verify(registry_key, org, crate::unix_now())
            .map_err(|e| ProtocolError::BadResponse(e.to_string()))
    }

    /// Step 1: ask the managed service to authorize and release its share.
    pub async fn release_from_service(
        &self,
        service_url: &str,
        session: &ReleaseSession,
        head: &VerifiedHead,
        id_token: &str,
    ) -> Result<(Share, SignedGrant)> {
        let req = ReleaseRequest {
            header_region: head.header_region.clone(),
            trailer: head
                .trailer
                .encode()
                .map_err(|e| ProtocolError::BadResponse(e.to_string()))?,
            id_token: id_token.to_owned(),
            client_key: session.client_key().to_bytes(),
            txn: session.txn,
        };
        let resp: ReleaseResponse = self
            .post_json(service_url, "/v1/release", &req, None)
            .await?;
        let share = session.open(EnvelopeRole::Service, &head.header.artifact_id, &resp.share)?;
        Ok((share, resp.grant))
    }

    /// Step 2: present the grant to the recipient org's key agent.
    pub async fn release_from_agent(
        &self,
        agent_url: &str,
        session: &ReleaseSession,
        head: &VerifiedHead,
        id_token: &str,
        grant: SignedGrant,
    ) -> Result<Share> {
        let req = AgentReleaseRequest {
            header_region: head.header_region.clone(),
            id_token: id_token.to_owned(),
            client_key: session.client_key().to_bytes(),
            txn: session.txn,
            grant,
        };
        let resp: AgentReleaseResponse = self
            .post_json(agent_url, "/v1/agent/release", &req, None)
            .await?;
        session.open(
            EnvelopeRole::RecipientOrg,
            &head.header.artifact_id,
            &resp.share,
        )
    }

    /// Both steps. Returns `(service_share, recipient_share)` for
    /// [`svx_core::VerifiedArtifact::decrypt`].
    pub async fn release(
        &self,
        service_url: &str,
        agent_url: &str,
        session: &ReleaseSession,
        head: &VerifiedHead,
        id_token: &str,
    ) -> Result<(Share, Share)> {
        let (svc, grant) = self
            .release_from_service(service_url, session, head, id_token)
            .await?;
        let org = self
            .release_from_agent(agent_url, session, head, id_token, grant)
            .await?;
        Ok((svc, org))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_policy() {
        assert!(check_url("https://svx.example", false).is_ok());
        assert!(check_url("http://svx.example", false).is_err());
        assert!(check_url("http://svx.example", true).is_err());
        assert!(check_url("http://127.0.0.1:8080", false).is_err());
        assert!(check_url("http://127.0.0.1:8080", true).is_ok());
        assert!(check_url("http://localhost:1", true).is_ok());
        assert!(check_url("http://[::1]:1", true).is_ok());
        assert!(check_url("ftp://127.0.0.1", true).is_err());
    }
}
