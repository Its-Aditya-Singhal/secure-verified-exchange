//! Signing up a new organization from a client: register it with the
//! managed service, prove control of its domain (a DNS TXT record) and of
//! its IdP (the person signing in becomes the first administrator), then
//! save a verified configuration.
//!
//! The service is checked against the pinned registry key fingerprint before
//! anything is sent to it.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use svx_core::crypto::VerifyingKey;
use svx_protocol::admin::{RegisterOrgRequest, RegisterOrgResponse, VerifyOrgRequest};
use svx_protocol::{ManagedClient, check_url};

use crate::account::{self, LoginMethod, WhoAmI};
use crate::config::{ClientConfig, Paths};
use crate::error::{ClientError, Result};
use crate::setup::{self, SetupPreview, SetupRequest};

/// What a new organization registers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardRequest {
    pub service_url: String,
    /// The registry key fingerprint (64 hex), obtained out of band.
    pub registry_key: String,
    pub org_id: String,
    pub display_name: String,
    /// The domain the organization proves control of.
    pub domain: String,
    /// The organization's own IdP (OIDC issuer) and SVX's client ID there.
    pub idp_issuer: String,
    pub idp_client_id: String,
    #[serde(default)]
    pub group_claim: Option<String>,
    /// The key agent URL, if the organization will receive files.
    #[serde(default)]
    pub key_agent_url: Option<String>,
    #[serde(default)]
    pub dev: bool,
    #[serde(default)]
    pub default_output_dir: Option<PathBuf>,
}

/// A registration waiting for its DNS record. Safe to store and show: it
/// holds no secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingOrg {
    pub request: OnboardRequest,
    /// Create a TXT record with this name…
    pub txt_name: String,
    /// …and exactly this value.
    pub txt_value: String,
    pub registered_at: i64,
}

impl OnboardRequest {
    /// The configuration, given the registry key that matched the pin.
    fn config(&self, registry: &VerifyingKey) -> ClientConfig {
        ClientConfig {
            service_url: self.service_url.trim().to_owned(),
            registry_key: hex::encode(registry.fingerprint()),
            registry_public: hex::encode(registry.to_vec()),
            org_id: self.org_id.trim().to_owned(),
            idp_issuer: self.idp_issuer.trim().to_owned(),
            idp_client_id: self.idp_client_id.trim().to_owned(),
            group_claim: self
                .group_claim
                .clone()
                .filter(|g| !g.trim().is_empty())
                .unwrap_or_else(|| "groups".into()),
            dev: self.dev,
            default_output_dir: self.default_output_dir.clone(),
        }
    }
}

/// Step 1: register. Returns the DNS record to create.
pub async fn register(req: OnboardRequest) -> Result<PendingOrg> {
    if let Some(u) = &req.key_agent_url {
        check_url(u, req.dev)
            .map_err(|_| ClientError::Config("key agent URL must be https".into()))?;
    }
    let client = ManagedClient::new(req.dev)?;
    // Talk only to a service that proves it belongs to the pinned registry.
    let key =
        setup::registry_key(&client, req.service_url.trim(), &req.registry_key, req.dev).await?;
    let cfg = req.config(&key);
    cfg.validate()?;
    client.service_record(&cfg.service_url, &key).await?;
    let r: RegisterOrgResponse = client
        .post_json(
            &cfg.service_url,
            "/v1/orgs",
            &RegisterOrgRequest {
                org_id: cfg.org_id.clone(),
                display_name: req.display_name.trim().to_owned(),
                domain: req.domain.trim().to_ascii_lowercase(),
                idp_issuer: cfg.idp_issuer.clone(),
                idp_client_id: cfg.idp_client_id.clone(),
                group_claim: Some(cfg.group_claim.clone()),
                key_agent_url: req.key_agent_url.clone().filter(|u| !u.trim().is_empty()),
            },
            None,
        )
        .await?;
    Ok(PendingOrg {
        request: req,
        txt_name: r.txt_name,
        txt_value: r.txt_value,
        registered_at: crate::now(),
    })
}

/// Step 2, once the DNS record exists: sign in with the organization's IdP,
/// verify (the signed-in person becomes the first administrator), then save
/// the verified configuration and an admin session.
pub async fn complete(
    paths: &Paths,
    pending: &PendingOrg,
    login: LoginMethod,
    replace: bool,
) -> Result<(SetupPreview, WhoAmI)> {
    let req = &pending.request;
    if paths.config.exists() && !replace {
        return Err(ClientError::Config(format!(
            "{} exists (replace it to continue)",
            paths.config.display()
        )));
    }
    let client = ManagedClient::new(req.dev)?;
    let key =
        setup::registry_key(&client, req.service_url.trim(), &req.registry_key, req.dev).await?;
    let cfg = req.config(&key);
    cfg.validate()?;
    let auth = account::authenticator(&cfg, &client, login)?;
    let nonce = hex::encode(svx_core::crypto::random_bytes::<16>());
    let id_token = auth.id_token(&nonce).await?;
    let _: serde_json::Value = client
        .post_json(
            &cfg.service_url,
            &format!("/v1/orgs/{}/verify", cfg.org_id),
            &VerifyOrgRequest {
                id_token: id_token.clone(),
            },
            None,
        )
        .await?;
    let mut preview = setup::verify(SetupRequest {
        service_url: cfg.service_url.clone(),
        registry_key: cfg.registry_key.clone(),
        org_id: cfg.org_id.clone(),
        idp_client_id: cfg.idp_client_id.clone(),
        dev: cfg.dev,
        default_output_dir: cfg.default_output_dir.clone(),
    })
    .await?;
    preview.config.group_claim = cfg.group_claim.clone();
    setup::write(paths, &preview.config, replace)?;
    let me = account::save_session(&preview.config, id_token, &nonce, &paths.session).await?;
    Ok((preview, me))
}
