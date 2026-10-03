//! First-run setup (`svx init`, the desktop app's welcome screen).
//!
//! The registry key is the client's only trust anchor. [`verify`] checks the
//! service record and the user's organization record against it, so a wrong
//! pin, a wrong service URL or an unknown organization fails before any
//! configuration is written.

use std::path::PathBuf;

use serde::Serialize;
use svx_protocol::{ManagedClient, check_url};

use crate::config::{ClientConfig, Paths, parse_registry_key};
use crate::error::{ClientError, Result};

/// What the user is setting up.
#[derive(Clone, Debug)]
pub struct SetupRequest {
    pub service_url: String,
    /// Registry public key (hex), from an out-of-band source.
    pub registry_key: String,
    pub org_id: String,
    pub idp_client_id: String,
    pub dev: bool,
    pub default_output_dir: Option<PathBuf>,
}

/// The verified result of [`verify`]: a configuration ready to save and the
/// facts to show the user before they confirm.
#[derive(Clone, Debug, Serialize)]
pub struct SetupPreview {
    #[serde(skip)]
    pub config: ClientConfig,
    pub service_id: String,
    pub service_url: String,
    pub org_id: String,
    pub org_display_name: String,
    pub idp_issuer: String,
    /// Without a key agent the organization can send but not receive.
    pub can_receive: bool,
}

/// Verify the service and organization records with the pinned key.
pub async fn verify(req: SetupRequest) -> Result<SetupPreview> {
    let key = parse_registry_key(&req.registry_key)?;
    check_url(&req.service_url, req.dev)
        .map_err(|_| ClientError::Config("service URL must be https".into()))?;
    let client = ManagedClient::new(req.dev)?;
    // Both lookups verify signatures with the pinned key: a wrong pin fails here.
    let service = client
        .service_record(&req.service_url, &key)
        .await
        .map_err(|e| context("verifying the service record with the registry key", e))?;
    let org = client
        .org_record(&req.service_url, &req.org_id, &key)
        .await
        .map_err(|e| {
            context(
                &format!("fetching the registry record for {}", req.org_id),
                e,
            )
        })?;
    let config = ClientConfig {
        service_url: req.service_url,
        registry_key: hex::encode(key.to_bytes()),
        org_id: req.org_id,
        idp_issuer: org.idp_issuer.clone(),
        idp_client_id: req.idp_client_id,
        group_claim: "groups".into(),
        dev: req.dev,
        default_output_dir: req.default_output_dir,
    };
    config.validate()?;
    Ok(SetupPreview {
        service_id: service.service_id,
        service_url: config.service_url.clone(),
        org_id: org.org_id,
        org_display_name: org.display_name,
        idp_issuer: org.idp_issuer,
        can_receive: org.key_agent_url.is_some(),
        config,
    })
}

/// Save a verified configuration. Refuses to replace an existing one unless
/// `force` is set.
pub fn write(paths: &Paths, config: &ClientConfig, force: bool) -> Result<()> {
    if paths.config.exists() && !force {
        return Err(ClientError::Config(format!(
            "{} exists (use --force to replace it)",
            paths.config.display()
        )));
    }
    config.save(&paths.config)
}

/// Keep the error's kind (unavailable, config, ...) and add what we were doing.
fn context(what: &str, e: svx_protocol::ProtocolError) -> ClientError {
    match ClientError::from(e) {
        ClientError::Other(m) => ClientError::Other(format!("{what}: {m}")),
        ClientError::Config(m) => ClientError::Config(format!("{what}: {m}")),
        ClientError::Unavailable(m) => ClientError::Unavailable(format!("{what}: {m}")),
        other => other,
    }
}
