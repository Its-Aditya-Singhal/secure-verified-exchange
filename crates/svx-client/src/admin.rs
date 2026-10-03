//! Administration of the user's own organization (requires `svx login` as
//! an org administrator). Authorization is enforced by the service.

use std::collections::BTreeMap;

use svx_protocol::admin::AuditPage;
use svx_protocol::{ManagedClient, Policy};

use crate::config::ClientConfig;
use crate::error::Result;

fn base(cfg: &ClientConfig) -> String {
    format!("/v1/admin/orgs/{}", cfg.org_id)
}

pub async fn revoke(
    cfg: &ClientConfig,
    client: &ManagedClient,
    bearer: &str,
    artifact_id: &[u8; 16],
) -> Result<()> {
    let _: serde_json::Value = client
        .post_json(
            &cfg.service_url,
            &format!(
                "{}/artifacts/{}/revoke",
                base(cfg),
                hex::encode(artifact_id)
            ),
            &(),
            Some(bearer),
        )
        .await?;
    Ok(())
}

pub async fn list_policies(
    cfg: &ClientConfig,
    client: &ManagedClient,
    bearer: &str,
) -> Result<BTreeMap<String, Policy>> {
    Ok(client
        .get_json_auth(&cfg.service_url, &format!("{}/policies", base(cfg)), bearer)
        .await?)
}

pub async fn set_policy(
    cfg: &ClientConfig,
    client: &ManagedClient,
    bearer: &str,
    name: &str,
    policy: &Policy,
) -> Result<Policy> {
    Ok(client
        .put_json(
            &cfg.service_url,
            &format!("{}/policies/{name}", base(cfg)),
            policy,
            bearer,
        )
        .await?)
}

pub async fn audit(
    cfg: &ClientConfig,
    client: &ManagedClient,
    bearer: &str,
    limit: u32,
) -> Result<AuditPage> {
    Ok(client
        .get_json_auth(
            &cfg.service_url,
            &format!("{}/audit?limit={limit}", base(cfg)),
            bearer,
        )
        .await?)
}
