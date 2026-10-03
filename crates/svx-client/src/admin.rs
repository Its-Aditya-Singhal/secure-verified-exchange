//! Administration of the user's own organization (requires `svx login` as
//! an org administrator). Authorization is enforced by the service.

use std::collections::BTreeMap;

use svx_protocol::admin::{
    AddAdminRequest, AuditPage, OrgOverview, PutKeyRequest, UpdateOrgRequest,
};
use svx_protocol::{AgentKeys, KeyEntry, KeyKindWire, KeyStatus, ManagedClient, Policy};

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
    audit_page(
        cfg,
        client,
        bearer,
        &AuditQuery {
            limit,
            ..Default::default()
        },
    )
    .await
}

/// Which audit records to fetch: the newest `limit`, optionally older than
/// `before_seq` and of one `event` kind.
#[derive(Clone, Debug, Default)]
pub struct AuditQuery {
    pub limit: u32,
    pub before_seq: Option<i64>,
    pub event: Option<String>,
}

pub async fn audit_page(
    cfg: &ClientConfig,
    client: &ManagedClient,
    bearer: &str,
    q: &AuditQuery,
) -> Result<AuditPage> {
    let mut url = url::Url::parse("http://x/").expect("static URL");
    {
        let mut p = url.query_pairs_mut();
        p.append_pair("limit", &q.limit.to_string());
        if let Some(b) = q.before_seq {
            p.append_pair("before_seq", &b.to_string());
        }
        if let Some(e) = q.event.as_deref().filter(|e| !e.is_empty()) {
            p.append_pair("event", e);
        }
    }
    let query = url.query().unwrap_or_default().to_owned();
    Ok(client
        .get_json_auth(
            &cfg.service_url,
            &format!("{}/audit?{query}", base(cfg)),
            bearer,
        )
        .await?)
}

/// Everything an administrator manages: settings, admins, keys.
pub async fn overview(
    cfg: &ClientConfig,
    client: &ManagedClient,
    bearer: &str,
) -> Result<OrgOverview> {
    Ok(client
        .get_json_auth(&cfg.service_url, &base(cfg), bearer)
        .await?)
}

pub async fn update_org(
    cfg: &ClientConfig,
    client: &ManagedClient,
    bearer: &str,
    req: &UpdateOrgRequest,
) -> Result<()> {
    let _: serde_json::Value = client
        .patch_json(&cfg.service_url, &base(cfg), req, bearer)
        .await?;
    Ok(())
}

pub async fn add_admin(
    cfg: &ClientConfig,
    client: &ManagedClient,
    bearer: &str,
    subject: &str,
) -> Result<()> {
    let _: serde_json::Value = client
        .post_json(
            &cfg.service_url,
            &format!("{}/admins", base(cfg)),
            &AddAdminRequest {
                subject: subject.to_owned(),
            },
            Some(bearer),
        )
        .await?;
    Ok(())
}

pub async fn remove_admin(
    cfg: &ClientConfig,
    client: &ManagedClient,
    bearer: &str,
    subject: &str,
) -> Result<()> {
    let _: serde_json::Value = client
        .delete_auth(
            &cfg.service_url,
            &format!("{}/admins/{}", base(cfg), path_segment(subject)),
            bearer,
        )
        .await?;
    Ok(())
}

pub async fn delete_policy(
    cfg: &ClientConfig,
    client: &ManagedClient,
    bearer: &str,
    name: &str,
) -> Result<()> {
    let _: serde_json::Value = client
        .delete_auth(
            &cfg.service_url,
            &format!("{}/policies/{}", base(cfg), path_segment(name)),
            bearer,
        )
        .await?;
    Ok(())
}

/// Register a public key or change a key's status.
pub async fn put_key(
    cfg: &ClientConfig,
    client: &ManagedClient,
    bearer: &str,
    kind: KeyKindWire,
    public_key: Vec<u8>,
    status: KeyStatus,
) -> Result<KeyEntry> {
    Ok(client
        .put_json(
            &cfg.service_url,
            &format!("{}/keys", base(cfg)),
            &PutKeyRequest {
                kind,
                public_key,
                status,
            },
            bearer,
        )
        .await?)
}

/// The keys a key agent reports it holds (public, unauthenticated).
pub async fn agent_keys(client: &ManagedClient, agent_url: &str) -> Result<AgentKeys> {
    Ok(client.get_json(agent_url, "/v1/agent/keys").await?)
}

/// Percent-encode one URL path segment (subjects can contain `/`, `|`, …).
fn path_segment(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}
