//! Typed queries. Every tenant-scoped query takes the org ID explicitly;
//! handlers derive it from an authenticated principal or a verified header.

use sqlx::{FromRow, PgPool};
use svx_core::TrustStore;
use svx_core::crypto::VerifyingKey;
use svx_core::format::Identifier;
use svx_oidc::IssuerConfig;
use svx_protocol::{KeyEntry, KeyKindWire, KeyStatus, Policy};

#[derive(Clone, Debug, FromRow)]
pub struct OrgRow {
    pub org_id: String,
    pub display_name: String,
    pub domain: String,
    pub idp_issuer: String,
    pub idp_client_id: String,
    pub group_claim: String,
    pub key_agent_url: Option<String>,
    pub challenge: String,
    pub created_at: i64,
    pub verified_at: Option<i64>,
}

impl OrgRow {
    pub fn issuer_config(&self) -> IssuerConfig {
        IssuerConfig {
            issuer: self.idp_issuer.clone(),
            client_id: self.idp_client_id.clone(),
            group_claim: self.group_claim.clone(),
        }
    }
}

#[derive(Clone, Debug, FromRow)]
pub struct KeyRow {
    pub key_id: Vec<u8>,
    pub kind: String,
    pub public_key: Vec<u8>,
    pub status: String,
    pub created_at: i64,
    pub retired_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

impl KeyRow {
    pub fn to_entry(&self) -> Option<KeyEntry> {
        Some(KeyEntry {
            key_id: self.key_id.as_slice().try_into().ok()?,
            kind: KeyKindWire::parse(&self.kind)?,
            public_key: self.public_key.as_slice().try_into().ok()?,
            status: KeyStatus::parse(&self.status)?,
        })
    }
}

pub async fn org(db: &PgPool, org_id: &str) -> Result<Option<OrgRow>, sqlx::Error> {
    sqlx::query_as::<_, OrgRow>("SELECT * FROM orgs WHERE org_id = $1")
        .bind(org_id)
        .fetch_optional(db)
        .await
}

pub async fn verified_org(db: &PgPool, org_id: &str) -> Result<Option<OrgRow>, sqlx::Error> {
    Ok(org(db, org_id).await?.filter(|o| o.verified_at.is_some()))
}

pub async fn keys(db: &PgPool, org_id: &str) -> Result<Vec<KeyRow>, sqlx::Error> {
    sqlx::query_as::<_, KeyRow>(
        "SELECT key_id, kind, public_key, status, created_at, retired_at, revoked_at \
         FROM org_keys WHERE org_id = $1 ORDER BY created_at, key_id",
    )
    .bind(org_id)
    .fetch_all(db)
    .await
}

/// Signing keys of `org` acceptable for an artifact signed at `created_at`:
/// active keys, and retired keys for artifacts created before retirement.
/// Revoked keys are never accepted.
pub async fn sender_trust(
    db: &PgPool,
    org: &Identifier,
    created_at: i64,
) -> Result<TrustStore, sqlx::Error> {
    let mut trust = TrustStore::new();
    if verified_org(db, org.as_str()).await?.is_none() {
        return Ok(trust);
    }
    for k in keys(db, org.as_str()).await? {
        if k.kind != "ed25519" {
            continue;
        }
        let usable = match k.status.as_str() {
            "active" => true,
            "retired" => k.retired_at.is_some_and(|r| created_at <= r),
            _ => false,
        };
        let Ok(pk) = <[u8; 32]>::try_from(k.public_key.as_slice()) else {
            continue;
        };
        if let (true, Ok(vk)) = (usable, VerifyingKey::from_bytes(&pk)) {
            trust.add(org.clone(), vk);
        }
    }
    Ok(trust)
}

pub async fn policy(db: &PgPool, org_id: &str, name: &str) -> Result<Option<Policy>, sqlx::Error> {
    let doc: Option<sqlx::types::Json<Policy>> =
        sqlx::query_scalar("SELECT document FROM policies WHERE org_id = $1 AND name = $2")
            .bind(org_id)
            .bind(name)
            .fetch_optional(db)
            .await?;
    Ok(doc.map(|j| j.0))
}

pub async fn is_admin(db: &PgPool, org_id: &str, subject: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM org_admins WHERE org_id = $1 AND subject = $2)",
    )
    .bind(org_id)
    .bind(subject)
    .fetch_one(db)
    .await
}

/// Revoked by either party named in the artifact's signed header.
pub async fn is_revoked(
    db: &PgPool,
    artifact_id: &[u8; 16],
    sender: &str,
    recipient: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM revocations WHERE artifact_id = $1 AND revoked_by_org IN ($2, $3))",
    )
    .bind(&artifact_id[..])
    .bind(sender)
    .bind(recipient)
    .fetch_one(db)
    .await
}
