//! Organization administration. Every handler starts with
//! [`require_admin`](super::require_admin).

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use serde::Deserialize;
use svx_protocol::admin::{
    AddAdminRequest, AdminEntry, AuditPage, KeyDetail, OrgOverview, PutKeyRequest, UpdateOrgRequest,
};
use svx_protocol::{KeyEntry, KeyStatus, Policy, check_url, unix_now};

use super::require_admin;
use crate::error::{ApiError, ApiResult};
use crate::{AppState, audit, db};

pub async fn put_key(
    State(st): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
    Json(req): Json<PutKeyRequest>,
) -> ApiResult<Json<KeyEntry>> {
    let admin = require_admin(&st, &org, &headers).await?;
    // Parses the key with exact-length checks for its kind.
    let key_id = req
        .kind
        .key_id_of(&req.public_key)
        .ok_or_else(|| ApiError::BadRequest(format!("invalid {} key", req.kind.as_str())))?;
    let now = unix_now();
    let existing = db::keys(&st.db, &org)
        .await?
        .into_iter()
        .find(|k| k.key_id == key_id);
    match existing {
        Some(k) => {
            let cur = KeyStatus::parse(&k.status)
                .ok_or_else(|| ApiError::Internal("bad key status".into()))?;
            if !cur.can_become(req.status) {
                return Err(ApiError::Conflict(format!(
                    "key cannot move from {} to {}",
                    cur.as_str(),
                    req.status.as_str()
                )));
            }
            sqlx::query(
                "UPDATE org_keys SET status = $3, \
                 retired_at = CASE WHEN $3 IN ('retired', 'revoked') THEN COALESCE(retired_at, $4) ELSE retired_at END, \
                 revoked_at = CASE WHEN $3 = 'revoked' THEN COALESCE(revoked_at, $4) ELSE revoked_at END \
                 WHERE org_id = $1 AND key_id = $2",
            )
            .bind(&org)
            .bind(&key_id[..])
            .bind(req.status.as_str())
            .bind(now)
            .execute(&st.db)
            .await?;
        }
        None => {
            sqlx::query(
                "INSERT INTO org_keys (org_id, key_id, kind, public_key, status, created_at, retired_at, revoked_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(&org)
            .bind(&key_id[..])
            .bind(req.kind.as_str())
            .bind(&req.public_key[..])
            .bind(req.status.as_str())
            .bind(now)
            .bind((req.status != KeyStatus::Active).then_some(now))
            .bind((req.status == KeyStatus::Revoked).then_some(now))
            .execute(&st.db)
            .await?;
        }
    }
    audit::append(
        &st.db,
        &org,
        audit::Record {
            event: audit::event::KEY_CHANGED,
            subject: Some(admin.identity.sub),
            reason: Some(format!(
                "{} {} -> {}",
                req.kind.as_str(),
                hex::encode(key_id),
                req.status.as_str()
            )),
            ..Default::default()
        },
    )
    .await?;
    Ok(Json(KeyEntry {
        key_id,
        kind: req.kind,
        public_key: req.public_key,
        status: req.status,
    }))
}

pub async fn add_admin(
    State(st): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
    Json(req): Json<AddAdminRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = require_admin(&st, &org, &headers).await?;
    if req.subject.is_empty() || req.subject.len() > 255 {
        return Err(ApiError::BadRequest("invalid subject".into()));
    }
    sqlx::query("INSERT INTO org_admins (org_id, subject, added_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(&admin.org_id)
        .bind(&req.subject)
        .bind(unix_now())
        .execute(&st.db)
        .await?;
    audit::append(
        &st.db,
        &org,
        audit::Record {
            event: audit::event::ADMIN_ADDED,
            subject: Some(admin.identity.sub),
            reason: Some(format!("added {}", req.subject)),
            ..Default::default()
        },
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub async fn put_policy(
    State(st): State<AppState>,
    Path((org, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(policy): Json<Policy>,
) -> ApiResult<Json<Policy>> {
    let admin = require_admin(&st, &org, &headers).await?;
    svx_core::format::Identifier::new(&name)
        .map_err(|_| ApiError::BadRequest("invalid policy name".into()))?;
    policy.validate().map_err(ApiError::BadRequest)?;
    sqlx::query(
        "INSERT INTO policies (org_id, name, document, updated_at) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (org_id, name) DO UPDATE SET document = EXCLUDED.document, updated_at = EXCLUDED.updated_at",
    )
    .bind(&admin.org_id)
    .bind(&name)
    .bind(sqlx::types::Json(&policy))
    .bind(unix_now())
    .execute(&st.db)
    .await?;
    audit::append(
        &st.db,
        &org,
        audit::Record {
            event: audit::event::POLICY_CHANGED,
            subject: Some(admin.identity.sub),
            reason: Some(format!("policy {name}")),
            ..Default::default()
        },
    )
    .await?;
    Ok(Json(policy))
}

/// Revoke future access. Effective only for artifacts whose signed header
/// names this org as sender or recipient (checked at release time), so one
/// org cannot revoke another's exchanges.
pub async fn revoke(
    State(st): State<AppState>,
    Path((org, artifact_hex)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = require_admin(&st, &org, &headers).await?;
    let mut artifact_id = [0u8; 16];
    hex::decode_to_slice(&artifact_hex, &mut artifact_id)
        .map_err(|_| ApiError::BadRequest("artifact_id must be 32 hex characters".into()))?;
    let registered: Option<(String, String)> =
        sqlx::query_as("SELECT sender_org, recipient_org FROM artifacts WHERE artifact_id = $1")
            .bind(&artifact_id[..])
            .fetch_optional(&st.db)
            .await?;
    if let Some((s, r)) = registered
        && s != org
        && r != org
    {
        return Err(ApiError::Unauthorized);
    }
    sqlx::query("INSERT INTO revocations (artifact_id, revoked_by_org, at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(&artifact_id[..])
        .bind(&org)
        .bind(unix_now())
        .execute(&st.db)
        .await?;
    audit::append(
        &st.db,
        &org,
        audit::Record {
            event: audit::event::ARTIFACT_REVOKED,
            subject: Some(admin.identity.sub),
            artifact_id: Some(artifact_hex.to_ascii_lowercase()),
            ..Default::default()
        },
    )
    .await?;
    Ok(Json(
        serde_json::json!({ "revoked": artifact_hex.to_ascii_lowercase() }),
    ))
}

#[derive(Deserialize)]
pub struct AuditQuery {
    limit: Option<i64>,
    before_seq: Option<i64>,
    event: Option<String>,
}

pub async fn audit(
    State(st): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Json<AuditPage>> {
    let admin = require_admin(&st, &org, &headers).await?;
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let event = q.event.as_deref().filter(|e| !e.is_empty());
    if event.is_some_and(|e| e.len() > 64) {
        return Err(ApiError::BadRequest("invalid event filter".into()));
    }
    let (entries, chain_valid) =
        audit::list(&st.db, &admin.org_id, limit, q.before_seq, event).await?;
    Ok(Json(AuditPage {
        entries,
        chain_valid,
    }))
}

/// All policies of the org, by name.
pub async fn list_policies(
    State(st): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<std::collections::BTreeMap<String, Policy>>> {
    let admin = require_admin(&st, &org, &headers).await?;
    let rows: Vec<(String, sqlx::types::Json<Policy>)> =
        sqlx::query_as("SELECT name, document FROM policies WHERE org_id = $1 ORDER BY name")
            .bind(&admin.org_id)
            .fetch_all(&st.db)
            .await?;
    Ok(Json(rows.into_iter().map(|(n, j)| (n, j.0)).collect()))
}

/// Everything an administrator manages for their organization.
pub async fn overview(
    State(st): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<OrgOverview>> {
    let admin = require_admin(&st, &org, &headers).await?;
    let o = db::verified_org(&st.db, &admin.org_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let admins = db::admins(&st.db, &admin.org_id)
        .await?
        .into_iter()
        .map(|(subject, added_at)| AdminEntry { subject, added_at })
        .collect();
    let keys = db::keys(&st.db, &admin.org_id)
        .await?
        .iter()
        .filter_map(|k| {
            let e = k.to_entry()?;
            Some(KeyDetail {
                key_id: e.key_id,
                kind: e.kind,
                public_key: e.public_key,
                status: e.status,
                created_at: k.created_at,
                retired_at: k.retired_at,
                revoked_at: k.revoked_at,
            })
        })
        .collect();
    Ok(Json(OrgOverview {
        org_id: o.org_id,
        display_name: o.display_name,
        domain: o.domain,
        idp_issuer: o.idp_issuer,
        idp_client_id: o.idp_client_id,
        group_claim: o.group_claim,
        key_agent_url: o.key_agent_url,
        verified_at: o.verified_at.unwrap_or_default(),
        admins,
        keys,
    }))
}

/// Change the display name or the key agent URL.
pub async fn update_org(
    State(st): State<AppState>,
    Path(org): Path<String>,
    headers: HeaderMap,
    Json(req): Json<UpdateOrgRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = require_admin(&st, &org, &headers).await?;
    if req.remove_key_agent && req.key_agent_url.is_some() {
        return Err(ApiError::BadRequest(
            "set a key agent URL or remove it, not both".into(),
        ));
    }
    if let Some(n) = &req.display_name
        && !super::orgs::valid_display_name(n)
    {
        return Err(ApiError::BadRequest("invalid display_name".into()));
    }
    if let Some(u) = &req.key_agent_url {
        check_url(u, st.dev)
            .map_err(|_| ApiError::BadRequest("key_agent_url must be an https URL".into()))?;
    }
    let mut changes = Vec::new();
    if let Some(n) = &req.display_name {
        sqlx::query("UPDATE orgs SET display_name = $2 WHERE org_id = $1")
            .bind(&admin.org_id)
            .bind(n)
            .execute(&st.db)
            .await?;
        changes.push("display name".to_owned());
    }
    if req.remove_key_agent || req.key_agent_url.is_some() {
        sqlx::query("UPDATE orgs SET key_agent_url = $2 WHERE org_id = $1")
            .bind(&admin.org_id)
            .bind(&req.key_agent_url)
            .execute(&st.db)
            .await?;
        changes.push(match &req.key_agent_url {
            Some(u) => format!("key agent {u}"),
            None => "key agent removed".to_owned(),
        });
    }
    if changes.is_empty() {
        return Err(ApiError::BadRequest("nothing to change".into()));
    }
    audit::append(
        &st.db,
        &org,
        audit::Record {
            event: audit::event::ORG_CHANGED,
            subject: Some(admin.identity.sub),
            reason: Some(changes.join(", ")),
            ..Default::default()
        },
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Remove an administrator. The last one can't be removed, so an
/// organization is never left without anyone able to manage it.
pub async fn remove_admin(
    State(st): State<AppState>,
    Path((org, subject)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = require_admin(&st, &org, &headers).await?;
    let mut tx = st.db.begin().await?;
    // Serialize removals per org so two admins can't remove each other at once.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('admins:' || $1))")
        .bind(&admin.org_id)
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM org_admins WHERE org_id = $1")
        .bind(&admin.org_id)
        .fetch_one(&mut *tx)
        .await?;
    let removed = sqlx::query("DELETE FROM org_admins WHERE org_id = $1 AND subject = $2")
        .bind(&admin.org_id)
        .bind(&subject)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if removed == 0 {
        return Err(ApiError::NotFound);
    }
    if count <= 1 {
        return Err(ApiError::Conflict(
            "the last administrator can't be removed".into(),
        ));
    }
    tx.commit().await?;
    audit::append(
        &st.db,
        &org,
        audit::Record {
            event: audit::event::ADMIN_REMOVED,
            subject: Some(admin.identity.sub),
            reason: Some(format!("removed {subject}")),
            ..Default::default()
        },
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Delete a policy. Artifacts that name it are denied from then on.
pub async fn delete_policy(
    State(st): State<AppState>,
    Path((org, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let admin = require_admin(&st, &org, &headers).await?;
    let removed = sqlx::query("DELETE FROM policies WHERE org_id = $1 AND name = $2")
        .bind(&admin.org_id)
        .bind(&name)
        .execute(&st.db)
        .await?
        .rows_affected();
    if removed == 0 {
        return Err(ApiError::NotFound);
    }
    audit::append(
        &st.db,
        &org,
        audit::Record {
            event: audit::event::POLICY_CHANGED,
            subject: Some(admin.identity.sub),
            reason: Some(format!("policy {name} deleted")),
            ..Default::default()
        },
    )
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
