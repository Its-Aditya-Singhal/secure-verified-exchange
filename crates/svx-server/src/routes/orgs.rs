//! Organization registration and domain verification.

use axum::Json;
use axum::extract::{Path, State};
use svx_core::crypto::random_bytes;
use svx_core::format::Identifier;
use svx_protocol::admin::{RegisterOrgRequest, RegisterOrgResponse, VerifyOrgRequest};
use svx_protocol::{check_url, unix_now};

use crate::error::{ApiError, ApiResult, is_unique_violation};
use crate::{AppState, audit, db};

/// Pending registrations older than this can be taken over (anti-squatting).
const PENDING_TTL_SECS: i64 = 7 * 24 * 3600;
const MAX_TEXT: usize = 255;

pub fn txt_name(domain: &str) -> String {
    format!("_svx-challenge.{domain}")
}

fn valid_domain(d: &str) -> bool {
    let labels: Vec<&str> = d.split('.').collect();
    d.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

pub(crate) fn valid_display_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= MAX_TEXT && !n.chars().any(char::is_control)
}

fn bad(msg: &str) -> ApiError {
    ApiError::BadRequest(msg.to_owned())
}

pub async fn register(
    State(st): State<AppState>,
    Json(req): Json<RegisterOrgRequest>,
) -> ApiResult<Json<RegisterOrgResponse>> {
    Identifier::new(&req.org_id).map_err(|_| bad("invalid org_id"))?;
    if !valid_domain(&req.domain) {
        return Err(bad("invalid domain"));
    }
    check_url(&req.idp_issuer, st.dev).map_err(|_| bad("idp_issuer must be an https URL"))?;
    if let Some(u) = &req.key_agent_url {
        check_url(u, st.dev).map_err(|_| bad("key_agent_url must be an https URL"))?;
    }
    if !valid_display_name(&req.display_name) {
        return Err(bad("invalid display_name"));
    }
    if req.idp_client_id.is_empty() || req.idp_client_id.len() > MAX_TEXT {
        return Err(bad("invalid idp_client_id"));
    }
    let group_claim = req.group_claim.clone().unwrap_or_else(|| "groups".into());
    if group_claim.is_empty()
        || group_claim.len() > 64
        || !group_claim.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(bad("invalid group_claim"));
    }

    let now = unix_now();
    if let Some(existing) = db::org(&st.db, &req.org_id).await? {
        if existing.verified_at.is_some() || now - existing.created_at < PENDING_TTL_SECS {
            return Err(ApiError::Conflict("org_id already registered".into()));
        }
        sqlx::query("DELETE FROM orgs WHERE org_id = $1 AND verified_at IS NULL")
            .bind(&req.org_id)
            .execute(&st.db)
            .await?;
    }

    let challenge = hex::encode(random_bytes::<16>());
    sqlx::query(
        "INSERT INTO orgs (org_id, display_name, domain, idp_issuer, idp_client_id, group_claim, key_agent_url, \
         challenge, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(&req.org_id)
    .bind(&req.display_name)
    .bind(&req.domain)
    .bind(&req.idp_issuer)
    .bind(&req.idp_client_id)
    .bind(&group_claim)
    .bind(&req.key_agent_url)
    .bind(&challenge)
    .bind(now)
    .execute(&st.db)
    .await?;
    audit::note(
        &st.db,
        &req.org_id,
        audit::Record {
            event: audit::event::ORG_REGISTERED,
            reason: Some(format!("domain {}", req.domain)),
            ..Default::default()
        },
    )
    .await;

    Ok(Json(RegisterOrgResponse {
        txt_name: txt_name(&req.domain),
        txt_value: format!("svx-verification={challenge}"),
    }))
}

/// Prove domain control (DNS TXT) and IdP control (an ID token from the
/// configured IdP). The token's subject becomes the first administrator.
pub async fn verify(
    State(st): State<AppState>,
    Path(org_id): Path<String>,
    Json(req): Json<VerifyOrgRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let org = db::org(&st.db, &org_id).await?.ok_or(ApiError::NotFound)?;
    if org.verified_at.is_some() {
        return Err(ApiError::Conflict("already verified".into()));
    }
    let expected = format!("svx-verification={}", org.challenge);
    let records = st
        .dns
        .txt(&txt_name(&org.domain))
        .await
        .map_err(|e| ApiError::BadRequest(format!("DNS lookup failed: {e}")))?;
    if !records.iter().any(|r| r.trim() == expected) {
        return Err(bad("DNS challenge record not found"));
    }
    let identity = st
        .oidc
        .validate(&org.issuer_config(), &req.id_token, None)
        .await
        .map_err(|_| ApiError::Unauthorized)?;

    let now = unix_now();
    let mut tx = st.db.begin().await?;
    let updated =
        sqlx::query("UPDATE orgs SET verified_at = $2 WHERE org_id = $1 AND verified_at IS NULL")
            .bind(&org_id)
            .bind(now)
            .execute(&mut *tx)
            .await;
    match updated {
        Err(e) if is_unique_violation(&e) => {
            return Err(ApiError::Conflict(
                "domain already belongs to a verified organization".into(),
            ));
        }
        r => {
            r?;
        }
    }
    sqlx::query("INSERT INTO org_admins (org_id, subject, added_at) VALUES ($1, $2, $3)")
        .bind(&org_id)
        .bind(&identity.sub)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    audit::note(
        &st.db,
        &org_id,
        audit::Record {
            event: audit::event::ORG_VERIFIED,
            subject: Some(identity.sub.clone()),
            ..Default::default()
        },
    )
    .await;
    Ok(Json(
        serde_json::json!({ "org_id": org_id, "verified_at": now }),
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn domains() {
        for ok in ["example.com", "acme-security.example", "a.b.c.d"] {
            assert!(super::valid_domain(ok), "{ok}");
        }
        for bad in [
            "",
            "localhost",
            "Example.com",
            "-a.com",
            "a-.com",
            "a..com",
            "a.com.",
            "exa mple.com",
        ] {
            assert!(!super::valid_domain(bad), "{bad}");
        }
    }
}
