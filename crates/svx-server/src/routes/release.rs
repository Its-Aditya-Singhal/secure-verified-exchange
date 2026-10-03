//! Artifact registration and the key-release decision.

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use serde::Deserialize;
use svx_core::VerifiedHead;
use svx_core::crypto::{nonce_binding, os_rng, seal_released_share};
use svx_core::format::{EnvelopeRole, parse_header_region};
use svx_oidc::Identity;
use svx_protocol::encoding::b64;
use svx_protocol::{
    DenyReason, Grant, PROTOCOL_VERSION, ReleaseRequest, ReleaseResponse, SealedShare,
    parse_client_key, unix_now,
};

use super::bearer;
use crate::error::{ApiError, ApiResult, is_unique_violation};
use crate::policy::{self, ArtifactTimes, Deny};
use crate::{AppState, GRANT_TTL_SECS, audit, db};

/// Failures within this window before a `suspicious_repeated_attempts` event.
const SUSPICIOUS_WINDOW_SECS: i64 = 600;
const SUSPICIOUS_THRESHOLD: i64 = 5;

fn deny(r: DenyReason) -> ApiError {
    ApiError::Deny(r)
}

/// Parse and verify the artifact head against the sender's registered keys.
/// Failures are audited to the recipient org when it can be identified.
pub(crate) async fn verified_head(
    st: &AppState,
    header_region: &[u8],
    trailer: &[u8],
) -> ApiResult<VerifiedHead> {
    let (_, header) =
        parse_header_region(header_region).map_err(|_| deny(DenyReason::InvalidArtifact))?;
    if header.service_id != st.service_id {
        return Err(deny(DenyReason::InvalidArtifact));
    }
    let trust = db::sender_trust(&st.db, &header.sender_org, header.created_at).await?;
    match svx_core::verify_head(header_region, trailer, &trust) {
        Ok(h) => Ok(h),
        Err(e) => {
            audit::note(
                &st.db,
                header.recipient_org.as_str(),
                audit::Record {
                    event: audit::event::SIGNATURE_FAILURE,
                    artifact_id: Some(hex::encode(header.artifact_id)),
                    reason: Some(e.to_string()),
                    ..Default::default()
                },
            )
            .await;
            Err(deny(DenyReason::InvalidArtifact))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterArtifactRequest {
    #[serde(with = "b64")]
    header_region: Vec<u8>,
    #[serde(with = "b64")]
    trailer: Vec<u8>,
}

/// Optional: a sender-org user records that an artifact was created. This
/// enables sender-side audit; release does not depend on it.
pub async fn register_artifact(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterArtifactRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let head = verified_head(&st, &req.header_region, &req.trailer).await?;
    let h = &head.header;
    let sender = db::verified_org(&st.db, h.sender_org.as_str())
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let token = bearer(&headers).ok_or(ApiError::Unauthorized)?;
    let who = st
        .oidc
        .validate(&sender.issuer_config(), token, None)
        .await
        .map_err(|_| ApiError::Unauthorized)?;
    let aid = hex::encode(h.artifact_id);
    sqlx::query(
        "INSERT INTO artifacts (artifact_id, sender_org, recipient_org, header_hash, registered_at) \
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (artifact_id) DO NOTHING",
    )
    .bind(&h.artifact_id[..])
    .bind(h.sender_org.as_str())
    .bind(h.recipient_org.as_str())
    .bind(&head.header_hash().as_bytes()[..])
    .bind(unix_now())
    .execute(&st.db)
    .await?;
    audit::append(
        &st.db,
        h.sender_org.as_str(),
        audit::Record {
            event: audit::event::ARTIFACT_REGISTERED,
            subject: Some(who.sub.clone()),
            artifact_id: Some(aid.clone()),
            reason: Some(format!("recipient {}", h.recipient_org)),
            ..Default::default()
        },
    )
    .await?;
    audit::note(
        &st.db,
        h.recipient_org.as_str(),
        audit::Record {
            event: audit::event::ARTIFACT_SHARED,
            subject: Some(audit::pseudonym(&who.issuer, &who.sub)),
            artifact_id: Some(aid.clone()),
            reason: Some(format!("sender {}", h.sender_org)),
            ..Default::default()
        },
    )
    .await;
    Ok(Json(serde_json::json!({ "artifact_id": aid })))
}

/// Record an authorization failure and flag repeated attempts.
async fn authz_failure(
    st: &AppState,
    org: &str,
    who: &Identity,
    aid: &str,
    event: &str,
    reason: &str,
) {
    audit::note(
        &st.db,
        org,
        audit::Record {
            event,
            subject: Some(who.sub.clone()),
            artifact_id: Some(aid.to_owned()),
            reason: Some(reason.to_owned()),
            ..Default::default()
        },
    )
    .await;
    let since = unix_now() - SUSPICIOUS_WINDOW_SECS;
    let failures = [
        audit::event::AUTHZ_FAILURE,
        audit::event::REVOKED_ACCESS,
        audit::event::REPLAY,
    ];
    if let Ok(n) = audit::count_recent(&st.db, org, &who.sub, &failures, since).await
        && n == SUSPICIOUS_THRESHOLD
    {
        audit::note(
            &st.db,
            org,
            audit::Record {
                event: audit::event::SUSPICIOUS,
                subject: Some(who.sub.clone()),
                artifact_id: Some(aid.to_owned()),
                reason: Some(format!("{n} denied attempts in {SUSPICIOUS_WINDOW_SECS}s")),
                ..Default::default()
            },
        )
        .await;
    }
}

/// The key-release decision (`docs/architecture.md` §6).
pub async fn release(
    State(st): State<AppState>,
    Json(req): Json<ReleaseRequest>,
) -> ApiResult<Json<ReleaseResponse>> {
    // 1. Artifact: structure, service binding, sender trust, signature.
    let head = verified_head(&st, &req.header_region, &req.trailer).await?;
    let h = &head.header;
    let aid = hex::encode(h.artifact_id);
    let recipient = db::verified_org(&st.db, h.recipient_org.as_str())
        .await?
        .ok_or(deny(DenyReason::InvalidArtifact))?;
    // Personal files open through /v1/personal/release (sender approval,
    // one-time), never through the company flow.
    if recipient.kind != "company" || h.all_recipients().len() != 1 {
        return Err(deny(DenyReason::InvalidArtifact));
    }
    let org = recipient.org_id.as_str();
    // Only post-quantum hybrid (X-Wing) one-time keys are accepted.
    let client_key = parse_client_key(&req.client_key).ok_or(deny(DenyReason::InvalidRequest))?;

    // 2. Authentication: the recipient org's own IdP, bound to this
    //    client key and transaction through the nonce.
    let nonce = nonce_binding(&client_key, &req.txn);
    let who = match st
        .oidc
        .validate(&recipient.issuer_config(), &req.id_token, Some(&nonce))
        .await
    {
        Ok(w) => w,
        Err(e) => {
            audit::note(
                &st.db,
                org,
                audit::Record {
                    event: audit::event::AUTHN_FAILURE,
                    artifact_id: Some(aid),
                    reason: Some(e.to_string()),
                    ..Default::default()
                },
            )
            .await;
            return Err(deny(DenyReason::NotAuthorized));
        }
    };

    // 3. Revocation by either party named in the signed header.
    if db::is_revoked(&st.db, &h.artifact_id, h.sender_org.as_str(), org).await? {
        authz_failure(
            &st,
            org,
            &who,
            &aid,
            audit::event::REVOKED_ACCESS,
            "artifact revoked",
        )
        .await;
        return Err(deny(DenyReason::ExpiredOrRevoked));
    }

    // 4. Policy (defined by the recipient org) and server-clock expiry.
    let Some(pol) = db::policy(&st.db, org, h.policy_ref.as_str()).await? else {
        authz_failure(
            &st,
            org,
            &who,
            &aid,
            audit::event::AUTHZ_FAILURE,
            "unknown policy",
        )
        .await;
        return Err(deny(DenyReason::NotAuthorized));
    };
    let times = ArtifactTimes {
        created_at: h.created_at,
        expires_at: h.expires_at,
    };
    match policy::evaluate(&pol, &who, times, unix_now()) {
        Ok(()) => {}
        Err(Deny::Expired) => {
            audit::note(
                &st.db,
                org,
                audit::Record {
                    event: audit::event::ARTIFACT_EXPIRED,
                    subject: Some(who.sub.clone()),
                    artifact_id: Some(aid),
                    ..Default::default()
                },
            )
            .await;
            return Err(deny(DenyReason::ExpiredOrRevoked));
        }
        Err(d) => {
            authz_failure(
                &st,
                org,
                &who,
                &aid,
                audit::event::AUTHZ_FAILURE,
                d.as_str(),
            )
            .await;
            return Err(deny(DenyReason::NotAuthorized));
        }
    }

    // 5. Single-use transaction.
    let txn_hex = hex::encode(req.txn);
    let inserted = sqlx::query(
        "INSERT INTO release_txns (txn, artifact_id, org_id, at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&req.txn[..])
    .bind(&h.artifact_id[..])
    .bind(org)
    .bind(unix_now())
    .execute(&st.db)
    .await;
    match inserted {
        Ok(_) => {}
        Err(e) if is_unique_violation(&e) => {
            authz_failure(
                &st,
                org,
                &who,
                &aid,
                audit::event::REPLAY,
                "transaction id reused",
            )
            .await;
            return Err(deny(DenyReason::NotAuthorized));
        }
        Err(e) => return Err(e.into()),
    }

    // 6. Release: unwrap the service share and re-seal it to the client.
    let share = match st.keys.unwrap_service_share(&head) {
        Ok(s) => s,
        Err(e) => {
            audit::note(
                &st.db,
                org,
                audit::Record {
                    event: audit::event::KEY_RELEASE_FAILURE,
                    subject: Some(who.sub.clone()),
                    artifact_id: Some(aid),
                    reason: Some(e.to_string()),
                    ..Default::default()
                },
            )
            .await;
            return Err(deny(DenyReason::InvalidArtifact));
        }
    };
    let (encapped_key, ciphertext) = seal_released_share(
        EnvelopeRole::Service,
        &share,
        &client_key,
        &h.artifact_id,
        &req.txn,
        &mut os_rng(),
    )
    .map_err(|e| ApiError::Internal(e.to_string()))?;
    drop(share);

    let now = unix_now();
    let grant = st
        .keys
        .sign_grant(&Grant {
            v: PROTOCOL_VERSION,
            service_id: st.service_id.to_string(),
            artifact_id: h.artifact_id,
            header_hash: *head.header_hash().as_bytes(),
            recipient_org: org.to_owned(),
            issuer: who.issuer.clone(),
            sub: who.sub.clone(),
            client_key_id: client_key.key_id(),
            txn: req.txn,
            iat: now,
            exp: now + GRANT_TTL_SECS,
        })
        .map_err(|e| ApiError::Internal(format!("signing the grant: {e}")))?;

    // Fail closed: no release without an audit record.
    audit::append(
        &st.db,
        org,
        audit::Record {
            event: audit::event::DECRYPTION_AUTHORIZED,
            subject: Some(who.sub.clone()),
            artifact_id: Some(aid.clone()),
            txn: Some(txn_hex.clone()),
            reason: Some(format!("policy {}", h.policy_ref)),
        },
    )
    .await?;
    audit::note(
        &st.db,
        h.sender_org.as_str(),
        audit::Record {
            event: audit::event::DECRYPTION_AUTHORIZED,
            subject: Some(audit::pseudonym(&who.issuer, &who.sub)),
            artifact_id: Some(aid),
            txn: Some(txn_hex),
            reason: Some(format!("recipient {org}")),
        },
    )
    .await;

    Ok(Json(ReleaseResponse {
        share: SealedShare {
            encapped_key,
            ciphertext,
        },
        grant,
    }))
}
