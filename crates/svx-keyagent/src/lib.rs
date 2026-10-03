//! The recipient organization's key agent.
//!
//! It holds the organization's KEM secret keys (X-Wing, the post-quantum
//! hybrid of X25519 and ML-KEM-768, for new files; X25519 for older ones)
//! and releases the
//! **recipient-org share** of an artifact only when *both*:
//!
//! 1. the managed service has authorized the release — proven by a fresh
//!    grant signed with the service's pinned grant key, committing to the
//!    exact header, transaction and client key; and
//! 2. the user authenticates to *this organization's own IdP* with an ID
//!    token whose `nonce` binds the same client key and transaction, and
//!    whose `iss`/`sub` match the grant.
//!
//! Condition 2 means a compromised managed service cannot obtain the org
//! share for itself: it cannot mint the org's ID tokens, and a token it saw
//! from a real user is bound to that user's ephemeral key, not the attacker's.

#![forbid(unsafe_code)]

pub mod config;

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use svx_core::crypto::{
    KemSecretKey, VerifyingKey, header_hash, nonce_binding, os_rng, seal_released_share,
};
use svx_core::format::{EnvelopeRole, Identifier, parse_header_region};
use svx_oidc::{IssuerConfig, Validator};
use svx_protocol::{
    AgentKey, AgentKeys, AgentReleaseRequest, AgentReleaseResponse, DenyReason, ErrorBody,
    KeyKindWire, SealedShare, parse_client_key, unix_now,
};

const MAX_BODY: usize = 3 * 1024 * 1024;

#[derive(Clone)]
pub struct AgentState {
    pub db: sqlx::PgPool,
    pub org_id: Identifier,
    pub idp: IssuerConfig,
    pub service_id: Identifier,
    /// The managed service's grant-signing key, pinned out of band.
    pub service_grant_key: VerifyingKey,
    /// Current and previous KEM keys (rotation, and X25519 keys for older
    /// files); selected by envelope key ID.
    pub kem_keys: Arc<Vec<KemSecretKey>>,
    pub oidc: Arc<Validator>,
}

pub async fn app(state: AgentState) -> anyhow::Result<Router> {
    sqlx::migrate!("./migrations").run(&state.db).await?;
    Ok(Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/agent/release", post(release))
        .route("/v1/agent/keys", get(keys))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state))
}

/// The KEM keys this agent holds: public key IDs and kinds only. An
/// administrator's app activates a new key in the registry only once the
/// agent lists it, so senders never seal files the agent can't open.
async fn keys(State(st): State<AgentState>) -> Json<AgentKeys> {
    Json(AgentKeys {
        org_id: st.org_id.to_string(),
        keys: st
            .kem_keys
            .iter()
            .map(|k| AgentKey {
                key_id: k.public_key().key_id(),
                kind: KeyKindWire::from_key_kind(k.kind()),
            })
            .collect(),
    })
}

struct Denied(DenyReason);

impl IntoResponse for Denied {
    fn into_response(self) -> Response {
        let status = match self.0 {
            DenyReason::InvalidRequest => StatusCode::BAD_REQUEST,
            DenyReason::InvalidArtifact => StatusCode::UNPROCESSABLE_ENTITY,
            DenyReason::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::FORBIDDEN,
        };
        (
            status,
            Json(ErrorBody {
                error: self.0,
                detail: None,
            }),
        )
            .into_response()
    }
}

async fn audit(
    st: &AgentState,
    event: &str,
    subject: Option<&str>,
    artifact: Option<&str>,
    txn: Option<&str>,
    reason: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO agent_audit (at, event, subject, artifact_id, txn, reason) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(unix_now())
    .bind(event)
    .bind(subject)
    .bind(artifact)
    .bind(txn)
    .bind(reason)
    .execute(&st.db)
    .await
    .map(|_| ())
}

async fn refuse(
    st: &AgentState,
    artifact: Option<&str>,
    subject: Option<&str>,
    why: &str,
    r: DenyReason,
) -> Denied {
    if let Err(e) = audit(st, "release_denied", subject, artifact, None, Some(why)).await {
        tracing::error!(error = %e, "agent audit failed");
    }
    Denied(r)
}

async fn release(
    State(st): State<AgentState>,
    Json(req): Json<AgentReleaseRequest>,
) -> Result<Json<AgentReleaseResponse>, Denied> {
    let now = unix_now();
    let Ok((_, header)) = parse_header_region(&req.header_region) else {
        return Err(refuse(
            &st,
            None,
            None,
            "malformed header",
            DenyReason::InvalidArtifact,
        )
        .await);
    };
    let aid = hex::encode(header.artifact_id);
    let a = Some(aid.as_str());

    // 1. The service's grant, pinned key, fresh.
    let grant = match req.grant.verify(&st.service_grant_key, now) {
        Ok(g) => g,
        Err(e) => {
            return Err(refuse(&st, a, None, &e.to_string(), DenyReason::NotAuthorized).await);
        }
    };
    // Only post-quantum hybrid (X-Wing) one-time keys are accepted.
    let Some(client_key) = parse_client_key(&req.client_key) else {
        return Err(refuse(&st, a, None, "bad client key", DenyReason::InvalidRequest).await);
    };
    // The grant must cover exactly this header, org, service, txn and client key.
    let bound = grant.service_id == st.service_id.as_str()
        && header.service_id == st.service_id
        && grant.recipient_org == st.org_id.as_str()
        && header.recipient_org == st.org_id
        && grant.artifact_id == header.artifact_id
        && grant.header_hash == *header_hash(&req.header_region).as_bytes()
        && grant.txn == req.txn
        && grant.client_key_id == client_key.key_id();
    if !bound {
        return Err(refuse(
            &st,
            a,
            Some(&grant.sub),
            "grant does not match request",
            DenyReason::NotAuthorized,
        )
        .await);
    }

    // 2. Independent authentication against this org's own IdP.
    let nonce = nonce_binding(&client_key, &req.txn);
    let who = match st.oidc.validate(&st.idp, &req.id_token, Some(&nonce)).await {
        Ok(w) => w,
        Err(e) => {
            return Err(refuse(&st, a, None, &e.to_string(), DenyReason::NotAuthorized).await);
        }
    };
    if who.sub != grant.sub || who.issuer != grant.issuer {
        return Err(refuse(
            &st,
            a,
            Some(&who.sub),
            "token subject differs from grant",
            DenyReason::NotAuthorized,
        )
        .await);
    }

    // 3. Single use.
    let txn_hex = hex::encode(req.txn);
    let ins = sqlx::query(
        "INSERT INTO agent_txns (txn, artifact_id, subject, at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&req.txn[..])
    .bind(&header.artifact_id[..])
    .bind(&who.sub)
    .bind(now)
    .execute(&st.db)
    .await;
    match ins {
        Ok(_) => {}
        Err(sqlx::Error::Database(d)) if d.code().as_deref() == Some("23505") => {
            return Err(refuse(
                &st,
                a,
                Some(&who.sub),
                "transaction id reused",
                DenyReason::NotAuthorized,
            )
            .await);
        }
        Err(e) => {
            tracing::error!(error = %e, "agent db error");
            return Err(Denied(DenyReason::Unavailable));
        }
    }

    // 4. Unwrap with the KEM key the envelope names, re-seal to the client.
    let env_key = header
        .envelope(EnvelopeRole::RecipientOrg)
        .map(|e| e.key_id);
    let Some(sk) = st
        .kem_keys
        .iter()
        .find(|k| Some(k.public_key().key_id()) == env_key)
    else {
        return Err(refuse(
            &st,
            a,
            Some(&who.sub),
            "no key for envelope",
            DenyReason::InvalidArtifact,
        )
        .await);
    };
    let share = match svx_core::unwrap_envelope(&header, EnvelopeRole::RecipientOrg, sk) {
        Ok(s) => s,
        Err(e) => {
            return Err(refuse(
                &st,
                a,
                Some(&who.sub),
                &e.to_string(),
                DenyReason::InvalidArtifact,
            )
            .await);
        }
    };
    let Ok((encapped_key, ciphertext)) = seal_released_share(
        EnvelopeRole::RecipientOrg,
        &share,
        &client_key,
        &header.artifact_id,
        &req.txn,
        &mut os_rng(),
    ) else {
        return Err(Denied(DenyReason::Unavailable));
    };
    drop(share);

    // Fail closed: no release without an audit record.
    if audit(
        &st,
        "share_released",
        Some(&who.sub),
        a,
        Some(&txn_hex),
        None,
    )
    .await
    .is_err()
    {
        return Err(Denied(DenyReason::Unavailable));
    }
    Ok(Json(AgentReleaseResponse {
        share: SealedShare {
            encapped_key,
            ciphertext,
        },
    }))
}
