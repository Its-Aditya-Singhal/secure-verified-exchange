//! Relayed sign-in for providers that don't support desktop apps directly
//! (Apple: no loopback redirects, and a client secret only the service may
//! hold).
//!
//! 1. The app sends `POST /v1/auth/relay/start` with the ID-token nonce
//!    (which binds its device keys) and `SHA-256(secret)`. The service makes
//!    the authorization URL (state, PKCE) and the app opens it.
//! 2. The provider sends the browser to `/v1/auth/relay/callback`. The
//!    service exchanges the code (with its client secret and the PKCE
//!    verifier) and validates the ID token, including the nonce.
//! 3. The app collects the token with `POST /v1/auth/relay/poll` and the
//!    secret, once. It then signs up as with any other provider.
//!
//! The browser never sees the token, and a token is useless for any keys
//! other than the ones its nonce binds.

use axum::Json;
use axum::extract::{Form, Query, State};
use axum::http::header;
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;
use sqlx::FromRow;
use svx_core::crypto::random_bytes;
use svx_oidc::IssuerConfig;
use svx_protocol::ManagedClient;
use svx_protocol::oidc_login::{AuthorizeParams, Pkce, authorize_url, discover, exchange_code};
use svx_protocol::personal::{
    RelayPollRequest, RelayPollResponse, RelayStartRequest, RelayStartResponse, relay_secret_hash,
};
use svx_protocol::unix_now;

use crate::AppState;
use crate::error::{ApiError, ApiResult};
use crate::relay::APPLE_ISSUER;

/// How long a relayed sign-in may take.
pub const RELAY_TTL_SECS: i64 = 600;
/// Relayed sign-ins started per minute (whole service).
const STARTS_PER_MINUTE: u32 = 600;

fn bad(m: &str) -> ApiError {
    ApiError::BadRequest(m.into())
}

/// `POST /v1/auth/relay/start`.
pub async fn start(
    State(st): State<AppState>,
    Json(req): Json<RelayStartRequest>,
) -> ApiResult<Json<RelayStartResponse>> {
    if !st.limiter.allow("relay-start", STARTS_PER_MINUTE) {
        return Err(ApiError::Conflict(
            "too many sign-ins right now; try again in a minute".into(),
        ));
    }
    let idp = st
        .personal_idps
        .iter()
        .find(|p| p.issuer == req.issuer && p.relay)
        .ok_or_else(|| bad("this provider isn't relayed by this service"))?;
    let redirect_uri = st
        .relay
        .redirect_uri
        .clone()
        .ok_or_else(|| bad("this service has no public URL for relayed sign-in"))?;
    if req.nonce.is_empty()
        || req.nonce.len() > 128
        || !req.nonce.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err(bad("invalid nonce"));
    }
    let d = discover(&provider_client(&st)?, &idp.issuer)
        .await
        .map_err(|e| ApiError::Internal(format!("provider discovery: {e}")))?;
    let pkce = Pkce::new();
    let state = hex::encode(random_bytes::<32>());
    let mut url = authorize_url(
        &d,
        &AuthorizeParams {
            client_id: &idp.client_id,
            redirect_uri: &redirect_uri,
            state: &state,
            nonce: &req.nonce,
            pkce: &pkce,
            login_hint: None,
        },
    )
    .map_err(|e| ApiError::Internal(e.to_string()))?;
    // Apple requires a form POST when the email scope is requested.
    url.query_pairs_mut()
        .append_pair("response_mode", "form_post");

    let now = unix_now();
    sqlx::query("DELETE FROM relay_logins WHERE created_at < $1")
        .bind(now - RELAY_TTL_SECS)
        .execute(&st.db)
        .await?;
    let relay_id = random_bytes::<16>();
    sqlx::query(
        "INSERT INTO relay_logins (relay_id, state, issuer, nonce, secret_hash, pkce_verifier, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&relay_id[..])
    .bind(&state)
    .bind(&idp.issuer)
    .bind(&req.nonce)
    .bind(&req.secret_hash[..])
    .bind(&pkce.verifier)
    .bind(now)
    .execute(&st.db)
    .await?;
    Ok(Json(RelayStartResponse {
        relay_id,
        authorize_url: url.to_string(),
        expires_at: now + RELAY_TTL_SECS,
    }))
}

fn provider_client(st: &AppState) -> ApiResult<ManagedClient> {
    ManagedClient::new(st.dev).map_err(|e| ApiError::Internal(e.to_string()))
}

#[derive(Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(FromRow)]
struct Pending {
    relay_id: Vec<u8>,
    issuer: String,
    nonce: String,
    pkce_verifier: String,
}

const PAGE_OK: &str = "<!doctype html><meta charset=utf-8><title>Secure Verified Exchange</title>\
<p>You're signed in. Return to Secure Verified Exchange to continue.</p>";
const PAGE_FAIL: &str = "<!doctype html><meta charset=utf-8><title>Secure Verified Exchange</title>\
<p>Sign-in didn't complete. Return to Secure Verified Exchange and try again.</p>";

fn page(body: &'static str) -> Response {
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::CONTENT_SECURITY_POLICY, "default-src 'none'"),
        ],
        Html(body),
    )
        .into_response()
}

/// `GET /v1/auth/relay/callback` (query) and `POST` (Apple's form post).
pub async fn callback_get(State(st): State<AppState>, Query(p): Query<CallbackParams>) -> Response {
    callback(&st, p).await
}

pub async fn callback_post(State(st): State<AppState>, Form(p): Form<CallbackParams>) -> Response {
    callback(&st, p).await
}

async fn callback(st: &AppState, p: CallbackParams) -> Response {
    let Some(state) = p.state.filter(|s| s.len() == 64) else {
        return page(PAGE_FAIL);
    };
    // Each state completes once.
    let pending: Option<Pending> = match sqlx::query_as(
        "UPDATE relay_logins SET state = state || '-used' \
         WHERE state = $1 AND created_at >= $2 AND id_token IS NULL AND error IS NULL \
         RETURNING relay_id, issuer, nonce, pkce_verifier",
    )
    .bind(&state)
    .bind(unix_now() - RELAY_TTL_SECS)
    .fetch_optional(&st.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "relay callback");
            return page(PAGE_FAIL);
        }
    };
    let Some(pending) = pending else {
        return page(PAGE_FAIL);
    };
    let outcome = match (p.error, p.code) {
        (Some(_), _) | (None, None) => Err("the provider didn't complete the sign-in".to_owned()),
        (None, Some(code)) => finish(st, &pending, &code).await,
    };
    let (token, error) = match outcome {
        Ok(t) => (Some(t), None),
        Err(e) => {
            tracing::warn!(error = %e, issuer = %pending.issuer, "relayed sign-in failed");
            (None, Some(e))
        }
    };
    let ok = token.is_some();
    if let Err(e) =
        sqlx::query("UPDATE relay_logins SET id_token = $2, error = $3 WHERE relay_id = $1")
            .bind(&pending.relay_id)
            .bind(token)
            .bind(error)
            .execute(&st.db)
            .await
    {
        tracing::error!(error = %e, "relay callback");
        return page(PAGE_FAIL);
    }
    page(if ok { PAGE_OK } else { PAGE_FAIL })
}

/// Exchange the code and validate the ID token (with the app's nonce).
async fn finish(st: &AppState, p: &Pending, code: &str) -> Result<String, String> {
    let idp = st
        .personal_idps
        .iter()
        .find(|i| i.issuer == p.issuer && i.relay)
        .ok_or("the provider is no longer configured")?;
    let redirect_uri = st.relay.redirect_uri.as_deref().ok_or("no redirect URI")?;
    let secret = match (&st.relay.apple, idp.issuer.as_str()) {
        (Some(k), APPLE_ISSUER) => {
            Some(k.client_secret(&idp.client_id).map_err(|e| e.to_string())?)
        }
        _ => idp.client_secret.clone(),
    };
    let client = provider_client(st).map_err(|_| "no HTTP client")?;
    let d = discover(&client, &idp.issuer)
        .await
        .map_err(|e| format!("provider discovery: {e}"))?;
    let pkce = Pkce {
        verifier: p.pkce_verifier.clone(),
        challenge: String::new(),
    };
    let token = exchange_code(
        &client,
        &d,
        &idp.client_id,
        secret.as_deref(),
        redirect_uri,
        code,
        &pkce,
    )
    .await
    .map_err(|e| format!("code exchange: {e}"))?;
    let cfg = IssuerConfig {
        issuer: idp.issuer.clone(),
        client_id: idp.client_id.clone(),
        group_claim: "groups".into(),
    };
    st.oidc
        .validate(&cfg, &token, Some(&p.nonce))
        .await
        .map_err(|e| format!("ID token: {e}"))?;
    Ok(token)
}

#[derive(FromRow)]
struct Row {
    secret_hash: Vec<u8>,
    created_at: i64,
    id_token: Option<String>,
    error: Option<String>,
}

/// `POST /v1/auth/relay/poll`: the token, once, to whoever holds the secret.
pub async fn poll(
    State(st): State<AppState>,
    Json(req): Json<RelayPollRequest>,
) -> ApiResult<Json<RelayPollResponse>> {
    let row: Option<Row> = sqlx::query_as(
        "SELECT secret_hash, created_at, id_token, error FROM relay_logins WHERE relay_id = $1",
    )
    .bind(&req.relay_id[..])
    .fetch_optional(&st.db)
    .await?;
    let gone = || {
        Json(RelayPollResponse::Failed {
            reason: "this sign-in expired; start again".into(),
        })
    };
    let Some(row) = row else {
        return Ok(gone());
    };
    if !ct_eq(&relay_secret_hash(&req.secret), &row.secret_hash) {
        return Err(ApiError::Unauthorized);
    }
    let expired = unix_now() - row.created_at > RELAY_TTL_SECS;
    if row.id_token.is_none() && row.error.is_none() && !expired {
        return Ok(Json(RelayPollResponse::Pending));
    }
    sqlx::query("DELETE FROM relay_logins WHERE relay_id = $1")
        .bind(&req.relay_id[..])
        .execute(&st.db)
        .await?;
    Ok(match (row.id_token, row.error) {
        (Some(id_token), _) if !expired => Json(RelayPollResponse::Done { id_token }),
        (_, Some(reason)) => Json(RelayPollResponse::Failed { reason }),
        _ => gone(),
    })
}

fn ct_eq(a: &[u8; 32], b: &[u8]) -> bool {
    b.len() == 32 && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
