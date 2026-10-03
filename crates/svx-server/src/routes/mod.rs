mod admin;
mod orgs;
mod public;
mod release;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::HeaderMap;
use axum::routing::{get, post, put};
use svx_oidc::Identity;

use crate::error::{ApiError, ApiResult};
use crate::{AppState, MAX_BODY, audit, db};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/service", get(public::service_info))
        .route("/v1/registry/orgs/{org}", get(public::org_record))
        .route("/v1/orgs", post(orgs::register))
        .route("/v1/orgs/{org}/verify", post(orgs::verify))
        .route("/v1/admin/orgs/{org}/keys", put(admin::put_key))
        .route("/v1/admin/orgs/{org}/admins", post(admin::add_admin))
        .route(
            "/v1/admin/orgs/{org}/policies/{name}",
            put(admin::put_policy),
        )
        .route(
            "/v1/admin/orgs/{org}/artifacts/{artifact_id}/revoke",
            post(admin::revoke),
        )
        .route("/v1/admin/orgs/{org}/audit", get(admin::audit))
        .route("/v1/artifacts", post(release::register_artifact))
        .route("/v1/release", post(release::release))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

pub(crate) fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

/// An authenticated administrator of `org_id`.
pub(crate) struct Admin {
    pub org_id: String,
    pub identity: Identity,
}

/// Authenticate the bearer ID token against `org_id`'s own IdP and require
/// the subject to be one of its admins. The org named in the path is only a
/// selector: a token from any other IdP, or from a non-admin, is refused.
pub(crate) async fn require_admin(
    st: &AppState,
    org_id: &str,
    headers: &HeaderMap,
) -> ApiResult<Admin> {
    let org = db::verified_org(&st.db, org_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let token = bearer(headers).ok_or(ApiError::Unauthorized)?;
    let identity = match st.oidc.validate(&org.issuer_config(), token, None).await {
        Ok(i) => i,
        Err(e) => {
            audit::note(
                &st.db,
                org_id,
                audit::Record {
                    event: audit::event::ADMIN_AUTH_FAILURE,
                    reason: Some(e.to_string()),
                    ..Default::default()
                },
            )
            .await;
            return Err(ApiError::Unauthorized);
        }
    };
    if !db::is_admin(&st.db, org_id, &identity.sub).await? {
        audit::note(
            &st.db,
            org_id,
            audit::Record {
                event: audit::event::ADMIN_AUTH_FAILURE,
                subject: Some(identity.sub.clone()),
                reason: Some("not an administrator".into()),
                ..Default::default()
            },
        )
        .await;
        return Err(ApiError::Unauthorized);
    }
    Ok(Admin {
        org_id: org_id.to_owned(),
        identity,
    })
}
