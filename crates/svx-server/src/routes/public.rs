use axum::Json;
use axum::extract::{Path, State};
use svx_protocol::{
    OrgRecord, PROTOCOL_VERSION, ServiceInfo, ServiceRecord, SignedOrgRecord, SignedServiceRecord,
    unix_now,
};

use svx_protocol::personal::OrgKind;

use crate::error::{ApiError, ApiResult};
use crate::{AppState, db};

pub async fn service_info(State(st): State<AppState>) -> Json<ServiceInfo> {
    let registry = st.keys.registry_public();
    Json(ServiceInfo {
        service_id: st.service_id.to_string(),
        kem_public: st.keys.service_kem_public().to_vec(),
        grant_public: st.keys.grant_public().to_vec(),
        registry_public: registry.to_vec(),
        registry_fingerprint: registry.fingerprint(),
    })
}

/// The service's public keys, signed by the registry key.
pub async fn service_record(State(st): State<AppState>) -> ApiResult<Json<SignedServiceRecord>> {
    let signed = st
        .keys
        .sign_service_record(&ServiceRecord {
            v: PROTOCOL_VERSION,
            service_id: st.service_id.to_string(),
            kem_public: st.keys.service_kem_public().to_vec(),
            grant_public: st.keys.grant_public().to_vec(),
            issued_at: unix_now(),
            // A relayed provider's client secret stays on the service.
            personal_idps: st
                .personal_idps
                .iter()
                .cloned()
                .map(|mut p| {
                    if p.relay {
                        p.client_secret = None;
                    }
                    p
                })
                .collect(),
        })
        .map_err(|e| ApiError::Internal(format!("signing the service record: {e}")))?;
    Ok(Json(signed))
}

/// The signed registry record of a verified organization.
pub async fn org_record(
    State(st): State<AppState>,
    Path(org): Path<String>,
) -> ApiResult<Json<SignedOrgRecord>> {
    Ok(Json(signed_org_record(&st, &org).await?))
}

/// Build and sign `org`'s registry record. A personal account's record
/// carries its verified email, so the directory binding is signed too.
pub(crate) async fn signed_org_record(st: &AppState, org: &str) -> ApiResult<SignedOrgRecord> {
    let o = db::verified_org(&st.db, org)
        .await?
        .ok_or(ApiError::NotFound)?;
    let keys = db::keys(&st.db, org)
        .await?
        .iter()
        .filter_map(db::KeyRow::to_entry)
        .collect();
    let (kind, account_email) = if o.kind == "personal" {
        let email: Option<String> =
            sqlx::query_scalar("SELECT email FROM personal_accounts WHERE org_id = $1")
                .bind(org)
                .fetch_optional(&st.db)
                .await?;
        (OrgKind::Personal, email)
    } else {
        (OrgKind::Company, None)
    };
    let record = OrgRecord {
        v: PROTOCOL_VERSION,
        org_id: o.org_id,
        display_name: o.display_name,
        domain: o.domain,
        idp_issuer: o.idp_issuer,
        key_agent_url: o.key_agent_url,
        keys,
        issued_at: unix_now(),
        kind,
        account_email,
    };
    st.keys
        .sign_record(&record)
        .map_err(|e| ApiError::Internal(format!("signing the registry record: {e}")))
}
