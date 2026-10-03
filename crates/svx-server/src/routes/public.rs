use axum::Json;
use axum::extract::{Path, State};
use svx_protocol::{
    OrgRecord, PROTOCOL_VERSION, ServiceInfo, ServiceRecord, SignedOrgRecord, SignedServiceRecord,
    unix_now,
};

use crate::error::{ApiError, ApiResult};
use crate::{AppState, db};

pub async fn service_info(State(st): State<AppState>) -> Json<ServiceInfo> {
    Json(ServiceInfo {
        service_id: st.service_id.to_string(),
        kem_public: st.keys.service_kem_public().to_vec(),
        grant_public: st.keys.grant_public().to_bytes(),
        registry_public: st.keys.registry_public().to_bytes(),
    })
}

/// The service's public keys, signed by the registry key.
pub async fn service_record(State(st): State<AppState>) -> Json<SignedServiceRecord> {
    Json(st.keys.sign_service_record(&ServiceRecord {
        v: PROTOCOL_VERSION,
        service_id: st.service_id.to_string(),
        kem_public: st.keys.service_kem_public().to_vec(),
        grant_public: st.keys.grant_public().to_bytes(),
        issued_at: unix_now(),
    }))
}

/// The signed registry record of a verified organization.
pub async fn org_record(
    State(st): State<AppState>,
    Path(org): Path<String>,
) -> ApiResult<Json<SignedOrgRecord>> {
    let o = db::verified_org(&st.db, &org)
        .await?
        .ok_or(ApiError::NotFound)?;
    let keys = db::keys(&st.db, &org)
        .await?
        .iter()
        .filter_map(db::KeyRow::to_entry)
        .collect();
    let record = OrgRecord {
        v: PROTOCOL_VERSION,
        org_id: o.org_id,
        display_name: o.display_name,
        domain: o.domain,
        idp_issuer: o.idp_issuer,
        key_agent_url: o.key_agent_url,
        keys,
        issued_at: unix_now(),
    };
    Ok(Json(st.keys.sign_record(&record)))
}
