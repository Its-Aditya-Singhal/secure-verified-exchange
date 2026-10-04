//! Desktop app updates, from a directory the release process fills
//! (`--updates-dir`): `manifest.json` (a release manifest signed offline
//! with the release key) and the update packages it names.
//!
//! The service holds no release key and is not trusted here: the app
//! verifies the manifest against the release key it pins, and every
//! package against the manifest and its Tauri signature.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use svx_protocol::update::{ReleaseManifest, SignedReleaseManifest, parse_version};

use crate::AppState;
use crate::error::{ApiError, ApiResult};

const MANIFEST: &str = "manifest.json";

async fn read(st: &AppState, name: &str) -> ApiResult<Vec<u8>> {
    let dir = st.updates.as_ref().ok_or(ApiError::NotFound)?;
    // Plain file names only: no paths, no hidden files.
    let ok = !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if !ok {
        return Err(ApiError::NotFound);
    }
    match tokio::fs::read(dir.join(name)).await {
        Ok(b) => Ok(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(ApiError::NotFound),
        Err(e) => Err(ApiError::Internal(e.to_string())),
    }
}

/// `GET /v1/updates/manifest`: the signed release manifest, as published.
pub async fn manifest(State(st): State<AppState>) -> ApiResult<Response> {
    let bytes = read(&st, MANIFEST).await?;
    Ok(([(header::CONTENT_TYPE, "application/json")], bytes).into_response())
}

/// `GET /v1/updates/tauri/{target}/{arch}/{current}`: the same release in
/// the Tauri updater's format, or 204 when there is nothing newer.
pub async fn tauri(
    State(st): State<AppState>,
    Path((target, arch, current)): Path<(String, String, String)>,
) -> ApiResult<Response> {
    let bytes = read(&st, MANIFEST).await?;
    let signed: SignedReleaseManifest =
        serde_json::from_slice(&bytes).map_err(|e| ApiError::Internal(e.to_string()))?;
    let m: ReleaseManifest =
        serde_json::from_slice(&signed.payload).map_err(|e| ApiError::Internal(e.to_string()))?;
    let newer = match (parse_version(&m.version), parse_version(&current)) {
        (Some(v), Some(c)) => v > c,
        _ => false,
    };
    let Some(p) = m
        .platforms
        .get(&format!("{target}-{arch}"))
        .filter(|_| newer)
    else {
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    Ok(Json(serde_json::json!({
        "version": m.version,
        "notes": m.notes,
        "url": p.url,
        "signature": p.signature,
    }))
    .into_response())
}

/// `GET /v1/updates/files/{name}`: an update package.
pub async fn file(State(st): State<AppState>, Path(name): Path<String>) -> ApiResult<Response> {
    if name == MANIFEST {
        return Err(ApiError::NotFound);
    }
    let bytes = read(&st, &name).await?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}
