use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use svx_protocol::{DenyReason, ErrorBody};

/// Every handler error. Release endpoints only ever produce [`ApiError::Deny`],
/// whose body is a coarse reason with no detail.
#[derive(Debug)]
pub enum ApiError {
    Deny(DenyReason),
    /// Admin/registration errors may carry a detail message.
    BadRequest(String),
    Unauthorized,
    NotFound,
    Conflict(String),
    Internal(String),
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        ApiError::Internal(e.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error, detail) = match self {
            ApiError::Deny(r) => {
                let s = match r {
                    DenyReason::InvalidRequest => StatusCode::BAD_REQUEST,
                    DenyReason::InvalidArtifact => StatusCode::UNPROCESSABLE_ENTITY,
                    DenyReason::NotAuthorized
                    | DenyReason::ExpiredOrRevoked
                    | DenyReason::AlreadyOpened
                    | DenyReason::Declined
                    | DenyReason::ViewOnly => StatusCode::FORBIDDEN,
                    DenyReason::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
                };
                (s, r, None)
            }
            ApiError::BadRequest(d) => {
                (StatusCode::BAD_REQUEST, DenyReason::InvalidRequest, Some(d))
            }
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, DenyReason::NotAuthorized, None),
            ApiError::NotFound => (
                StatusCode::NOT_FOUND,
                DenyReason::InvalidRequest,
                Some("not found".into()),
            ),
            ApiError::Conflict(d) => (StatusCode::CONFLICT, DenyReason::InvalidRequest, Some(d)),
            ApiError::Internal(e) => {
                // Never echo internal errors to clients.
                tracing::error!(error = %e, "internal error");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    DenyReason::Unavailable,
                    None,
                )
            }
        };
        (status, Json(ErrorBody { error, detail })).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

/// Whether a sqlx error is a unique-constraint violation.
pub fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(d) if d.code().as_deref() == Some("23505"))
}
