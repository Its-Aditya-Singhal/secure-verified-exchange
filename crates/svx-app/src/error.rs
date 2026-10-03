use std::path::PathBuf;

use serde::Serialize;
use svx_client::ClientError;

/// An error as the UI sees it: a stable `kind` to pick a screen, and a
/// message that is safe to show (no key material or plaintext).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AppError {
    /// [`svx_client::ErrorKind`] names, plus `not_configured`.
    pub kind: String,
    pub message: String,
    /// `not_authorized` or `expired_or_revoked` for `denied`.
    pub deny_reason: Option<String>,
    /// 1 = refusal, 2 = local error, 3 = unavailable.
    pub exit_code: u8,
    /// The existing path, for `output_exists`.
    pub path: Option<PathBuf>,
}

pub type Result<T> = std::result::Result<T, AppError>;

impl AppError {
    pub fn not_configured() -> Self {
        AppError {
            kind: "not_configured".into(),
            message: "SVX is not set up yet".into(),
            deny_reason: None,
            exit_code: 2,
            path: None,
        }
    }

    pub fn other(message: impl Into<String>) -> Self {
        AppError {
            kind: "other".into(),
            message: message.into(),
            deny_reason: None,
            exit_code: 2,
            path: None,
        }
    }
}

impl From<ClientError> for AppError {
    fn from(e: ClientError) -> Self {
        AppError {
            kind: e.kind().as_str().into(),
            message: e.to_string(),
            deny_reason: e.deny_reason().map(Into::into),
            exit_code: e.exit_code(),
            path: match &e {
                ClientError::OutputExists(p) => Some(p.clone()),
                _ => None,
            },
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        ClientError::from(e).into()
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AppError {}
