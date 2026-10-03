use std::path::PathBuf;

use svx_protocol::{DenyReason, ProtocolError};

/// Client errors, grouped so a UI can show a safe message and pick an exit
/// code. None of these carry key material or plaintext.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("artifact rejected: {0}")]
    Rejected(String),
    #[error("this artifact is addressed to {recipient}, not to your organization ({mine})")]
    NotRecipient { recipient: String, mine: String },
    #[error("artifact expired")]
    Expired,
    #[error("access denied: {0}")]
    Denied(DenyReason),
    #[error("SVX service unavailable: {0}")]
    Unavailable(String),
    #[error("login failed: {0}")]
    Login(String),
    #[error("not logged in (run `svx login`)")]
    NotLoggedIn,
    #[error("{} already exists (use --overwrite or choose another directory)", .0.display())]
    OutputExists(PathBuf),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ClientError>;

impl ClientError {
    /// `1` = security refusal, `2` = local/usage error, `3` = service unavailable.
    pub fn exit_code(&self) -> u8 {
        match self {
            ClientError::Rejected(_)
            | ClientError::NotRecipient { .. }
            | ClientError::Expired
            | ClientError::Denied(_) => 1,
            ClientError::Unavailable(_) => 3,
            _ => 2,
        }
    }
}

impl From<ProtocolError> for ClientError {
    fn from(e: ProtocolError) -> Self {
        match e {
            ProtocolError::Denied(DenyReason::Unavailable) => {
                ClientError::Unavailable("service reported unavailable".into())
            }
            ProtocolError::Denied(r) => ClientError::Denied(r),
            ProtocolError::Http(e) => ClientError::Unavailable(e.to_string()),
            ProtocolError::Status(s) if s >= 500 => ClientError::Unavailable(format!("HTTP {s}")),
            ProtocolError::InsecureUrl(u) => ClientError::Config(format!("insecure URL {u}")),
            other => ClientError::Other(other.to_string()),
        }
    }
}
