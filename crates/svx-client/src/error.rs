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
    /// The service refused an administrative request and said why.
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ClientError>;

/// Stable machine-readable error category, for SDKs and scripts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Config,
    Io,
    Rejected,
    NotRecipient,
    Expired,
    Denied,
    Unavailable,
    Login,
    NotLoggedIn,
    OutputExists,
    Invalid,
    Other,
}

impl ErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::Config => "config",
            ErrorKind::Io => "io",
            ErrorKind::Rejected => "rejected",
            ErrorKind::NotRecipient => "not_recipient",
            ErrorKind::Expired => "expired",
            ErrorKind::Denied => "denied",
            ErrorKind::Unavailable => "unavailable",
            ErrorKind::Login => "login",
            ErrorKind::NotLoggedIn => "not_logged_in",
            ErrorKind::OutputExists => "output_exists",
            ErrorKind::Invalid => "invalid",
            ErrorKind::Other => "other",
        }
    }
}

impl ClientError {
    pub fn kind(&self) -> ErrorKind {
        match self {
            ClientError::Config(_) => ErrorKind::Config,
            ClientError::Io(_) => ErrorKind::Io,
            ClientError::Rejected(_) => ErrorKind::Rejected,
            ClientError::NotRecipient { .. } => ErrorKind::NotRecipient,
            ClientError::Expired => ErrorKind::Expired,
            ClientError::Denied(_) => ErrorKind::Denied,
            ClientError::Unavailable(_) => ErrorKind::Unavailable,
            ClientError::Login(_) => ErrorKind::Login,
            ClientError::NotLoggedIn => ErrorKind::NotLoggedIn,
            ClientError::OutputExists(_) => ErrorKind::OutputExists,
            ClientError::Invalid(_) => ErrorKind::Invalid,
            ClientError::Other(_) => ErrorKind::Other,
        }
    }

    /// The coarse denial reason, for [`ClientError::Denied`].
    pub fn deny_reason(&self) -> Option<&'static str> {
        match self {
            ClientError::Denied(r) => Some(match r {
                DenyReason::NotAuthorized => "not_authorized",
                DenyReason::ExpiredOrRevoked => "expired_or_revoked",
                DenyReason::InvalidArtifact => "invalid_artifact",
                DenyReason::InvalidRequest => "invalid_request",
                DenyReason::Unavailable => "unavailable",
            }),
            _ => None,
        }
    }

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
            ProtocolError::Invalid(d) => ClientError::Invalid(d),
            ProtocolError::Http(e) => ClientError::Unavailable(e.to_string()),
            ProtocolError::Status(s) if s >= 500 => ClientError::Unavailable(format!("HTTP {s}")),
            ProtocolError::InsecureUrl(u) => ClientError::Config(format!("insecure URL {u}")),
            other => ClientError::Other(other.to_string()),
        }
    }
}
