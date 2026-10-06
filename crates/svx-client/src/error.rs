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
    /// Sign-up: the account already has keys on another device (restore
    /// the backup, or reset the keys).
    #[error(
        "this account already has keys on another device: restore your backup, or reset your keys"
    )]
    AccountExists,
    /// The user's own account is suspended by the service's operator.
    #[error(
        "your SVX account is suspended; write to support@getsvx.me if you think this is a mistake"
    )]
    Suspended,
    /// The user stopped waiting (for example for the sender's approval).
    #[error("cancelled")]
    Cancelled,
    /// Touch ID / the computer's password / Windows Hello wasn't confirmed.
    #[error("not confirmed: confirm it's you to continue")]
    NotConfirmed,
    /// View-only files can't be shown here: this system can't keep the
    /// viewer out of screenshots and recordings.
    #[error(
        "view-only files can't be shown on this computer: it can't block screenshots. \
         Open the file on a Mac or a Windows computer"
    )]
    ViewUnsupported,
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
    AccountExists,
    Suspended,
    Cancelled,
    NotConfirmed,
    ViewUnsupported,
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
            ErrorKind::AccountExists => "account_exists",
            ErrorKind::Suspended => "suspended",
            ErrorKind::Cancelled => "cancelled",
            ErrorKind::NotConfirmed => "not_confirmed",
            ErrorKind::ViewUnsupported => "view_unsupported",
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
            ClientError::AccountExists => ErrorKind::AccountExists,
            ClientError::Suspended => ErrorKind::Suspended,
            ClientError::Cancelled => ErrorKind::Cancelled,
            ClientError::NotConfirmed => ErrorKind::NotConfirmed,
            ClientError::ViewUnsupported => ErrorKind::ViewUnsupported,
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
                DenyReason::AlreadyOpened => "already_opened",
                DenyReason::Declined => "declined",
                DenyReason::ViewOnly => "view_only",
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
            | ClientError::Denied(_)
            | ClientError::Suspended => 1,
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
            ProtocolError::Invalid(d) if d == svx_protocol::personal::KEYS_ON_ANOTHER_DEVICE => {
                ClientError::AccountExists
            }
            ProtocolError::Invalid(d) if d == svx_protocol::personal::ACCOUNT_SUSPENDED => {
                ClientError::Suspended
            }
            ProtocolError::Invalid(d) => ClientError::Invalid(d),
            ProtocolError::Http(e) => ClientError::Unavailable(e.to_string()),
            ProtocolError::Status(s) if s >= 500 => ClientError::Unavailable(format!("HTTP {s}")),
            ProtocolError::InsecureUrl(u) => ClientError::Config(format!("insecure URL {u}")),
            other => ClientError::Other(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_suspended_account_has_its_own_kind() {
        let e = ClientError::from(ProtocolError::Invalid(
            svx_protocol::personal::ACCOUNT_SUSPENDED.into(),
        ));
        assert_eq!(e.kind().as_str(), "suspended");
        assert_eq!(e.exit_code(), 1);
        let other = ClientError::from(ProtocolError::Invalid("no such account".into()));
        assert_eq!(other.kind().as_str(), "invalid");
    }
}
