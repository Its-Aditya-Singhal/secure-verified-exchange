use svx_crypto::CryptoError;
use svx_format::FormatError;

/// Errors from high-level operations. Any error means: do not use the output.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("integrity verification failed: {0}")]
    Format(#[from] FormatError),
    #[error("{0}")]
    Crypto(#[from] CryptoError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("sender {org} (key {key_id}) is not in the trust store")]
    UntrustedSender { org: String, key_id: String },
    #[error("payload commitment does not match the trailer")]
    CommitmentMismatch,
    #[error("artifact changed between verification and decryption")]
    ArtifactChanged,
    #[error("artifact is missing the required {0} key envelope")]
    MissingEnvelope(&'static str),
    #[error("key does not match the {0} key envelope")]
    WrongKey(&'static str),
    #[error("invalid manifest: {0}")]
    Manifest(String),
    #[error("plaintext length does not match the manifest")]
    LengthMismatch,
    #[error("invalid key file: {0}")]
    KeyFile(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;
