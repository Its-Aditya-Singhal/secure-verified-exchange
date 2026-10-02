/// Cryptographic failures. Messages are intentionally terse: they must not
/// leak which byte failed or any key material.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("unsupported cipher suite {0:#06x}")]
    UnsupportedSuite(u16),
    #[error("unsupported signature algorithm {0:#06x}")]
    UnsupportedSignatureAlgorithm(u16),
    #[error("signature verification failed")]
    BadSignature,
    #[error("authenticated decryption failed")]
    Decryption,
    #[error("key share could not be unwrapped")]
    EnvelopeOpen,
    #[error("key commitment does not match")]
    KeyCommitmentMismatch,
    #[error("invalid key encoding")]
    InvalidKey,
    #[error("encryption failed")]
    Encryption,
    #[error("stream misuse: {0}")]
    StreamState(&'static str),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
