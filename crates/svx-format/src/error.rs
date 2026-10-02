use std::io;

/// Errors produced while reading or writing an SVX container.
///
/// Every variant means the input must be rejected; there is no "partially
/// valid" container.
#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("not an SVX file (bad magic bytes)")]
    BadMagic,
    #[error("unsupported SVX format version {major}.{minor}")]
    UnsupportedVersion { major: u8, minor: u8 },
    #[error("container is truncated")]
    Truncated,
    #[error("{what} exceeds the limit of {limit}")]
    LimitExceeded { what: &'static str, limit: u64 },
    #[error("malformed {0}")]
    Malformed(&'static str),
    #[error("header fields are duplicated or out of order (tag {0:#06x})")]
    FieldOrder(u16),
    #[error("unknown critical header field {0:#06x}")]
    UnknownCriticalField(u16),
    #[error("required header field missing: {0}")]
    MissingField(&'static str),
    #[error("invalid identifier in {0}")]
    InvalidIdentifier(&'static str),
    #[error("unexpected data after the trailer")]
    TrailingData,
    #[error("writer used out of order: {0}")]
    WriterState(&'static str),
}

pub type Result<T> = std::result::Result<T, FormatError>;

/// Map an unexpected EOF to [`FormatError::Truncated`].
pub(crate) fn map_eof(e: io::Error) -> FormatError {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        FormatError::Truncated
    } else {
        FormatError::Io(e)
    }
}
