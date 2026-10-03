//! Hard upper bounds applied while parsing untrusted input.
//!
//! These are part of the SVX 1.0 specification: a conforming reader MUST
//! reject a container that exceeds any of them, and a conforming writer MUST
//! NOT produce one.

/// Maximum size of the header section (excluding the 16-byte prelude).
pub const MAX_HEADER_LEN: u32 = 1024 * 1024;
/// Maximum length of any single header field value.
pub const MAX_FIELD_LEN: u32 = 256 * 1024;
/// Maximum number of fields in a header, including unknown non-critical ones.
pub const MAX_FIELDS: usize = 64;
/// Maximum number of key envelopes in one artifact.
pub const MAX_ENVELOPES: usize = 16;
/// Maximum number of recipients of one artifact (SVX 1.2): one service
/// envelope plus one recipient envelope each must fit in [`MAX_ENVELOPES`].
pub const MAX_RECIPIENTS: usize = MAX_ENVELOPES - 1;
/// Maximum ciphertext length inside a single key envelope.
pub const MAX_ENVELOPE_CT_LEN: usize = 1024;
/// Maximum encapsulated-key length in envelope layout V2 (X-Wing needs 1120).
pub const MAX_ENCAPPED_KEY_LEN: usize = 2048;
/// Maximum length of the encrypted manifest (64 KiB plaintext + AEAD tag).
pub const MAX_MANIFEST_CT_LEN: usize = 64 * 1024 + 16;
/// Smallest permitted plaintext chunk size.
pub const MIN_CHUNK_SIZE: u32 = 64;
/// Largest permitted plaintext chunk size.
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;
/// Default plaintext chunk size used by writers.
pub const DEFAULT_CHUNK_SIZE: u32 = 64 * 1024;
/// AEAD tag length appended to every chunk ciphertext.
pub const CHUNK_TAG_LEN: u32 = 16;
/// Maximum number of chunks (the STREAM counter is 32 bits).
pub const MAX_CHUNKS: u64 = 1 << 32;
/// Maximum length of an identifier string.
pub const MAX_IDENTIFIER_LEN: usize = 128;
/// Maximum length of a signature.
pub const MAX_SIGNATURE_LEN: usize = 4096;
