//! Reference parser and writer for the SVX 1.0 binary container.
//!
//! This crate is deliberately free of cryptography: it only knows how to lay
//! out and strictly parse the bytes described in `spec/SVX-1.0.md`. Every
//! length read from untrusted input is bounded by a constant in [`limits`]
//! before any allocation happens.
//!
//! Higher layers (`svx-crypto`, `svx-core`) are responsible for hashing,
//! signature verification and decryption. Nothing parsed here should be
//! trusted until the signature over it has been verified.

#![forbid(unsafe_code)]

mod container;
mod error;
mod header;
mod ident;
pub mod limits;
mod wire;

pub use container::{ChunkInfo, Container, Reader, Trailer, Writer, parse, parse_header_region};
pub use error::{FormatError, Result};
pub use header::{EnvelopeRole, Header, KeyEnvelope, Prelude, UnknownField, tags};
pub use ident::Identifier;

/// The eight magic bytes at the start of every `.svx` file.
///
/// Modelled on the PNG signature: a non-ASCII first byte, the ASCII name, a
/// CRLF pair, a DOS EOF character and a LF, so that common transfer-mode
/// corruption (CRLF translation, 7-bit stripping) is detected immediately.
pub const MAGIC: [u8; 8] = [0x89, b'S', b'V', b'X', 0x0D, 0x0A, 0x1A, 0x0A];

/// Major format version written and accepted by this implementation.
pub const FORMAT_MAJOR: u8 = 1;
/// Minor format version written by this implementation.
pub const FORMAT_MINOR: u8 = 0;

/// Magic bytes that open the trailer section.
pub const TRAILER_MAGIC: [u8; 4] = *b"SVXT";

/// Length in bytes of an artifact identifier.
pub const ARTIFACT_ID_LEN: usize = 16;
/// Length in bytes of a key identifier.
pub const KEY_ID_LEN: usize = 16;
/// Length in bytes of the STREAM nonce prefix.
pub const NONCE_PREFIX_LEN: usize = 7;
/// Length in bytes of the key commitment.
pub const KEY_COMMITMENT_LEN: usize = 32;
/// Length in bytes of an HPKE encapsulated key for DHKEM(X25519).
pub const ENCAPPED_KEY_LEN: usize = 32;
/// Length in bytes of the payload commitment hash.
pub const PAYLOAD_COMMITMENT_LEN: usize = 32;

/// Chunk flag: more chunks follow.
pub const CHUNK_FLAG_MORE: u8 = 0x00;
/// Chunk flag: this is the final chunk.
pub const CHUNK_FLAG_FINAL: u8 = 0x01;
