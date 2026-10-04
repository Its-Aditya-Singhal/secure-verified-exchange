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
pub use header::{EnvelopeLayout, EnvelopeRole, Header, KeyEnvelope, Prelude, UnknownField, tags};
pub use ident::Identifier;

/// The eight magic bytes at the start of every `.svx` file.
///
/// Modelled on the PNG signature: a non-ASCII first byte, the ASCII name, a
/// CRLF pair, a DOS EOF character and a LF, so that common transfer-mode
/// corruption (CRLF translation, 7-bit stripping) is detected immediately.
pub const MAGIC: [u8; 8] = [0x89, b'S', b'V', b'X', 0x0D, 0x0A, 0x1A, 0x0A];

/// Major format version written and accepted by this implementation.
pub const FORMAT_MAJOR: u8 = 1;
/// Minor format version written for suite `0x0001` (SVX 1.0 layout).
pub const FORMAT_MINOR: u8 = 0;
/// Minor format version written for suite `0x0003` (SVX 1.1: envelope layout V2).
pub const FORMAT_MINOR_HYBRID: u8 = 1;
/// Minor format version written for multi-recipient artifacts (SVX 1.2:
/// the critical `recipients` field).
pub const FORMAT_MINOR_RECIPIENTS: u8 = 2;
/// Minor format version written for suite `0x0004` (SVX 1.3: SVX-2 with
/// MLKEM1024-P384 envelopes, a 64-byte payload commitment and signatures up
/// to 64 KiB), with or without the `recipients` field.
pub const FORMAT_MINOR_MAX: u8 = 3;

/// Suite `0x0001` (SVX-1): envelope layout V1.
pub const SUITE_ID_SVX1: u16 = 0x0001;
/// Suite `0x0003` (SVX-1H, post-quantum hybrid): envelope layout V2 with
/// X-Wing encapsulated keys.
pub const SUITE_ID_SVX1H: u16 = 0x0003;
/// X-Wing encapsulated key length, required in every SVX-1H envelope.
pub const HYBRID_ENCAPPED_KEY_LEN: usize = 1120;
/// Suite `0x0004` (SVX-2, maximum strength): envelope layout V2 with
/// MLKEM1024-P384 encapsulated keys.
pub const SUITE_ID_SVX2: u16 = 0x0004;
/// MLKEM1024-P384 encapsulated key length, required in every SVX-2 envelope.
pub const MAX_ENCAPPED_KEY_LEN_SVX2: usize = 1665;

/// Structural rules tying a suite to its envelope layout. Suites this crate
/// does not know are left to the cryptographic layer, which rejects them.
pub fn check_suite_layout(suite_id: u16, header: &Header) -> Result<()> {
    match suite_id {
        SUITE_ID_SVX1 if header.envelope_layout != EnvelopeLayout::V1 => Err(
            FormatError::Malformed("suite 0x0001 requires key envelope layout V1"),
        ),
        SUITE_ID_SVX1H => {
            if header.envelope_layout != EnvelopeLayout::V2 {
                return Err(FormatError::Malformed(
                    "suite 0x0003 requires key envelope layout V2",
                ));
            }
            if header
                .envelopes
                .iter()
                .any(|e| e.encapped_key.len() != HYBRID_ENCAPPED_KEY_LEN)
            {
                return Err(FormatError::Malformed(
                    "suite 0x0003 requires X-Wing encapsulated keys",
                ));
            }
            Ok(())
        }
        SUITE_ID_SVX2 => {
            if header.envelope_layout != EnvelopeLayout::V2 {
                return Err(FormatError::Malformed(
                    "suite 0x0004 requires key envelope layout V2",
                ));
            }
            if header
                .envelopes
                .iter()
                .any(|e| e.encapped_key.len() != MAX_ENCAPPED_KEY_LEN_SVX2)
            {
                return Err(FormatError::Malformed(
                    "suite 0x0004 requires MLKEM1024-P384 encapsulated keys",
                ));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Length of the trailer's payload commitment: SHA-512 (64 bytes) in suite
/// `0x0004`, SHA-256 (32 bytes) otherwise.
pub fn payload_commitment_len(suite_id: u16) -> usize {
    if suite_id == SUITE_ID_SVX2 {
        PAYLOAD_COMMITMENT_LEN_WIDE
    } else {
        PAYLOAD_COMMITMENT_LEN
    }
}

/// The minor version a writer emits for `suite_id` and `header`.
pub fn minor_for(suite_id: u16, header: &Header) -> u8 {
    if suite_id == SUITE_ID_SVX2 {
        FORMAT_MINOR_MAX
    } else if !header.recipients.is_empty() {
        FORMAT_MINOR_RECIPIENTS
    } else if suite_id == SUITE_ID_SVX1H {
        FORMAT_MINOR_HYBRID
    } else {
        FORMAT_MINOR
    }
}

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
/// Length in bytes of the payload commitment hash (SHA-256).
pub const PAYLOAD_COMMITMENT_LEN: usize = 32;
/// Length in bytes of the payload commitment hash in suite `0x0004` (SHA-512).
pub const PAYLOAD_COMMITMENT_LEN_WIDE: usize = 64;

/// Chunk flag: more chunks follow.
pub const CHUNK_FLAG_MORE: u8 = 0x00;
/// Chunk flag: this is the final chunk.
pub const CHUNK_FLAG_FINAL: u8 = 0x01;
