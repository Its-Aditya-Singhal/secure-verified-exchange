//! Serde helpers: binary blobs as standard base64, identifiers and public
//! keys as lowercase hex.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serializer, de::Error};

/// Upper bound on any base64 blob we are willing to decode (header regions
/// are ≤ 1 MiB + 16 bytes; nothing else comes close).
const MAX_B64_LEN: usize = 2 * 1024 * 1024;

pub mod b64 {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() > MAX_B64_LEN {
            return Err(D::Error::custom("base64 value too large"));
        }
        STANDARD.decode(s.as_bytes()).map_err(D::Error::custom)
    }
}

pub mod hex_array {
    use super::*;

    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        let mut out = [0u8; N];
        hex::decode_to_slice(s.as_bytes(), &mut out).map_err(D::Error::custom)?;
        Ok(out)
    }
}

/// Variable-length public keys (32 bytes classical, up to 1984 bytes for
/// post-quantum hybrid keys) as lowercase hex. Exact lengths are checked
/// where the key is parsed.
pub mod hex_vec {
    use super::*;

    /// Larger than any key SVX uses.
    const MAX_LEN: usize = 4096;

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() > 2 * MAX_LEN {
            return Err(D::Error::custom("hex value too large"));
        }
        hex::decode(s.as_bytes()).map_err(D::Error::custom)
    }
}

pub fn b64_encode(v: &[u8]) -> String {
    STANDARD.encode(v)
}
