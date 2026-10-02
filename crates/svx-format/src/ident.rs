use std::fmt;

use crate::error::{FormatError, Result};
use crate::limits::MAX_IDENTIFIER_LEN;

/// An opaque, ASCII-restricted identifier (organization IDs, service IDs,
/// policy references).
///
/// Allowed characters are `a-z`, `0-9`, `-`, `.`, `_` and `:`; the first
/// character must be alphanumeric; length is 1..=128. Restricting the
/// alphabet removes Unicode confusables and normalization ambiguity from
/// anything that is compared for authorization decisions.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Identifier(String);

impl Identifier {
    /// Validate and wrap `s`.
    pub fn new(s: &str) -> Result<Self> {
        Self::validate(s.as_bytes(), "identifier")?;
        Ok(Self(s.to_owned()))
    }

    pub(crate) fn from_wire(bytes: &[u8], field: &'static str) -> Result<Self> {
        Self::validate(bytes, field)?;
        // Validation guarantees ASCII, so this cannot fail.
        let s = std::str::from_utf8(bytes).map_err(|_| FormatError::InvalidIdentifier(field))?;
        Ok(Self(s.to_owned()))
    }

    fn validate(b: &[u8], field: &'static str) -> Result<()> {
        if b.is_empty() || b.len() > MAX_IDENTIFIER_LEN || !b[0].is_ascii_alphanumeric() {
            return Err(FormatError::InvalidIdentifier(field));
        }
        let ok = b.iter().all(|&c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'.' | b'_' | b':')
        });
        if ok {
            Ok(())
        } else {
            Err(FormatError::InvalidIdentifier(field))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identifier({:?})", self.0)
    }
}

impl std::str::FromStr for Identifier {
    type Err = FormatError;
    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid() {
        for s in [
            "acme-security",
            "example.corp",
            "a",
            "policy:incident_response",
            "x9",
        ] {
            Identifier::new(s).unwrap();
        }
    }

    #[test]
    fn rejects_invalid() {
        let long = "a".repeat(129);
        for s in [
            "",
            "-acme",
            "Acme",
            "acme corp",
            "acme/../x",
            "ac\u{0430}me",
            long.as_str(),
        ] {
            assert!(Identifier::new(s).is_err(), "{s:?} should be rejected");
        }
    }
}
