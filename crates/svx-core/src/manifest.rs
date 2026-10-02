//! The encrypted manifest: everything about the payload that must not be
//! visible to someone who merely holds the file (names, sizes, classification).

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

pub const MANIFEST_VERSION: u32 = 1;
const MAX_NAME_LEN: usize = 255;
const MAX_TEXT_LEN: usize = 4096;
const MAX_FILES: usize = 1;

/// One payload file. SVX 1.0 carries exactly one file; senders who need
/// several should archive them first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub svx_manifest: u32,
    pub files: Vec<FileEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl Manifest {
    pub fn single_file(name: &str, size: u64) -> Self {
        Manifest {
            svx_manifest: MANIFEST_VERSION,
            files: vec![FileEntry {
                name: name.to_owned(),
                size,
                content_type: None,
            }],
            classification: None,
            description: None,
        }
    }

    pub fn total_size(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|e| CoreError::Manifest(e.to_string()))
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let m: Manifest =
            serde_json::from_slice(b).map_err(|e| CoreError::Manifest(e.to_string()))?;
        m.validate()?;
        Ok(m)
    }

    /// Reject anything a client could misuse when writing the payload to
    /// disk: path separators, traversal, control characters, reserved names.
    pub fn validate(&self) -> Result<()> {
        if self.svx_manifest != MANIFEST_VERSION {
            return Err(CoreError::Manifest(format!(
                "unsupported manifest version {}",
                self.svx_manifest
            )));
        }
        if self.files.is_empty() || self.files.len() > MAX_FILES {
            return Err(CoreError::Manifest(
                "SVX 1.0 manifests carry exactly one file".into(),
            ));
        }
        for f in &self.files {
            validate_name(&f.name)?;
            if let Some(ct) = &f.content_type {
                validate_text(ct, "content_type")?;
            }
        }
        if let Some(c) = &self.classification {
            validate_text(c, "classification")?;
        }
        if let Some(d) = &self.description {
            validate_text(d, "description")?;
        }
        Ok(())
    }
}

fn validate_text(s: &str, what: &str) -> Result<()> {
    if s.len() > MAX_TEXT_LEN || s.chars().any(|c| c.is_control() && c != '\n') {
        return Err(CoreError::Manifest(format!("invalid {what}")));
    }
    Ok(())
}

/// A safe single path component.
pub(crate) fn validate_name(name: &str) -> Result<()> {
    let bad = name.is_empty()
        || name.len() > MAX_NAME_LEN
        || name == "."
        || name == ".."
        || name.starts_with('.') && name.chars().all(|c| c == '.')
        || name
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\' | ':' | '\0'))
        || name.ends_with(' ')
        || name.ends_with('.')
        || is_windows_reserved(name);
    if bad {
        Err(CoreError::Manifest(format!("unsafe file name {name:?}")))
    } else {
        Ok(())
    }
}

fn is_windows_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in ["secret.txt", "evidence.zip", "report 2026.pdf", "naïve.txt"] {
            validate_name(ok).unwrap();
        }
        for bad in [
            "",
            ".",
            "..",
            "../etc/passwd",
            "a/b",
            "a\\b",
            "C:evil",
            "x\0y",
            "nul.txt",
            "COM1",
            "trail.",
            "trail ",
            "new\nline",
        ] {
            assert!(validate_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn round_trip() {
        let mut m = Manifest::single_file("secret.txt", 12);
        m.classification = Some("TLP:AMBER".into());
        assert_eq!(Manifest::from_bytes(&m.to_bytes().unwrap()).unwrap(), m);
    }
}
