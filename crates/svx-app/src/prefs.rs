//! Desktop preferences (`desktop.json` next to `config.toml`). Only
//! conveniences: no keys, tokens or file contents.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const MAX_RECENT: usize = 8;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// Most recent first.
    pub recent_recipients: Vec<String>,
    /// Path of the signing key file last used (never its contents).
    pub signing_key: Option<PathBuf>,
    pub last_policy: Option<String>,
}

impl Prefs {
    /// Missing or unreadable preferences are simply empty.
    pub fn load(path: &Path) -> Prefs {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir)?;
        let tmp = tempfile::NamedTempFile::new_in(dir)?;
        serde_json::to_writer_pretty(tmp.as_file(), self)?;
        tmp.persist(path).map_err(|e| e.error)?;
        Ok(())
    }

    pub fn used(&mut self, recipient: &str, signing_key: &Path, policy: &str) {
        self.recent_recipients.retain(|r| r != recipient);
        self.recent_recipients.insert(0, recipient.to_owned());
        self.recent_recipients.truncate(MAX_RECENT);
        self.signing_key = Some(signing_key.to_path_buf());
        self.last_policy = Some(policy.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_recipients_are_deduplicated_and_capped() {
        let mut p = Prefs::default();
        for i in 0..12 {
            p.used(&format!("org-{i}"), Path::new("k"), "pol");
        }
        p.used("org-5", Path::new("k"), "pol");
        assert_eq!(p.recent_recipients.len(), MAX_RECENT);
        assert_eq!(p.recent_recipients[0], "org-5");
        assert_eq!(
            p.recent_recipients.iter().filter(|r| *r == "org-5").count(),
            1
        );
    }

    #[test]
    fn round_trip_and_garbage_tolerant() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("desktop.json");
        assert_eq!(Prefs::load(&path), Prefs::default());
        let mut p = Prefs::default();
        p.used("example-corp", Path::new("/keys/acme.sign.key"), "ir");
        p.save(&path).unwrap();
        assert_eq!(Prefs::load(&path), p);
        std::fs::write(&path, b"not json").unwrap();
        assert_eq!(Prefs::load(&path), Prefs::default());
    }
}
