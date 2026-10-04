//! Desktop preferences (`desktop.json` next to `config.toml`). Only
//! conveniences: no keys, tokens or file contents.

use std::path::Path;

use serde::{Deserialize, Serialize};
use svx_client::keyadmin::ExportedKemKey;
use svx_client::onboard::PendingOrg;

const MAX_RECENT: usize = 8;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// Most recent first.
    pub recent_recipients: Vec<String>,
    /// The signing key to use: a key file path or `keychain:<org>/<key_id>`
    /// (a reference, never the key itself).
    pub signing_key: Option<String>,
    pub last_policy: Option<String>,
    /// A new organization's registration waiting for its DNS record.
    pub pending_org: Option<PendingOrg>,
    /// An encryption key exported for the key agent, not yet activated.
    pub pending_encryption_key: Option<ExportedKemKey>,
    /// Ask for Touch ID / the computer's password / Windows Hello before
    /// using the keys. `None` = on (the default).
    pub ask_presence: Option<bool>,
    /// Minutes an unlocked session lasts without use (default 15).
    pub relock_minutes: Option<u32>,
}

/// Bounds for [`Prefs::relock_minutes`].
pub const RELOCK_MINUTES: std::ops::RangeInclusive<u32> = 1..=240;

impl Prefs {
    pub fn presence_on(&self) -> bool {
        self.ask_presence.unwrap_or(true)
    }

    pub fn relock(&self) -> std::time::Duration {
        let m = self
            .relock_minutes
            .filter(|m| RELOCK_MINUTES.contains(m))
            .unwrap_or(15);
        std::time::Duration::from_secs(u64::from(m) * 60)
    }

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

    pub fn used(&mut self, recipient: &str, signing_key: &str, policy: &str) {
        self.recent_recipients.retain(|r| r != recipient);
        self.recent_recipients.insert(0, recipient.to_owned());
        self.recent_recipients.truncate(MAX_RECENT);
        self.signing_key = Some(signing_key.to_owned());
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
            p.used(&format!("org-{i}"), "k", "pol");
        }
        p.used("org-5", "k", "pol");
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
        p.used("example-corp", "/keys/acme.sign.key", "ir");
        // Preferences written by Phase 5a (a key file path) still load.
        let old =
            br#"{"recent_recipients":["x"],"signing_key":"/keys/a.sign.key","last_policy":"p"}"#;
        std::fs::write(&path, old).unwrap();
        assert_eq!(
            Prefs::load(&path).signing_key.as_deref(),
            Some("/keys/a.sign.key")
        );
        p.save(&path).unwrap();
        assert_eq!(Prefs::load(&path), p);
        std::fs::write(&path, b"not json").unwrap();
        assert_eq!(Prefs::load(&path), Prefs::default());
    }
}
