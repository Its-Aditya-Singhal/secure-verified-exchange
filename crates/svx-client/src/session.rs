//! Short-lived admin session cache.
//!
//! `svx login` stores the ID token here (owner-only permissions) so admin
//! commands do not need a browser round trip each time. The token is used
//! **only** as a bearer for admin endpoints. It can never release key
//! shares: release requires a token whose `nonce` binds a fresh ephemeral
//! key, so `svx open` always logs in again.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::error::{ClientError, Result};

/// Sessions closer than this to expiry are treated as expired.
const EXPIRY_MARGIN_SECS: i64 = 15;
const MAX_SESSION_FILE: u64 = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub id_token: String,
    pub issuer: String,
    pub sub: String,
    pub exp: i64,
}

/// Read `exp` from a token we just received from our own IdP. The token
/// itself is validated separately (`svx_oidc`); this only sets cache expiry.
pub fn token_exp(token: &str) -> Option<i64> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("exp")?.as_i64()
}

pub fn save(path: &Path, s: &Session) -> Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    // NamedTempFile is created 0600 on Unix; rename is atomic.
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    serde_json::to_writer(&mut tmp, s).map_err(|e| ClientError::Other(e.to_string()))?;
    tmp.persist(path).map_err(|e| ClientError::Io(e.error))?;
    Ok(())
}

/// A valid, unexpired session, or `None`. Expired, oversized, unreadable or
/// over-permissive session files are deleted.
pub fn load(path: &Path, now: i64) -> Option<Session> {
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            let _ = std::fs::remove_file(path);
            return None;
        }
    }
    if meta.len() > MAX_SESSION_FILE {
        let _ = std::fs::remove_file(path);
        return None;
    }
    let s: Option<Session> = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    match s {
        Some(s) if s.exp > now + EXPIRY_MARGIN_SECS => Some(s),
        _ => {
            let _ = std::fs::remove_file(path);
            None
        }
    }
}

pub fn require(path: &Path, now: i64) -> Result<Session> {
    load(path, now).ok_or(ClientError::NotLoggedIn)
}

pub fn clear(path: &Path) -> Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(exp: i64) -> Session {
        Session {
            id_token: "a.b.c".into(),
            issuer: "https://idp".into(),
            sub: "alice".into(),
            exp,
        }
    }

    #[test]
    fn lifecycle() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("session.json");
        assert!(load(&p, 1000).is_none());
        save(&p, &s(2000)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(load(&p, 1000).unwrap().sub, "alice");
        // Expired (with margin) → removed.
        assert!(load(&p, 1990).is_none());
        assert!(!p.exists());
        save(&p, &s(2000)).unwrap();
        assert!(clear(&p).unwrap());
        assert!(!clear(&p).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_session_is_discarded() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("session.json");
        save(&p, &s(2000)).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&p, 1000).is_none());
        assert!(!p.exists());
    }

    #[test]
    fn exp_from_token() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"exp":12345,"sub":"x"}"#);
        assert_eq!(token_exp(&format!("h.{payload}.s")), Some(12345));
        assert_eq!(token_exp("garbage"), None);
    }
}
