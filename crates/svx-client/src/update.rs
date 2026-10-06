//! Desktop app updates: find a newer release and check its package. The
//! desktop shell downloads and installs it with the Tauri updater, but only
//! after [`check`] verified the signed release manifest, and installs only
//! bytes that pass [`verify_package`].
//!
//! The release key's fingerprint and the update URL are built into release
//! builds (`SVX_RELEASE_KEY`, `SVX_UPDATE_URL` at build time). Builds made
//! without them read the same variables at run time (development), and
//! check nothing otherwise.

use serde::Serialize;
use sha2::{Digest, Sha512};
use svx_protocol::update::{PlatformRelease, SignedReleaseManifest, parse_version};
use svx_protocol::{ManagedClient, ProtocolError, check_url};

use crate::error::{ClientError, Result};

const BUILT_IN_URL: Option<&str> = option_env!("SVX_UPDATE_URL");
const BUILT_IN_KEY: Option<&str> = option_env!("SVX_RELEASE_KEY");

/// Where updates come from, and the release key they must be signed with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateSource {
    /// Base URL, e.g. `https://svx.example/v1/updates`.
    pub base_url: String,
    /// Release key fingerprint (64 hex).
    pub release_key: String,
    /// Plain-http loopback allowed (local testing).
    pub dev: bool,
}

impl UpdateSource {
    pub fn manifest_url(&self) -> String {
        format!("{}/manifest", self.base_url.trim_end_matches('/'))
    }

    /// The Tauri updater's endpoint (its `{{target}}`, `{{arch}}` and
    /// `{{current_version}}` placeholders are filled in by the updater).
    pub fn tauri_endpoint(&self) -> String {
        format!(
            "{}/tauri/{{{{target}}}}/{{{{arch}}}}/{{{{current_version}}}}",
            self.base_url.trim_end_matches('/')
        )
    }
}

fn loopback_http(url: &str) -> bool {
    url::Url::parse(url).is_ok_and(|u| {
        u.scheme() == "http" && matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
    })
}

/// The update source of this build, if it has one.
pub fn update_source() -> Option<UpdateSource> {
    let (url, key) = match (BUILT_IN_URL, BUILT_IN_KEY) {
        (Some(u), Some(k)) => (u.to_owned(), k.to_owned()),
        // Nothing built in: development builds may name one at run time.
        _ => {
            let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
            (env("SVX_UPDATE_URL")?, env("SVX_RELEASE_KEY")?)
        }
    };
    let url = url.trim().to_owned();
    let key = key.trim().to_ascii_lowercase();
    if key.len() != 64 || hex::decode(&key).is_err() {
        return None;
    }
    let dev = loopback_http(&url);
    check_url(&url, dev).ok()?;
    Some(UpdateSource {
        base_url: url,
        release_key: key,
        dev,
    })
}

/// The Tauri updater's name for this platform, e.g. `darwin-aarch64`.
pub fn platform_key() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    format!("{os}-{}", std::env::consts::ARCH)
}

/// A newer release, verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AvailableUpdate {
    pub version: String,
    pub notes: String,
    pub released_at: i64,
    pub platform: String,
    pub package: PlatformRelease,
}

/// Fetch and verify the release manifest; `Some` if it offers a newer
/// version than `current` for `platform`.
pub async fn check(
    src: &UpdateSource,
    current: &str,
    platform: &str,
) -> Result<Option<AvailableUpdate>> {
    let current_v = parse_version(current)
        .ok_or_else(|| ClientError::Config(format!("invalid app version {current:?}")))?;
    let http = ManagedClient::new(src.dev)?;
    check_url(&src.base_url, src.dev)?;
    let resp = http
        .http()
        .get(src.manifest_url())
        .send()
        .await
        .map_err(ProtocolError::from)?;
    // No release published yet (a new service): there is nothing to update
    // to. That is not an error, and must never read like a refusal.
    if resp.status().as_u16() == 404 {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(ProtocolError::Status(resp.status().as_u16()).into());
    }
    let signed: SignedReleaseManifest = resp
        .json()
        .await
        .map_err(|e| ProtocolError::BadResponse(e.to_string()))?;
    let m = signed
        .verify(&src.release_key)
        .map_err(|e| ClientError::Rejected(format!("update refused: {e}")))?;
    let v = parse_version(&m.version).expect("checked by verify");
    // Never go back (or sideways) to a version that isn't newer.
    if v <= current_v {
        return Ok(None);
    }
    let Some(package) = m.platforms.get(platform).cloned() else {
        return Ok(None);
    };
    check_url(&package.url, src.dev)
        .map_err(|_| ClientError::Rejected("update refused: insecure download URL".into()))?;
    Ok(Some(AvailableUpdate {
        version: m.version,
        notes: m.notes,
        released_at: m.released_at,
        platform: platform.to_owned(),
        package,
    }))
}

/// Check a downloaded package against the signed manifest: exact size and
/// SHA-512.
pub fn verify_package(bytes: &[u8], package: &PlatformRelease) -> Result<()> {
    let hash = hex::encode(Sha512::digest(bytes));
    if bytes.len() as u64 != package.size || !hash.eq_ignore_ascii_case(&package.sha512) {
        return Err(ClientError::Rejected(
            "update refused: the download doesn't match the signed release".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_hash_and_size() {
        let bytes = b"package bytes";
        let p = PlatformRelease {
            url: "https://u.example/p".into(),
            size: bytes.len() as u64,
            sha512: hex::encode(Sha512::digest(bytes)),
            signature: "sig".into(),
        };
        verify_package(bytes, &p).unwrap();
        assert!(verify_package(b"package bytez", &p).is_err());
        assert!(verify_package(b"package bytes!", &p).is_err());
    }

    #[test]
    fn endpoints_and_platform() {
        let s = UpdateSource {
            base_url: "https://svx.example/v1/updates/".into(),
            release_key: "00".repeat(32),
            dev: false,
        };
        assert_eq!(s.manifest_url(), "https://svx.example/v1/updates/manifest");
        assert_eq!(
            s.tauri_endpoint(),
            "https://svx.example/v1/updates/tauri/{{target}}/{{arch}}/{{current_version}}"
        );
        assert!(platform_key().contains('-'));
        assert!(loopback_http("http://127.0.0.1:9/v1/updates"));
        assert!(!loopback_http("http://evil.example/v1/updates"));
    }
}
