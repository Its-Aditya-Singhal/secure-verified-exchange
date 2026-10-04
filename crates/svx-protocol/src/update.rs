//! Desktop app updates: a release manifest signed offline with the release
//! key, whose fingerprint is built into the app.
//!
//! The manifest names, per platform, the update package's URL, size,
//! SHA-512 and Tauri updater signature. The app installs a package only if
//! the manifest verifies (all three signatures of an SVX-2 key), it is a
//! newer version than the one running, the package's Tauri (minisign)
//! signature verifies, and its size and SHA-512 match the manifest. The
//! update server is not trusted for any of this.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use svx_core::crypto::{
    CryptoError, KeyKind, SignContext, SigningKey, VerifyingKey, sign_context, verify_context,
};

use crate::encoding::{b64, hex_vec};

pub const MANIFEST_VERSION: u32 = 1;
pub const PRODUCT: &str = "svx-desktop";
/// Upper bound on a manifest payload.
const MAX_MANIFEST_LEN: usize = 64 * 1024;

/// One platform's update package.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformRelease {
    /// Where to download it (https).
    pub url: String,
    pub size: u64,
    /// SHA-512 of the package, hex.
    pub sha512: String,
    /// The Tauri updater signature (contents of the `.sig` file).
    pub signature: String,
}

/// A release of the desktop app.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub v: u32,
    pub product: String,
    /// `major.minor.patch`.
    pub version: String,
    pub released_at: i64,
    #[serde(default)]
    pub notes: String,
    /// Keyed by `<os>-<arch>` as the Tauri updater names them, for example
    /// `darwin-aarch64`, `windows-x86_64`, `linux-x86_64`.
    pub platforms: BTreeMap<String, PlatformRelease>,
}

/// What the update server publishes at `/v1/updates/manifest`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReleaseManifest {
    #[serde(with = "b64")]
    pub payload: Vec<u8>,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
    /// The release key (SVX-2); the app checks it against its pinned
    /// fingerprint before using it.
    #[serde(with = "hex_vec")]
    pub public_key: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UpdateError {
    #[error("the release is signed by a key this app doesn't trust")]
    WrongKey,
    #[error("the release signature is invalid")]
    BadSignature,
    #[error("the release manifest is malformed: {0}")]
    Malformed(String),
}

/// A release key's fingerprint, as built into the app (64 hex; the same
/// value `svx keygen --kind sign` prints).
pub fn release_key_fingerprint(key: &VerifyingKey) -> String {
    hex::encode(key.fingerprint())
}

/// A version as `(major, minor, patch)`; pre-release and build suffixes
/// are not accepted.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.trim().split('.');
    let mut next = || -> Option<u64> {
        let p = it.next()?;
        if p.is_empty() || p.len() > 9 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        p.parse().ok()
    };
    let r = (next()?, next()?, next()?);
    it.next().is_none().then_some(r)
}

impl ReleaseManifest {
    /// The checks [`SignedReleaseManifest::verify`] applies after the
    /// signature (public for fuzzing).
    pub fn check(&self) -> Result<(), UpdateError> {
        let bad = |m: &str| Err(UpdateError::Malformed(m.into()));
        if self.v != MANIFEST_VERSION {
            return bad("unknown manifest version");
        }
        if self.product != PRODUCT {
            return bad("not a release of this app");
        }
        if parse_version(&self.version).is_none() {
            return bad("invalid version");
        }
        for (name, p) in &self.platforms {
            let ok_name = name.split_once('-').is_some_and(|(os, arch)| {
                matches!(os, "darwin" | "windows" | "linux")
                    && matches!(arch, "aarch64" | "x86_64" | "universal")
            });
            if !ok_name {
                return bad("unknown platform");
            }
            if p.sha512.len() != 128 || hex::decode(&p.sha512).is_err() {
                return bad("invalid package hash");
            }
            if p.size == 0 || p.signature.is_empty() || url::Url::parse(&p.url).is_err() {
                return bad("invalid package entry");
            }
        }
        Ok(())
    }
}

impl SignedReleaseManifest {
    /// Sign a manifest with the release key (an SVX-2 key; offline).
    pub fn sign(m: &ReleaseManifest, key: &SigningKey) -> Result<Self, CryptoError> {
        if key.kind() != KeyKind::MaxSigning {
            return Err(CryptoError::WrongKeyKind);
        }
        let payload = serde_json::to_vec_pretty(m).expect("manifest serializes");
        let signature = sign_context(key, SignContext::ReleaseManifest, &payload)?;
        Ok(SignedReleaseManifest {
            payload,
            signature,
            public_key: key.verifying_key().to_vec(),
        })
    }

    /// Check the key against the pinned fingerprint, verify every
    /// signature, then parse and check the manifest.
    pub fn verify(&self, pinned_fingerprint: &str) -> Result<ReleaseManifest, UpdateError> {
        let key = VerifyingKey::from_kind_bytes(KeyKind::MaxSigning, &self.public_key)
            .map_err(|_| UpdateError::WrongKey)?;
        if !release_key_fingerprint(&key).eq_ignore_ascii_case(pinned_fingerprint.trim()) {
            return Err(UpdateError::WrongKey);
        }
        if self.payload.len() > MAX_MANIFEST_LEN {
            return Err(UpdateError::Malformed("too large".into()));
        }
        verify_context(
            &key,
            SignContext::ReleaseManifest,
            &self.payload,
            &self.signature,
        )
        .map_err(|_| UpdateError::BadSignature)?;
        let m: ReleaseManifest = serde_json::from_slice(&self.payload)
            .map_err(|e| UpdateError::Malformed(e.to_string()))?;
        m.check()?;
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use svx_core::crypto::os_rng;

    pub(crate) fn manifest(version: &str) -> ReleaseManifest {
        let mut platforms = BTreeMap::new();
        platforms.insert(
            "darwin-aarch64".into(),
            PlatformRelease {
                url: "https://updates.svx.example/v1/updates/files/app.tar.gz".into(),
                size: 10,
                sha512: "ab".repeat(64),
                signature: "minisign".into(),
            },
        );
        ReleaseManifest {
            v: MANIFEST_VERSION,
            product: PRODUCT.into(),
            version: version.into(),
            released_at: 1,
            notes: "Fixes".into(),
            platforms,
        }
    }

    #[test]
    fn sign_verify_and_tamper() {
        let k = SigningKey::generate_max(&mut os_rng());
        let fp = release_key_fingerprint(&k.verifying_key());
        let s = SignedReleaseManifest::sign(&manifest("1.2.3"), &k).unwrap();
        assert_eq!(s.verify(&fp).unwrap(), manifest("1.2.3"));
        assert_eq!(s.verify(&fp.to_uppercase()).unwrap().version, "1.2.3");

        // Another key, even a valid one, is refused.
        let other = SigningKey::generate_max(&mut os_rng());
        let o = SignedReleaseManifest::sign(&manifest("9.9.9"), &other).unwrap();
        assert_eq!(o.verify(&fp).unwrap_err(), UpdateError::WrongKey);
        let mut swapped = o.clone();
        swapped.public_key = s.public_key.clone();
        assert_eq!(swapped.verify(&fp).unwrap_err(), UpdateError::BadSignature);

        // Any change to the payload breaks the signature.
        let mut t = s.clone();
        let i = t.payload.iter().position(|&b| b == b'3').unwrap();
        t.payload[i] = b'4';
        assert_eq!(t.verify(&fp).unwrap_err(), UpdateError::BadSignature);
        // So does dropping the SLH-DSA part.
        let mut t = s.clone();
        t.signature.truncate(4691);
        assert_eq!(t.verify(&fp).unwrap_err(), UpdateError::BadSignature);
        // Only SVX-2 release keys sign.
        let ed = SigningKey::generate(&mut os_rng());
        assert!(SignedReleaseManifest::sign(&manifest("1.0.0"), &ed).is_err());
    }

    #[test]
    fn malformed_manifests_are_refused() {
        let k = SigningKey::generate_max(&mut os_rng());
        let fp = release_key_fingerprint(&k.verifying_key());
        let mut cases = vec![];
        let mut m = manifest("1.0");
        cases.push(m.clone());
        m = manifest("1.0.0");
        m.product = "other".into();
        cases.push(m);
        let mut m = manifest("1.0.0");
        m.platforms.get_mut("darwin-aarch64").unwrap().sha512 = "00".into();
        cases.push(m);
        let mut m = manifest("1.0.0");
        let p = m.platforms.remove("darwin-aarch64").unwrap();
        m.platforms.insert("plan9-mips".into(), p);
        cases.push(m);
        for m in cases {
            let s = SignedReleaseManifest::sign(&m, &k).unwrap();
            assert!(
                matches!(s.verify(&fp), Err(UpdateError::Malformed(_))),
                "{m:?}"
            );
        }
    }

    #[test]
    fn versions() {
        assert_eq!(parse_version("0.1.0"), Some((0, 1, 0)));
        assert_eq!(parse_version("10.20.30"), Some((10, 20, 30)));
        for bad in [
            "1.0",
            "1.0.0.0",
            "1.0.0-beta",
            "v1.0.0",
            "1..0",
            "",
            "1.0.x",
        ] {
            assert_eq!(parse_version(bad), None, "{bad}");
        }
        assert!(parse_version("0.10.0") > parse_version("0.9.9"));
    }
}
