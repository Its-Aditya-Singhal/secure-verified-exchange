//! Desktop app updates: the service publishes a release signed offline; the
//! client accepts it only with the pinned release key, a newer version and
//! a package matching the signed size and SHA-512. Skipped without
//! `SVX_TEST_DATABASE_URL`.

use std::collections::BTreeMap;

use sha2::{Digest, Sha512};
use svx_client::ClientError;
use svx_client::update::{UpdateSource, check, verify_package};
use svx_core::crypto::{SigningKey, os_rng};
use svx_protocol::update::{
    MANIFEST_VERSION, PRODUCT, PlatformRelease, ReleaseManifest, SignedReleaseManifest,
    release_key_fingerprint,
};
use svx_testkit::*;

macro_rules! world {
    () => {
        match World::new().await {
            Some(w) => w,
            None => return,
        }
    };
}

const PACKAGE: &[u8] = b"FICTIONAL update package for Secure Verified Exchange 0.2.0";

fn publish(w: &World, key: &SigningKey, version: &str) {
    let name = format!("svx-desktop-{version}-darwin-aarch64.app.tar.gz");
    std::fs::write(w.updates_dir.join(&name), PACKAGE).unwrap();
    let mut platforms = BTreeMap::new();
    platforms.insert(
        "darwin-aarch64".to_string(),
        PlatformRelease {
            url: format!("{}/v1/updates/files/{name}", w.service_url),
            size: PACKAGE.len() as u64,
            sha512: hex::encode(Sha512::digest(PACKAGE)),
            signature: "dW50cnVzdGVkIGNvbW1lbnQ=".into(),
        },
    );
    let m = ReleaseManifest {
        v: MANIFEST_VERSION,
        product: PRODUCT.into(),
        version: version.into(),
        released_at: 1,
        notes: "Faster opening.".into(),
        platforms,
    };
    let signed = SignedReleaseManifest::sign(&m, key).unwrap();
    std::fs::write(
        w.updates_dir.join("manifest.json"),
        serde_json::to_vec(&signed).unwrap(),
    )
    .unwrap();
}

fn source(w: &World, key: &SigningKey) -> UpdateSource {
    UpdateSource {
        base_url: format!("{}/v1/updates", w.service_url),
        release_key: release_key_fingerprint(&key.verifying_key()),
        dev: true,
    }
}

#[tokio::test]
async fn signed_updates_newer_only_and_matching() {
    let w = world!();
    let key = SigningKey::generate_max(&mut os_rng());
    let src = source(&w, &key);

    // Nothing published yet.
    assert!(check(&src, "0.1.0", "darwin-aarch64").await.is_err());

    publish(&w, &key, "0.2.0");
    let u = check(&src, "0.1.0", "darwin-aarch64")
        .await
        .unwrap()
        .expect("an update");
    assert_eq!(u.version, "0.2.0");
    assert_eq!(u.notes, "Faster opening.");
    // Not for this platform, or not newer: nothing to do.
    assert!(
        check(&src, "0.1.0", "windows-x86_64")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        check(&src, "0.2.0", "darwin-aarch64")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        check(&src, "0.10.0", "darwin-aarch64")
            .await
            .unwrap()
            .is_none()
    );

    // The package as served matches; anything else is refused.
    let http = reqwest::Client::new();
    let bytes = http
        .get(&u.package.url)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    verify_package(&bytes, &u.package).unwrap();
    let mut evil = bytes.to_vec();
    evil[0] ^= 1;
    assert!(matches!(
        verify_package(&evil, &u.package),
        Err(ClientError::Rejected(_))
    ));

    // The Tauri updater's view of the same release.
    let t: serde_json::Value = http
        .get(format!(
            "{}/v1/updates/tauri/darwin/aarch64/0.1.0",
            w.service_url
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(t["version"], "0.2.0");
    assert_eq!(t["url"], u.package.url.as_str());
    let none = http
        .get(format!(
            "{}/v1/updates/tauri/darwin/aarch64/0.2.0",
            w.service_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(none.status(), 204);
    // Only plain file names are served.
    for bad in ["manifest.json", "..%2Fetc%2Fpasswd", ".hidden"] {
        let r = http
            .get(format!("{}/v1/updates/files/{bad}", w.service_url))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "{bad}");
    }

    // A release signed by another key is refused, even if newer.
    let other = SigningKey::generate_max(&mut os_rng());
    publish(&w, &other, "9.0.0");
    assert!(matches!(
        check(&src, "0.1.0", "darwin-aarch64").await,
        Err(ClientError::Rejected(m)) if m.contains("trust")
    ));
    // A tampered manifest is refused.
    publish(&w, &key, "0.3.0");
    let path = w.updates_dir.join("manifest.json");
    let mut signed: SignedReleaseManifest =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let text = String::from_utf8(signed.payload.clone()).unwrap();
    signed.payload = text.replace("0.3.0", "0.4.0").into_bytes();
    std::fs::write(&path, serde_json::to_vec(&signed).unwrap()).unwrap();
    assert!(matches!(
        check(&src, "0.1.0", "darwin-aarch64").await,
        Err(ClientError::Rejected(m)) if m.contains("signature")
    ));
    w.cleanup().await.unwrap();
}
