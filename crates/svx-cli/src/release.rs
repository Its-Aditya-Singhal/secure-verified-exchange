//! `svx release`: sign desktop app releases for the update server.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha512};
use svx_core::keyfile;
use svx_protocol::update::{
    MANIFEST_VERSION, PRODUCT, PlatformRelease, ReleaseManifest, SignedReleaseManifest,
    parse_version, release_key_fingerprint,
};

/// A file name safe to serve: what the update server accepts.
fn served_name(platform: &str, version: &str, package: &Path) -> Result<String> {
    let file = package
        .file_name()
        .and_then(|f| f.to_str())
        .context("package has no file name")?;
    // Keep the extension the updater needs (.app.tar.gz, .msi, .exe, …).
    let ext = [
        ".app.tar.gz",
        ".tar.gz",
        ".msi",
        ".exe",
        ".AppImage",
        ".deb",
        ".zip",
    ]
    .into_iter()
    .find(|e| file.ends_with(e))
    .with_context(|| format!("{file}: not an update package"))?;
    Ok(format!("svx-desktop-{version}-{platform}{ext}"))
}

pub fn sign(
    key: &Path,
    version: &str,
    notes: &str,
    base_url: &str,
    platforms: &[String],
    out: &Path,
) -> Result<ExitCode> {
    if parse_version(version).is_none() {
        bail!("the version must be major.minor.patch, like 0.2.0");
    }
    svx_protocol::check_url(base_url, true).context("--base-url")?;
    let (_, sk) = keyfile::load_signing_key(key).context("reading the release key")?;
    std::fs::create_dir_all(out)?;
    let mut entries = BTreeMap::new();
    for p in platforms {
        let (name, path) = p
            .split_once('=')
            .with_context(|| format!("expected <os>-<arch>=<package>, got {p:?}"))?;
        let path = Path::new(path);
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let sig_path = format!("{}.sig", path.display());
        let signature = std::fs::read_to_string(&sig_path).with_context(|| {
            format!("reading {sig_path} (build with createUpdaterArtifacts and TAURI_SIGNING_PRIVATE_KEY)")
        })?;
        let served = served_name(name, version, path)?;
        std::fs::write(out.join(&served), &bytes)?;
        entries.insert(
            name.to_owned(),
            PlatformRelease {
                url: format!("{}/{served}", base_url.trim_end_matches('/')),
                size: bytes.len() as u64,
                sha512: hex::encode(Sha512::digest(&bytes)),
                signature: signature.trim().to_owned(),
            },
        );
        println!("{name}: {served} ({} bytes)", bytes.len());
    }
    let manifest = ReleaseManifest {
        v: MANIFEST_VERSION,
        product: PRODUCT.into(),
        version: version.into(),
        released_at: svx_protocol::unix_now(),
        notes: notes.into(),
        platforms: entries,
    };
    let signed = SignedReleaseManifest::sign(&manifest, &sk)
        .context("the release key must be an SVX-2 signing key (svx keygen --kind sign)")?;
    let fp = release_key_fingerprint(&sk.verifying_key());
    // Check what we wrote, as the app will.
    signed.verify(&fp)?;
    std::fs::write(
        out.join("manifest.json"),
        serde_json::to_vec_pretty(&signed)?,
    )?;
    println!("Signed {version} with release key {fp}");
    println!("Wrote {}", out.join("manifest.json").display());
    Ok(ExitCode::SUCCESS)
}

pub fn verify(manifest: &Path, fingerprint: &str) -> Result<ExitCode> {
    let signed: SignedReleaseManifest = serde_json::from_slice(&std::fs::read(manifest)?)?;
    let m = signed.verify(fingerprint)?;
    println!(
        "Valid release {} ({} platform(s))",
        m.version,
        m.platforms.len()
    );
    for (name, p) in &m.platforms {
        println!("  {name}: {} ({} bytes)", p.url, p.size);
    }
    Ok(ExitCode::SUCCESS)
}

pub fn fingerprint(public: &Path) -> Result<ExitCode> {
    let (_, vk) = keyfile::load_verifying_key(public).context("reading the release key")?;
    if vk.kind() != svx_core::crypto::KeyKind::MaxSigning {
        bail!("release keys are SVX-2 signing keys (svx keygen --kind sign)");
    }
    println!("{}", release_key_fingerprint(&vk));
    Ok(ExitCode::SUCCESS)
}
