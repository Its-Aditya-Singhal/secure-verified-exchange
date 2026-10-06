# Releasing the desktop app

Desktop releases update themselves from the SVX service. This costs nothing: there are no paid signing certificates, and the update server is the SVX service itself (or any static host). Updates are protected by two signatures made with our own keys. The service is not trusted for any of this. See [desktop.md](desktop.md#updates) for what the app checks.

## Keys

Both keys are kept off the repository, in `~/.svx-release` (owner-only, `chmod 700`). Back the folder up somewhere offline: without these keys, installed apps can't be updated any more and would have to be reinstalled.

| File | What | Made with |
|------|------|-----------|
| `release.sign.key`, `release.sign.pub` | **SVX-2 release key** (Ed25519 + ML-DSA-87 + SLH-DSA). Signs `manifest.json`. Its fingerprint is built into every release build as `SVX_RELEASE_KEY`. | `svx keygen --kind sign --owner svx-release --out ~/.svx-release/release` |
| `tauri.key`, `tauri.key.password` | **Tauri updater key** (minisign Ed25519). Signs each package. Its public half is `plugins.updater.pubkey` in `apps/desktop/src-tauri/tauri.conf.json`. | `npx tauri signer generate -w ~/.svx-release/tauri.key -p <password>` |

`svx release fingerprint ~/.svx-release/release.sign.pub` prints the fingerprint.

**Rotating a key.** Ship one release built with both the old and the new key's trust, then switch:
- For the release key: build that release with the new `SVX_RELEASE_KEY`, signed with the old key.
- For the Tauri key: put the new `pubkey` in that release, and sign its package with the old key.

A lost key can't be rotated this way. Users then reinstall by hand.

## Making a release

```sh
scripts/release.sh 0.2.0 --update-url https://svx.example/v1/updates --notes "Faster opening."
```

The script does five things:

1. Reads the release key fingerprint.
2. Builds the app with that fingerprint and `SVX_UPDATE_URL` built in. It uses `tauri.release.conf.json`, which turns on `createUpdaterArtifacts`, and sets the version.
3. Signs the package with the Tauri key. The signature records the version, and the app requires that (`requireSignedVersion`).
4. Runs `svx release sign`. That copies the package to `dist-release/0.2.0/` with a plain file name and writes `manifest.json`: version, notes, and for each platform the URL, size, SHA-512 and Tauri signature. The manifest is signed with the release key and checked again as the app will check it.
5. Prints where the result is.

Copy `dist-release/0.2.0/` to the service's updates directory, then run:

```sh
svx-server … --updates-dir /srv/svx/updates
svx release verify /srv/svx/updates/manifest.json --fingerprint <release key fingerprint>
```

**Platforms.** The macOS package is built on the release Mac. Windows is built on GitHub and signed on the Mac:

```sh
git push                                        # GitHub builds the pushed branch
scripts/fetch-windows-build.sh 0.2.0            # starts .github/workflows/windows.yml, waits, downloads
scripts/release.sh 0.2.0 --update-url … --service-url … --registry-fingerprint … \
  --windows-package "dist-release/0.2.0/windows/Secure Verified Exchange_0.2.0_x64-setup.exe"
```

- **The Windows workflow** runs only when started by hand (`workflow_dispatch`), never on a push. It holds no secrets: the values it builds in (service URL, registry and release key fingerprints) are public. It uploads the unsigned NSIS installer for 3 days.
- **`--windows-package`** signs that installer with the Tauri key on the Mac, checks the signature names the version, and lists it as `windows-x86_64` in the same manifest. The updater on Windows runs it in passive mode; the install is per user and needs no administrator.
- **Linux** has no release build yet; on Linux the script makes the AppImage.

`manifest.json` lists every platform of a release, so sign once, after collecting all the packages.

## Testing updates locally

This uses a loopback http server, so the test builds use `tauri.localtest.conf.json`. That file sets the updater's `dangerousInsecureTransportProtocol`. Never publish such a build.

```sh
# 0. Work under the real path /private/tmp (on macOS /tmp is a symlink to it).
#    Tauri refuses to update an app reached through a symlink, and the app says so.
T=/private/tmp

# 1. The service on a fixed port, publishing from $T/svx-updates
cargo run -p svx-demo -- serve --state-dir $T/svx-stack --service-port 8790 --updates-dir $T/svx-updates

# 2. Version 0.1.0 with that update source built in (not published)
scripts/release.sh 0.1.0 --update-url http://127.0.0.1:8790/v1/updates --local --build-only
mkdir -p "$T/svx-test-apps/0.1.0"
cp -R "target/release/bundle/macos/Secure Verified Exchange.app" "$T/svx-test-apps/0.1.0/"

# 3. Version 0.1.1, signed and published to $T/svx-updates
scripts/release.sh 0.1.1 --update-url http://127.0.0.1:8790/v1/updates --local --out $T/svx-updates

# 4. Run 0.1.0 with a test configuration: it offers 0.1.1, installs it and restarts
SVX_CONFIG=$T/svx-update-test/config.toml \
  "$T/svx-test-apps/0.1.0/Secure Verified Exchange.app/Contents/MacOS/svx-desktop"
```

To check that tampered updates are refused, change a byte of the package in `$T/svx-updates`, or sign a manifest with another key. The app must show "update refused" and keep running the old version. `crates/svx-testkit/tests/updates.rs` covers the same cases automatically.

## Where the app must live

On macOS the updater only works when the app's own path has no symbolic link in it. Running from `/tmp` fails because `/tmp` is a link to `/private/tmp`; the app then says "update failed: … goes through a symbolic link … Move the app to the Applications folder". Installed apps in `/Applications` or `~/Applications` are fine, and so are Linux and Windows.

Windows installers aren't code-signed (that needs a paid certificate), so the first install shows "Windows protected your PC": **More info → Run anyway**. Updates after that are verified as above.

## What is not covered

- **Freeze attacks.** A malicious update server can keep serving an old manifest, so the app never learns about a newer version. It can't install anything old: the app only ever moves forward.
- **Unsigned first install.** The first download comes from the website or a direct link. Its integrity depends on that channel (https) until the app is installed. From then on, updates are verified as above.

## macOS signing and the keychain

Every macOS build is re-signed with one self-made certificate
(`~/.svx-release/macos-signing.p12`, made once by
`scripts/make-signing-cert.sh`, valid 20 years). The app's identity is then
`identifier "org.svx.desktop" and certificate root = H"2734d30f…"` for every
version, so the keychain items it created stay readable after an update.
With ad-hoc signing (before 0.1.3) each build had a different identity, and
macOS asked for the login keychain password after every update.

`scripts/release.sh` builds with Tauri (ad-hoc), re-signs the app from a
private temporary keychain with the same options (hardened runtime, no
entitlements), and rebuilds and re-signs the update package. The certificate
isn't from Apple: Gatekeeper still treats the app as from an unidentified
developer, and macOS doesn't need to trust it. Keep the `.p12` and its
password with the other release keys (offline backup). If it's lost, make a
new one: users get one more keychain prompt after that update.
