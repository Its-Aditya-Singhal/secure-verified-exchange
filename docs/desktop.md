# The desktop app: Secure Verified Exchange

Secure Verified Exchange is the SVX app for macOS, Windows and Linux. Senders protect a file or folder for another organization. Recipients double-click the `.svx` file they receive; it opens in the app, they sign in with their company login, and the file is decrypted if their organization's policy allows it.

The app is a presentation layer. Every check — signature verification, recipient and expiry checks, the sign-in bound to a one-time key, key release, decryption and folder extraction — runs in the `svx-client` library, the same code the `svx` CLI and the SDKs use.

```
apps/desktop/            TypeScript UI (Vite, no framework) — displays results only
apps/desktop/src-tauri/  svx-desktop: Tauri 2 shell, one thin command per operation
crates/svx-app/          command layer over svx_client::Client (no UI; tested directly)
```

## Install

Phase 5 builds are **unsigned**. Each CI run uploads installers as workflow artifacts (`svx-desktop-macOS`, `-Windows`, `-Linux`).

| Platform | Installer | First launch |
|----------|-----------|--------------|
| macOS 11+ | `.dmg` (drag to Applications) | Right-click the app → **Open** once (Gatekeeper; signing and notarization come in Phase 6) |
| Windows 10+ | `.msi` or NSIS `.exe` | SmartScreen may warn: **More info → Run anyway** |
| Linux | `.deb` (registers the `.svx` type) or `.AppImage` | AppImage: the `.svx` association needs `packaging/linux/install.sh`'s MIME file, or use the `.deb` |

The installers register `.svx` (MIME type `application/vnd.svx`, macOS UTI `org.svx.artifact`) so a double-click opens the app. If the app is already running, the file goes to the open window.

## First run

**A new organization** chooses **Register a new organization…**: enter the service URL and registry key, your organization's name, ID and domain, and your company sign-in. The app shows a DNS TXT record to add to your domain; once it exists, **Verify and sign in** proves you control both the domain and the sign-in, and makes you the first administrator. The registration is remembered if you close the app while DNS updates. Then create this computer's signing key, and you can send.

**Joining an existing organization:** your administrator gives you four values: the service URL, the registry key (the service's public key, 64 hex characters), your organization ID and the sign-in client ID. Enter them and press **Verify**. The app checks the service record and your organization's record against the registry key before anything is saved; **Save** verifies again and writes the configuration.

**Import config file…** fills the form from an existing `config.toml` (for example one written by `svx init` or `svx-demo serve`). It is verified the same way.

The app and the `svx` CLI share the configuration and the admin session (`~/Library/Application Support/org.svx.svx/` on macOS, the platform config directory elsewhere, or `$SVX_CONFIG`).

## Protect & send

1. Choose or drop a **file or folder**. A folder is zipped and marked as a folder inside the encrypted manifest; the recipient gets the folder back.
2. Enter the recipient **organization ID** and press **Check**. The app shows the organization's name from its registry record, verified with the pinned key, and whether it can receive. Recent recipients are offered as shortcuts.
3. Choose the recipient's **policy**, an **expiry**, an optional **classification** and **note**. Files are signed with this computer's **keychain key** (created on the Admin page), or a `.sign.key` file you choose; only a reference is remembered.
4. Optionally **record the file with the service** (needs an administrator sign-in on the Admin page).

**Protect file** writes `<name>.svx` next to the original. New files are always post-quantum hybrid; the result shows the protection level. Send it any way you like: email, chat, a file share.

## Open

A `.svx` file arrives by double-click, drag-and-drop or **Choose file…**:

1. **Before any sign-in** the file is verified against the registry. The app shows who sent it (signature verified), who it is for, when it expires, its policy and its protection level: **post-quantum** for every file made with SVX 1.1 (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65), or **classical** for older files. A tampered file, a file for another organization or an expired file is refused here, and you are never asked to sign in.
2. **Open securely** starts the flow, shown as a live timeline: checking the file → signature verified → connecting → signing you in (your browser opens your company sign-in) → checking you're allowed → access approved → decrypting on this device.
3. The result:

| Outcome | What you see |
|---------|--------------|
| Approved | The file or folder name, sender, classification, where it was saved; **Open** for document types, **Show in Finder/Explorer** for everything |
| Not allowed by policy | "You're not allowed to open this file". Nothing was decrypted. |
| Revoked or expired at the service | "Access to this file has ended" |
| Tampered / unknown sender | "This file can't be trusted" |
| Not for your organization | "This file wasn't sent to your organization" |
| Service or key agent unreachable | "Can't reach the SVX service", with **Try again** |
| Sign-in cancelled or failed | "Sign-in didn't complete", with **Try again** |
| Name already taken | "A file with this name is already there" — files are never overwritten; **Choose another folder…** |

Opened files go to `~/SVX` by default (Settings → **Change folder…**), owner-only, written to a private temporary file and moved into place only after the whole payload authenticated.

**Folders** are extracted by `svx-client` with strict checks: entry names must be plain relative paths (no `..`, absolute paths, drive letters, backslashes or device names), only regular files and folders (no links), limits on entry count, total size and compression ratio, private staging, and an existing folder is never replaced.

**Open** is offered only for document types that do not run code (PDF, text, images, Office documents without macros, media, ZIP). Executables, scripts, installers, app bundles, shortcuts and HTML are only shown in their folder.

## Admin

All administration happens here (there is no web portal). Sign in with your company login; the session is short-lived and can never open files. Every change is authorized by the SVX service and recorded in the audit trail.

- **Organization:** details, display name, the key agent URL, and whether the key agent is reachable.
- **Keys:** every registered key with its status, which one this computer signs with, and which encryption keys the key agent holds.
  - *Signing keys:* **Create a new signing key** makes a post-quantum key in this computer's keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service) and registers it. It never leaves the device and is never shown. **Register another sender's key…** adds a colleague's `.sign.pub`.
  - *Encryption key:* **Create a new encryption key…** writes it, owner-only, to a folder you choose for the key agent. After installing it on the agent, **Activate** checks that the agent holds it before switching new files to it, then retires the old key. See [key-agent.md](key-agent.md).
  - **Retire** (no new files; existing ones still work) or **Revoke** (compromised; refused from now on) any key.
- **Policies:** create, edit and delete who may open files sent to you: allowed groups and users, required sign-in strength, maximum file age.
- **Administrators:** add and remove (the last administrator can't be removed).
- **Audit trail:** filter by event, load older records, **Export CSV…** (spreadsheet-safe), with the hash-chain check.
- **Revoke a file** by artifact ID or by choosing the `.svx`. Revocation stops all future access; it cannot recall copies already opened.

**Settings → Signing key → Move a key file into the keychain…** imports an existing `.sign.key`; delete the file afterwards.

## Security notes

- The web view loads only the bundled UI under a strict Content Security Policy (no remote content, no inline script). All values are rendered as text, never as HTML.
- The UI has no file-system or shell permissions of its own. File pickers, **Show in Finder** and **Open** are app commands, and the last two only accept paths the app itself produced in this session. Commands that write files (key export, audit export) open their own save dialog; the UI never supplies a path to write to.
- Signing keys created in the app live in the OS keychain and are used inside the Rust layer; they never reach the UI.
- Sign-in uses the system browser with a loopback redirect (RFC 8252) and a nonce bound to a fresh one-time X-Wing key per open, exactly as in the CLI. Connections to the service and key agent use post-quantum TLS (X25519MLKEM768).
- Development mode (local stacks only) allows plain http and test users; the app shows a **dev** badge. Never use it with real data.

## Try it against the dev stack

```sh
cargo run -p svx-demo -- serve --state-dir /tmp/svx-stack     # keep running
cd apps/desktop && npm ci
SVX_CONFIG=/tmp/svx-app/acme/config.toml npm run tauri dev    # sender: Import /tmp/svx-stack/acme.toml
SVX_CONFIG=/tmp/svx-app/example/config.toml npm run tauri dev # recipient: Import /tmp/svx-stack/example.toml
```

Using a separate `SVX_CONFIG` per organization keeps your real configuration untouched. As Acme, protect a file for `example-corp` with policy `incident-response` and the signing key `/tmp/svx-stack/acme.sign.key`. As Example Corp, open it (or `/tmp/svx-stack/incident-report.svx`) as test user `alice` (approved) or `bob` (denied). Admin test users: `example-admin`, `acme-admin`.

To try double-click opening on macOS, build the bundle (`npm run tauri build -- --debug --bundles app`), copy `target/debug/bundle/macos/Secure Verified Exchange.app` to `/Applications`, open it once, and set it up with **Import config file…**. The installed app uses the default configuration location.

## Building

Prerequisites: Rust (stable; `svx-desktop` needs 1.90+), Node 20.19+, and on Linux the WebKitGTK packages:

```sh
sudo apt-get install -y libwebkit2gtk-4.1-dev build-essential file libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev patchelf
```

```sh
cd apps/desktop
npm ci
npm run build                 # type-check and build the UI
npm run tauri dev             # run with hot reload
npm run tauri build           # installers in target/release/bundle/
cargo test -p svx-app -p svx-desktop
```

Workspace-wide `cargo build/test/clippy` works without Node: the shell's build script writes a placeholder page if the UI has not been built. The CI `test` job excludes `svx-desktop` (it needs the WebKitGTK libraries on Linux); the `desktop` job builds, lints, tests and packages it on all three platforms.

## Known limitations

- Builds are unsigned; no auto-update (Phase 6).
- Recipients are entered by organization ID; there is no directory search yet.
- Keychain keys are software keys protected by the OS keychain; hardware-backed keys (Secure Enclave, TPM) come later.
- macOS builds are per architecture (Apple silicon from CI), not universal.
- No device-code sign-in; the browser must be on the same machine.
- A policy's access window (`not_before`/`not_after`) is kept but not editable in the app yet.
