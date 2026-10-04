# The desktop app: Secure Verified Exchange

Secure Verified Exchange is the SVX app for macOS, Windows and Linux. Senders protect a file or folder for another organization. Recipients double-click the `.svx` file they receive; it opens in the app, they sign in with their company login, and the file is decrypted if their organization's policy allows it.

The app is a presentation layer. Every check — signature verification, recipient and expiry checks, the sign-in bound to a one-time key, key release, decryption and folder extraction — runs in the `svx-client` library, the same code the `svx` CLI and the SDKs use.

```
apps/desktop/            TypeScript UI (Vite, no framework) — displays results only
apps/desktop/src-tauri/  svx-desktop: Tauri 2 shell, one thin command per operation
crates/svx-app/          command layer over svx_client::Client (no UI; tested directly)
```

## Install

Builds are **unsigned**: signing and notarization need a paid Apple Developer ID and a Windows code-signing certificate, which this project doesn't buy (see "Updates" below for how updates are still protected). Each CI run uploads installers as workflow artifacts (`svx-desktop-macOS`, `-Windows`, `-Linux`).

| Platform | Installer | First launch |
|----------|-----------|--------------|
| macOS 11+ | `.dmg` (drag to Applications) | Right-click the app → **Open** once (Gatekeeper warns about unsigned apps) |
| Windows 10+ | `.msi` or NSIS `.exe` | SmartScreen may warn: **More info → Run anyway** |
| Linux | `.deb` (registers the `.svx` type) or `.AppImage` | AppImage: the `.svx` association needs `packaging/linux/install.sh`'s MIME file, or use the `.deb` |

The installers register `.svx` (MIME type `application/vnd.svx`, macOS UTI `org.svx.artifact`) so a double-click opens the app. If the app is already running, the file goes to the open window.

## First run

**Personal accounts (the default first screen):** **Continue with Google** or **Create account with email** (name, email, password with a strength meter, then an emailed 6-digit code). The app makes this device's keys in the keychain and suggests saving a backup. Then the sidebar shows Send, Open, History, Requests and Settings. See [personal.md](personal.md). The rest of this section is company setup, reached with **Company or test server setup**.


**A new organization** chooses **Register a new organization…**: enter the service URL and registry key fingerprint, your organization's name, ID and domain, and your company sign-in. The app shows a DNS TXT record to add to your domain; once it exists, **Verify and sign in** proves you control both the domain and the sign-in, and makes you the first administrator. The registration is remembered if you close the app while DNS updates. Then create this computer's signing key, and you can send.

**Joining an existing organization:** your administrator gives you four values: the service URL, the registry key fingerprint (64 hex characters that identify the service's post-quantum registry key), your organization ID and the sign-in client ID. Enter them and press **Verify**. The app checks the service record and your organization's record against that registry key before anything is saved; **Save** verifies again and writes the configuration.

**Import config file…** fills the form from an existing `config.toml` (for example one written by `svx init` or `svx-demo serve`). It is verified the same way.

The app and the `svx` CLI share the configuration and the admin session (`~/Library/Application Support/org.svx.svx/` on macOS, the platform config directory elsewhere, or `$SVX_CONFIG`).

## Protect & send

1. Choose or drop a **file or folder**. A folder is zipped and marked as a folder inside the encrypted manifest; the recipient gets the folder back.
2. Enter the recipient **organization ID** and press **Check**. The app shows the organization's name from its registry record, verified with the pinned key, and whether it can receive. Recent recipients are offered as shortcuts.
3. Choose the recipient's **policy**, an **expiry**, an optional **classification** and **note**. Files are signed with this computer's **keychain key** (created on the Admin page), or a `.sign.key` file you choose; only a reference is remembered.
4. Optionally **record the file with the service** (needs an administrator sign-in on the Admin page).

**Protect file** writes `<name>.svx` next to the original. New files always use the maximum-strength suite SVX-2; the result shows the protection level. Send it any way you like: email, chat, a file share.

## Open

A `.svx` file arrives by double-click, drag-and-drop or **Choose file…**:

1. **Before any sign-in** the file is verified against the registry. The app shows who sent it (signature verified), who it is for, when it expires, its policy and its protection level: **Maximum (SVX-2)** for files made with SVX 1.3 (ML-KEM-1024 + P-384, Ed25519 + ML-DSA-87 + SLH-DSA), **post-quantum** for SVX 1.1 and 1.2 files (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65), or **classical** for older files. A tampered file, a file for another organization or an expired file is refused here, and you are never asked to sign in.
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

## View-only files

A personal account can send a file **view only** (see [Personal accounts](personal.md#view-only-files-phase-7)): the Send screen has a **View only** switch, checked in Rust for the chosen file (type, size, LibreOffice for Office files), with **Let them ask to keep a copy** and one honest line about what it can't stop.

When a recipient opens one, the Open screen says it's view-only and **View securely** runs the usual timeline, then opens a **separate protected window** (title "(view only)"):

- The window is created hidden, protected from screenshots and recordings by the operating system (`content_protected`) at creation and again afterwards, and shown only once that worked. If protection can't be set, there is no viewer. Linux can't do it, so the Open screen disables the button there up front.
- The document lives in the Rust layer (`svx-viewer`). The window's page (`viewer.html`) asks for one page at a time and gets **raw pixels** with the watermark already burned in, drawn on a canvas. It never receives the file, its text or its bytes, so there is nothing to copy, save or print; its keyboard, context-menu and drag handlers are only friction. Each view command answers only the window its session belongs to.
- The toolbar has page and zoom controls (also `+` `-` `0`, arrows, Home, End, Esc to close), **Ask to keep a copy** (then "Waiting for the sender", "Save a copy" or the sender's refusal) and **Close**. Closing the window wipes the document; **Lock** (Settings) closes every viewer.
- Nothing is written to disk; opening it again asks the service again. History shows a "view only" badge; the file page has the sender's switches.

To check capture blocking on your Mac (this matters: newer macOS versions may change how window capture is handled), run the probe and try Cmd+Shift+3, Cmd+Shift+4 then Space, Cmd+Shift+5 and QuickTime on the red window; the green window is the control:

```sh
cargo run -p svx-desktop --example viewer_probe
```

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
- Sign-in uses the system browser with a loopback redirect (RFC 8252) and a nonce bound to a fresh one-time MLKEM1024-P384 key per open, exactly as in the CLI. Connections to the service and key agent use post-quantum TLS (X25519MLKEM768).
- Development mode (local stacks only) allows plain http and test users; the app shows a **dev** badge. Never use it with real data.

## Personal accounts

- **Send:** a file or folder, email chips (each checked in the signed directory: green when found, red otherwise), **Ask me before each open** and **One-time** (both on by default), optional expiry.
- **Open:** no sign-in step; when the sender must approve, the timeline shows "Waiting for … to approve" with **Stop waiting**.
- **History:** sent and received files, with people, dates and status. A sent file's page has the recipients' states, the two switches, an earlier expiry, revoke for one person or everyone, and **Send a new copy**.
- **Requests:** approve or decline, after ticking that you checked it's really them. The sidebar shows how many are waiting.
- **Settings:** account, key IDs, backup, reset keys (email accounts: with a code and the password), change password (email accounts), sign out, output folder, "Confirm it's you", updates.

File names of personal files are kept only in `history.json` next to the configuration.

## Confirm it's you (Touch ID)

Before the keys are used, the app asks for **Touch ID or the Mac's password** (Windows: **Windows Hello** face, fingerprint or PIN; Linux: not available). The `svx-client` library enforces it, not the UI:

| Asks | For |
|------|-----|
| once, then not again until the app has been idle for 15 minutes (5 min to 4 h in Settings) | sending, opening, changing a file's rules, revoking |
| every time | approving someone, saving a backup, changing the password, signing out, creating, importing, rotating or retiring organization keys |

Refusing stops the action before anything is signed, decrypted or written (error kind `not_confirmed`). Settings → **Confirm it's you** turns it off or changes the idle time; turning it off or making sessions longer asks first. **Lock now** ends the session. Development services never ask, so test windows don't keep prompting. The CLI asks with `svx --require-presence …`.

This is a software check: it stops someone using your unlocked computer, not malware running as you. Keys bound to the Secure Enclave or TPM would need a signed app (a paid Apple Developer ID); see threat model T26.

## Updates

The app checks for updates at start and once a day (Settings → **Updates** turns it off or checks now) and shows **Install and restart**. An update is installed only if:

1. the release manifest is signed with the **SVX-2 release key** whose fingerprint is built into the app (all three signatures: Ed25519, ML-DSA-87, SLH-DSA), and its version is newer than the running one (no downgrades);
2. the update server's offer names that same version, URL and package signature;
3. the package's **Tauri updater signature** (minisign, the public key in `tauri.conf.json`) verifies, including the version recorded in it;
4. the downloaded bytes have exactly the size and SHA-512 in the signed manifest.

Checks 1 and 4 are in `svx_client::update`; the Tauri updater does 3 and the install. Updates come from the SVX service (`svx-server --updates-dir`); see [releasing.md](releasing.md). Builds without a built-in release key don't check for updates. On macOS, after an update the keychain may ask once to let the new version use its keys (unsigned apps get a new code identity each build).

## Try it against the dev stack

```sh
cargo run -p svx-demo -- serve --state-dir /tmp/svx-stack     # keep running
cd apps/desktop && npm ci
SVX_CONFIG=/tmp/svx-app/acme/config.toml npm run tauri dev    # sender: Import /tmp/svx-stack/acme.toml
SVX_CONFIG=/tmp/svx-app/example/config.toml ../../target/debug/svx-desktop # recipient (needs the first window running): Import /tmp/svx-stack/example.toml
```

Using a separate `SVX_CONFIG` per organization keeps your real configuration untouched. A launch with `SVX_CONFIG` gets its own window; without it, a second launch hands its files to the running window. As Acme, protect a file for `example-corp` with policy `incident-response` and the signing key `/tmp/svx-stack/acme.sign.key`. As Example Corp, open it (or `/tmp/svx-stack/incident-report.svx`) as test user `alice` (approved) or `bob` (denied). Admin test users: `example-admin`, `acme-admin`.

To try double-click opening on macOS, build the bundle (`npm run tauri build -- --debug --bundles app`), copy `target/debug/bundle/macos/Secure Verified Exchange.app` to `/Applications`, open it once, and set it up with **Import config file…**. The installed app uses the default configuration location.

## Building

Prerequisites: Rust (stable; `svx-desktop` needs 1.92+, for the PDF renderer), Node 20.19+, and on Linux the WebKitGTK packages:

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

Icons come from the brand files (`brand/svg`, "The Clasp X"; see [`brand/README.md`](../brand/README.md)). After changing them, run `brand/build-icons.sh`. It regenerates the app icon (`.icns`, `.ico`, PNGs) and the `.svx` document icon: `svx-file.icns`, which `src-tauri/Info.plist` registers on macOS, plus the Linux MIME icons and the Windows `svx-file.ico`. The app draws its logo inline (`src/brand.ts`) and takes its colors from the tokens in `src/style.css`.

Workspace-wide `cargo build/test/clippy` works without Node: the shell's build script writes a placeholder page if the UI has not been built. The CI `test` job excludes `svx-desktop` (it needs the WebKitGTK libraries on Linux); the `desktop` job builds, lints, tests and packages it on all three platforms.

## Known limitations

- View-only files can't be shown on Linux, and capture blocking is untested on Windows; see the threat model, T29.
- Builds are unsigned (no paid certificates); updates are signed with our own keys instead. The Windows installer shows the app icon for `.svx` files (the document icon needs a custom installer template).
- Recipients are entered by organization ID; there is no directory search yet.
- Keychain keys are software keys protected by the OS keychain and the Touch ID / password check; hardware-backed keys (Secure Enclave, TPM) need a signed app.
- macOS builds are per architecture (Apple silicon from CI), not universal.
- No device-code sign-in; the browser must be on the same machine.
- A policy's access window (`not_before`/`not_after`) is kept but not editable in the app yet.
