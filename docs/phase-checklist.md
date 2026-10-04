# SVX phase checklist

Every task by phase. Finished tasks are ticked and ~~struck through~~. Open tasks are left plain.
For the summary table, see [roadmap.md](roadmap.md).

Last updated: 2026-10-03.

## Phase 1: Foundations ✅

- [x] ~~Threat model (`threat-model/THREAT_MODEL.md`)~~
- [x] ~~Security architecture (`docs/architecture.md`)~~
- [x] ~~Crypto profile (`spec/crypto-profile.md`)~~
- [x] ~~SVX 1.0 binary container spec (`spec/SVX-1.0.md`)~~
- [x] ~~Rust parser and writer (`svx-format`)~~
- [x] ~~ChaCha20-Poly1305 STREAM AEAD for payloads~~
- [x] ~~HPKE key envelopes~~
- [x] ~~Ed25519 signing~~
- [x] ~~Deterministic test vectors (`test-vectors/v1`), checked for reproducibility in CI~~
- [x] ~~Property tests~~
- [x] ~~Fuzz targets (`fuzz/`), run as a smoke test in CI~~
- [x] ~~Offline CLI: `svx keygen`, `pack`, `inspect`, `verify`~~

## Phase 2: Managed service ✅

- [x] ~~`svx-server` (axum + PostgreSQL)~~
- [x] ~~Org registry with DNS TXT domain verification~~
- [x] ~~Signed registry records~~
- [x] ~~`svx-oidc` ID-token validation:~~
  - [x] ~~issuer, audience, signature, expiry, freshness and nonce~~
  - [x] ~~JWKS cache~~
  - [x] ~~asymmetric algorithms only~~
- [x] ~~`svx-mock-idp` dev IdP (auth code + PKCE)~~
- [x] ~~Policy engine: users, groups, `acr` assurance, time window, maximum age~~
- [x] ~~Server-side expiry and revocation~~
- [x] ~~Key release:~~
  - [x] ~~re-sealing to an ephemeral key~~
  - [x] ~~nonce-bound tokens~~
  - [x] ~~single-use transaction IDs~~
- [x] ~~Split payload key (service share + key agent share)~~
- [x] ~~`svx-keyagent` recipient key agent~~
- [x] ~~Hash-chained, append-only audit log~~
- [x] ~~Admin API~~

## Phase 3: Client and CLI ✅

- [x] ~~`svx-client` library~~
- [x] ~~`svx init` pins the registry key~~
- [x] ~~Browser login: OIDC + PKCE with a loopback redirect (RFC 8252)~~
- [x] ~~`login`, `logout` and `whoami`, with a short-lived 0600 admin session~~
- [x] ~~Fail-closed `open`:~~
  - [x] ~~re-authenticates for every file with a key-bound nonce~~
  - [x] ~~writes to a private temp file and renames atomically~~
  - [x] ~~validates file names~~
- [x] ~~`status`, managed `pack --recipient`, `revoke`, `policy`, `organizations`, `audit`~~
- [x] ~~`.svx` file association files for Linux, Windows and macOS (`packaging/`)~~
- [ ] Device-code login flow (deferred)

## Phase 4: Demo and SDKs ✅

- [x] ~~`svx-demo run`: 14 self-checking scenarios between Acme Security and Example Corp:~~
  - [x] ~~Eve intercepts, inspects and forges a token, and fails~~
  - [x] ~~Alice is authorized; Bob is denied~~
  - [x] ~~tampered, expired and revoked files are refused~~
  - [x] ~~the audit chain verifies~~
- [x] ~~`svx-demo serve`: local stack with one command~~
- [x] ~~Shared `svx_client::Client` facade~~
- [x] ~~Python SDK (PyO3/maturin, abi3): typed errors, offline and end-to-end tests, demo example~~
- [x] ~~Node.js/TypeScript SDK (napi-rs): typed errors, offline and end-to-end tests, demo example~~
- [ ] Publish wheels and npm packages with signed releases (moved to Phase 6)

## Phase 5a: Desktop app ✅

- [x] ~~"Secure Verified Exchange" app for macOS, Windows and Linux (Tauri 2 over `svx-client`)~~
- [x] ~~`svx-app` command layer with error DTOs, preferences and the produced-paths allowlist~~
- [x] ~~Verified first-run setup (`svx_client::setup`)~~
- [x] ~~Protect and send files~~
- [x] ~~Protect and send folders: deterministic zip, hardened extraction on open~~
- [x] ~~Double-click opening with a live timeline~~
- [x] ~~A separate screen for each kind of refusal~~
- [x] ~~Basic admin: revoke, audit, policies~~
- [x] ~~`.svx` file association and single instance on all three platforms~~
- [x] ~~Unsigned installers built in CI (`desktop` job)~~
- [ ] Manual Mac walkthrough:
  - [ ] double-click a file to open it as alice and as bob
  - [ ] a second double-click goes to the running window

## Post-quantum hybrid suite SVX-1H (format 1.1) ✅

- [x] ~~X-Wing (X25519 + ML-KEM-768) envelopes and release sealing~~
- [x] ~~Composite Ed25519 + ML-DSA-65 signatures (both must verify)~~
- [x] ~~X-Wing one-time release keys (classical ones refused)~~
- [x] ~~Post-quantum TLS (X25519MLKEM768), pinned by `tls_pq` tests~~
- [x] ~~Format 1.1 (`key_envelopes_v2`)~~
- [x] ~~Protocol v2 with hybrid registry key kinds~~
- [x] ~~Migration 0002~~
- [x] ~~KATs and hybrid test vectors~~
- [x] ~~Older SVX-1 files still open (read-only)~~
- [x] ~~Merge PR #2~~
- [x] ~~Hybrid registry, grant and service-record signatures (protocol v3):~~
  - [x] ~~service grant and registry keys are Ed25519 + ML-DSA-65; classical ones refused~~
  - [x] ~~clients pin the registry key's 256-bit fingerprint~~
  - [x] ~~key agent `check` verifies the fingerprint and the grant key~~

## Maximum-strength suite SVX-2 (format 1.3, protocol v4) ✅

- [x] ~~MLKEM1024-P384 envelopes and one-time release keys (X25519 and X-Wing refused)~~
- [x] ~~Ed25519 + ML-DSA-87 + SLH-DSA-SHA2-256s file signatures (all three must verify)~~
- [x] ~~SHA-512 header hash and payload commitment, HKDF-SHA512 key schedule~~
- [x] ~~Service, registry and device keys are SVX-2 keys; full signatures on records, fast (Ed25519 + ML-DSA-87) on grants and account requests~~
- [x] ~~Backup password: Argon2id 256 MiB, t=4 (older backups still open)~~
- [x] ~~Migration 0005; ACVP KATs for ML-DSA-87 and SLH-DSA, HPKE vector for MLKEM1024-P384; `max-*` test vectors~~
- [x] ~~SVX-1H and SVX-1 files still open~~
- [ ] Move `slh-dsa` from `=0.2.0-rc.5` to the stable release when it ships

## Phase 5b: In-app administration and key agent packaging ✅

- [x] ~~Service admin API:~~
  - [x] ~~org overview and settings (`GET` and `PATCH /v1/admin/orgs/{org}`)~~
  - [x] ~~remove an admin, with the last admin protected~~
  - [x] ~~delete a policy~~
  - [x] ~~audit paging and event filter~~
- [x] ~~`svx_client::onboard`: registration → DNS TXT → IdP sign-in → first admin~~
- [x] ~~`svx_client::keystore`: signing keys in the OS keychain (`keyring`, feature `keychain`)~~
- [x] ~~`svx_client::keyadmin`:~~
  - [x] ~~create and register a signing key, rolling back on failure~~
  - [x] ~~export an encryption key for the key agent~~
  - [x] ~~activate it only once the agent holds it~~
  - [x] ~~retire or revoke keys~~
- [x] ~~Desktop onboarding wizard (resumable)~~
- [x] ~~Admin tabs: Organization, Keys, Policies, Administrators, Audit trail (CSV export), Revoke~~
- [x] ~~Keychain key used for sending; Settings can import a key file into the keychain~~
- [x] ~~Key agent:~~
  - [x] ~~`agent.toml` config~~
  - [x] ~~`serve`, `check` and `healthcheck`~~
  - [x] ~~`GET /v1/agent/keys`~~
  - [x] ~~refuses world-readable keys~~
- [x] ~~`deploy/keyagent`: distroless non-root Dockerfile, compose, hardened systemd unit, `install.sh`~~
- [x] ~~CI job `keyagent-package`: builds the image, smoke-tests it, uploads a Linux tarball~~
- [x] ~~Docs: `key-agent.md`, `api.md`, `desktop.md`, threat model~~
- [ ] Merge PR #3 (now targets `main`)
- [ ] Manual tests:
  - [ ] first real OS keychain use on the Mac
  - [ ] try onboarding and the admin tabs against `svx-demo serve`
- [ ] Edit policy access windows in the app
- [ ] Org directory search (today recipients are typed by ID)
- [ ] Enforce classification limits in policy

## Phase 5d: Personal accounts

- [x] ~~Format 1.2: several recipients (critical `recipients` field, one envelope per recipient, new vectors)~~
- [x] ~~Service:~~
  - [x] ~~sign-up with Google, keys bound by the token nonce, verified email required~~
  - [x] ~~requests signed with the device key (time window, single-use nonce)~~
  - [x] ~~email directory (signed record with the verified email, rate-limited)~~
  - [x] ~~file rules: approval, one-time, expiry, revoke per file or person~~
  - [x] ~~personal release with pending approval, one-time receipt and retry window~~
  - [x] ~~requests, approve/decline, history~~
  - [x] ~~approval emails (SMTP over TLS; no file names or links)~~
- [x] ~~`svx_client::personal`: sign-up, backup (Argon2id + ChaCha20-Poly1305), restore, reset, lookup, send, open with approval wait, history~~
- [x] ~~Desktop app: welcome (Google or email first), sidebar, Send by email, History, File page, Requests, waiting timeline, Settings (backup, reset, sign out)~~
- [x] ~~CLI: `account`, `send`, `requests`, `approve`, `decline`, `history`, `file`~~
- [x] ~~Demo checks 11–16; `svx-demo serve` prints personal accounts and emails~~
- [x] ~~Docs: `personal.md`, API, architecture, keys, desktop, threat model~~
- [ ] Google OAuth client ("Desktop app") for real sign-in
- [x] ~~Service-side sign-in relay for Apple~~ (removed in Phase 6: Apple sign-in needs a paid developer account)
- [ ] SMTP account for approval emails
- [ ] Manual test with two app windows against `svx-demo serve`

## Phase 5c: Website (deferred by the user)

The website never receives, encrypts or decrypts files.

- [ ] Product information pages
- [ ] Account sign-up
- [ ] App downloads
- [ ] Documentation sections

## Phase 6: Hardening and review (in progress, $0 budget)

- [x] ~~`cargo-deny` (advisories, licenses, sources) in CI~~
- [x] ~~Fuzz smoke run in CI~~
- [x] ~~Email + password accounts (emailed codes, zxcvbn rules, Argon2id, lock-out, reset and change); Apple sign-in removed~~
- [x] ~~Touch ID / password / Windows Hello before the keys are used (client-enforced, session and always actions)~~
- [x] ~~Auto-update: SVX-2-signed release manifest + Tauri signature, newer versions only, size and SHA-512 checked; `svx release`, `scripts/release.sh`, `svx-server --updates-dir`~~
- [x] ~~12 fuzz targets; long local runs (`scripts/fuzz-local.sh`, corpus kept between runs)~~
- [x] ~~`cargo-audit` in the local preflight (`scripts/preflight.sh`); CI keeps `cargo-deny`, which checks the same RustSec database against the real dependency graph~~
- [ ] Manual tests by the user: email account in the app; Touch ID prompts; self-update 0.1.0 → 0.1.1
- [ ] Production (free, by the user, when going live):
  - [ ] a Gmail address with an app password, for sending code and approval emails (steps in `docs/personal.md`, "Production setup")
  - [ ] a Google OAuth client ("Desktop app" client ID) for Continue with Google
- [x] Self-update from a symlinked path (found 2026-10-04: "StartingBinary found current_exe() that contains a symlink on a non-allowed platform: /tmp"). Cause: macOS `/tmp` is a symlink to `/private/tmp`, and Tauri refuses to update an app reached through a symlink (a security rule, kept on). Fixed: the app now says so clearly and what to do (`symlinked_location` in `apps/desktop/src-tauri/src/main.rs`, with a test), and `docs/releasing.md` tests from `/private/tmp`. 
  - [ ] Repeat the 0.1.0 → 0.1.1 test from `/private/tmp` by hand (app 0.1.0 is open from there; click Install)
- [x] Compatibility test suite (`docs/compatibility.md`): every committed vector of every suite verified and decrypted by the current reader, backups from the older Argon2id cost and a committed backup fixture, records of other protocol versions refused; platforms covered by the CI matrix
- [ ] Independent external security review
- [ ] Public beta
- Not planned (paid): signed and notarized macOS installers, signed Windows installers, hardware-bound keys (Secure Enclave, TPM, KMS), signed wheels/npm packages and a published key agent image (they need registries' signing or paid accounts; revisit later)

## Phase 7: View-only files (requested 2026-10-04; plan first, nothing built)

The sender can make a file **view-only**: the recipient sees it only inside the app, with no screenshots, recording, copy or save, until the sender allows sharing.

- [ ] File rule `view_only`, chosen when sending: on or off, plus "let them ask to share it".
  - Kept on the service with the other per-file rules.
  - Also signed into the file, so a modified app can't just ignore it.
- [ ] View-only files never become a normal file on disk.
  - After opening, the app keeps the content re-encrypted with a key held on this device. It isn't plaintext, it shows the app icon, and only the app opens it.
  - The content is decrypted into memory only while it's on screen.
- [ ] Built-in viewer for common types: PDF, images, plain text, and maybe Office files via PDF.
  - Other types can't be view-only. The app says so when sending.
- [ ] Block screen capture of the viewer window. Screenshots and recordings show a black window.
  - macOS: window sharing type "none".
  - Windows: `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`.
  - Linux: no OS support. Refuse view-only files there, or warn.
  - Tauri exposes this as `set_content_protected`.
- [ ] No copy, cut, select-all, drag-out, print, "save as" or "open with" in the viewer.
  - The clipboard is cleared when the viewer opens and closes.
- [ ] Visible watermark: the recipient's email, the time, and the file ID across the content.
  - It deters photos of the screen and identifies who leaked a copy.
- [ ] "Ask to share": the recipient requests permission and the sender approves or declines in Requests.
  - This reuses the approval flow.
  - Only after approval does the app export a normal file. Copy and screenshots then work for that file.
  - Every step goes in the audit trail.
- [ ] The sender can switch view-only and "let them ask" later from the file's page.
- [ ] Tamper resistance, as far as is possible for $0:
  - [ ] the security parts stay in Rust, compiled and optimized (no JavaScript to edit);
  - [ ] the app checks its own files at start and refuses view-only files if they changed;
  - [ ] the service gives the key for a view-only file only to a known app build;
  - [ ] the key for re-encrypted content is kept in the keychain;
  - [ ] symbols are stripped and the binary is obfuscated.
- [ ] Docs and threat model:
  - say clearly what view-only stops (casual copying, screenshots, screen recording) and what it can't stop (see below);
  - add tests.

**Limits to keep in mind (no software can remove these):**
- **Photos of the screen.** A phone can always photograph the screen; the watermark only discourages it and traces it.
- **A determined technical attacker.** Encrypting the app's own code doesn't stop someone with full control of their computer. The processor must run the decrypted code, so the key has to be inside the app, where an attacker can find it. The same goes for the decrypted file in memory while it's shown. Everything above raises the effort a lot, but doesn't make it impossible. Streaming services use DRM hardware in the graphics chip for this, which isn't available to apps like ours.
- **Unsigned app.** The strongest standard protection against a modified app is OS code signing, which needs the paid Apple and Windows certificates. Without them, the self-checks above are the next best thing.
- **What stays strong:** who can open a file (sender, service and keys) stays enforced by the service and cryptography, not by the app's honesty.

## Later (not in v1)

- [ ] Federation
- [ ] Hardware keys
- [ ] Device posture
- [ ] HSM integrations
- [ ] Controlled viewers
- [ ] Watermarking
- [ ] SIEM, DLP and EDR integration
- [ ] Multi-party approval
- [ ] Threshold keys
