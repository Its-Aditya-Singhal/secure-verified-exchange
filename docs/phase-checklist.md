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

## Phase 5c: Website (deferred by the user)

The website never receives, encrypts or decrypts files.

- [ ] Product information pages
- [ ] Account sign-up
- [ ] App downloads
- [ ] Documentation sections

## Phase 6: Hardening and review (planned)

- [x] ~~`cargo-deny` (advisories, licenses, sources) in CI~~
- [x] ~~Fuzz smoke run in CI~~
- [ ] Continuous fuzzing (long-running, corpus kept between runs)
- [ ] `cargo-audit` in CI (or confirm the `cargo-deny` advisories check is enough)
- [ ] Compatibility test suite across versions and platforms
- [ ] Signed and notarized macOS installers, universal binary
- [ ] Signed Windows installers
- [ ] Auto-update
- [ ] Signed releases of the Python wheels and npm packages
- [ ] Sign the key agent image and publish it to a registry
- [ ] Hardware-backed signing keys (Secure Enclave, TPM, KMS) instead of software keychain keys
- [ ] Independent external security review
- [ ] Public beta

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
