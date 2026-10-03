# SVX Roadmap

SVX is built in phases, following the development order in the product specification. The security architecture comes first and the website comes last.

| Phase | Scope | Status |
|-------|-------|--------|
| **1. Foundations** | Threat model; security architecture; crypto profile; SVX 1.0 binary spec; Rust parser and writer; STREAM AEAD, HPKE envelopes, Ed25519 signing; deterministic test vectors; property tests and fuzz targets; `svx keygen / pack / inspect / verify` | ✅ done |
| **2. Managed service** | `svx-server` (axum + PostgreSQL). Org registry with DNS TXT domain verification and signed registry records. `svx-oidc` token validation (issuer, audience, signature, expiry, freshness, nonce; JWKS cache; asymmetric algorithms only). `svx-mock-idp` dev IdP (auth code + PKCE). Policy engine: users, groups, `acr` assurance, time window, max age. Server-side expiry and revocation. Key release with ephemeral-key re-sealing, nonce-bound tokens and single-use transaction IDs. `svx-keyagent` recipient key agent. Hash-chained, append-only audit log. Admin API. | ✅ done |
| **3. Client & CLI** | `svx-client` library and the `svx` CLI. `init` pins the registry key. Browser login via OIDC + PKCE with a loopback redirect (RFC 8252). `login/logout/whoami` with a short-lived 0600 admin session. Fail-closed `open` that re-authenticates per artifact with a key-bound nonce, uses private temp files, renames atomically and validates file names. Also `status`, managed `pack --recipient`, `revoke`, `policy`, `organizations`, `audit`. Linux, Windows and macOS file-association files. Device-code flow deferred. | ✅ done |
| **4. Demo & SDKs** | Demo between Acme Security and Example Corp: Eve intercepts, Alice is authorized, Bob is denied, plus tampered, expired and revoked artifacts. Python SDK (PyO3/maturin), then TypeScript. | planned |
| **5. Admin portal & website** | Org admin UI (domains, IdP, policies, audit, revocation, key rotation). Public website and the 21 documentation sections. | planned |
| **6. Hardening & review** | Continuous fuzzing, `cargo-deny` and `cargo-audit` in CI, compatibility test suite, signed releases and updates, independent security review, then public beta. | planned |

Future features, not in v1: federation, hardware keys, device posture, HSM integrations, controlled viewers, watermarking, SIEM/DLP/EDR integration, multi-party approval, threshold keys, post-quantum suite.
