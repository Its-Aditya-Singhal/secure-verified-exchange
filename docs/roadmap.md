# SVX Roadmap

SVX is built in phases, following the development order in the product specification. The security architecture comes first and the website comes last.

| Phase | Scope | Status |
|-------|-------|--------|
| **1. Foundations** | Threat model; security architecture; crypto profile; SVX 1.0 binary spec; Rust parser and writer; STREAM AEAD, HPKE envelopes, Ed25519 signing; deterministic test vectors; property tests and fuzz targets; `svx keygen / pack / inspect / verify` | ✅ this release |
| **2. Managed service** | `svx-server` (axum + SQLite/Postgres). Org registry with DNS domain verification and signed records. OIDC token validation (issuer, audience, signature, expiry, nonce) against a bundled mock IdP. Policy engine (users, groups, roles, assurance, time, classification). Server-side expiry and revocation. Key-release protocol with single-use transaction IDs. Recipient key agent. Append-only audit log. Tenant isolation. | planned |
| **3. Client & CLI** | `svx login` (OIDC + PKCE / device flow), `whoami`, `open`, `status`, `revoke`, `policy`, `organizations`. Fail-closed open flow. Secure temporary files. OS file association for `.svx`. | planned |
| **4. Demo & SDKs** | Demo between Acme Security and Example Corp: Eve intercepts, Alice is authorized, Bob is denied, plus tampered, expired and revoked artifacts. Python SDK (PyO3/maturin), then TypeScript. | planned |
| **5. Admin portal & website** | Org admin UI (domains, IdP, policies, audit, revocation, key rotation). Public website and the 21 documentation sections. | planned |
| **6. Hardening & review** | Continuous fuzzing, `cargo-deny` and `cargo-audit` in CI, compatibility test suite, signed releases and updates, independent security review, then public beta. | planned |

Future features, not in v1: federation, hardware keys, device posture, HSM integrations, controlled viewers, watermarking, SIEM/DLP/EDR integration, multi-party approval, threshold keys, post-quantum suite.
