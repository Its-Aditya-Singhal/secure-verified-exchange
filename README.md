# SVX — Secure Verified Exchange

**SVX is an open, managed format for exchanging encrypted artifacts.** It is built for sending sensitive data between organizations: incident evidence, forensic artifacts, vulnerability reports and similar material.

A `.svx` file is a passive, signed and encrypted container. Its contents stay encrypted while stored and transferred. Decryption capability is released only after the recipient organization's identity provider authenticates the user and the managed service authorizes that user for that specific artifact.

> SVX does not make data impossible to steal. It makes an intercepted or unauthorized `.svx` file cryptographically useless for revealing its protected contents. It also provides strong identity, authorization, integrity, expiration, revocation and audit controls. See the [threat model](threat-model/THREAT_MODEL.md) for what SVX does and does not protect against.

## What is in this repository (Phases 1–4)

| Path | What |
|------|------|
| [`threat-model/THREAT_MODEL.md`](threat-model/THREAT_MODEL.md) | Goals, non-goals, actors, threats T1–T22 with their status |
| [`docs/architecture.md`](docs/architecture.md) | Components, split-key model, opening flow, org trust, key-release protocol, authorization, audit |
| [`docs/key-hierarchy.md`](docs/key-hierarchy.md) | Key types, storage, rotation, revocation, recovery |
| [`spec/SVX-1.0.md`](spec/SVX-1.0.md) | Normative binary container format |
| [`spec/crypto-profile.md`](spec/crypto-profile.md) | Normative cryptographic profile (suite SVX-1) |
| [`docs/roadmap.md`](docs/roadmap.md) | The phased build plan |
| [`docs/api.md`](docs/api.md) | Managed service and key agent HTTP API |
| [`docs/running-locally.md`](docs/running-locally.md) | Run the service, key agent and dev IdPs locally |
| [`docs/client.md`](docs/client.md) | The `svx` client: setup, open flow, admin commands, exit codes, limitations |
| [`docs/demo.md`](docs/demo.md) | The Acme Security → Example Corp demo and the one-command dev stack |
| [`docs/sdk-python.md`](docs/sdk-python.md), [`docs/sdk-node.md`](docs/sdk-node.md) | Python and Node.js/TypeScript SDKs |
| `crates/svx-format` | Strict, bounded, crypto-free parser and writer |
| `crates/svx-crypto` | STREAM ChaCha20-Poly1305, HPKE key envelopes, HKDF key schedule, Ed25519 |
| `crates/svx-core` | Pack, verify and open APIs; key files; trust store |
| `crates/svx-client` | Client library: config with pinned registry key, browser OIDC login, fail-closed open, managed pack, admin |
| `crates/svx-cli` | The `svx` command |
| `crates/svx-testkit` | Shared end-to-end harness (Postgres, dev IdPs, service, key agent) |
| `crates/svx-demo` | `svx-demo run` (scripted, self-checking demo) and `svx-demo serve` (local dev stack) |
| `crates/svx-py`, `sdk/python` | Python SDK (PyO3 + maturin) |
| `crates/svx-node`, `sdk/node` | Node.js/TypeScript SDK (napi-rs) |
| `examples/python`, `examples/node` | The demo story written against each SDK |
| `packaging/` | `.svx` file association for Linux, Windows and macOS |
| `crates/svx-protocol` | Managed Mode wire types, signed grants and registry records, release client, OIDC PKCE helpers |
| `crates/svx-oidc` | ID-token validation (discovery, JWKS cache, strict claims, nonce binding) |
| `crates/svx-server` | Managed service: org registry, admin API, policy engine, key release, revocation, audit (PostgreSQL) |
| `crates/svx-keyagent` | Recipient organization's key agent: releases the org share only with a service grant **and** the user's own-IdP token |
| `crates/svx-mock-idp` | **Development-only** OIDC provider with fictional users |
| `crates/svx-testvectors` | Deterministic generator and conformance checks for `test-vectors/v1` |
| `fuzz/` | cargo-fuzz targets: `parse`, `verify_open`, `manifest` |

## Design at a glance

- **No custom cryptography.** The format uses ChaCha20-Poly1305 (STREAM), HPKE (RFC 9180) with X25519, HKDF-SHA256, Ed25519 and SHA-256. There is one suite and no negotiation, so there is nothing to downgrade.
- **Split key.** The payload key is derived from two shares. One is sealed to the managed service and the other to the recipient organization's key agent. Neither party can decrypt alone, so compromising the server does not expose payloads.
- **Integrity before plaintext.** The header hash is the AAD for every chunk. A signed payload commitment covers every chunk. Chunk nonces bind position and finality. A single flipped bit anywhere causes rejection, and a test checks this for every byte of a file.
- **Private metadata.** File names, sizes, classification and description are stored in an encrypted manifest. Only opaque routing identifiers are public.
- **Streaming.** Memory use is constant, so multi-GB forensic images work.
- **No bypass.** The CLI has no local "unpack" path. Opening an artifact requires shares released by the managed service and the recipient's key agent after authentication and authorization.

## See it work

Requires Rust 1.88+ and Docker (or any PostgreSQL 14+ you can create databases on).

```sh
docker compose up -d
cargo run -p svx-demo -- run
```

This starts the managed service, Example Corp's key agent and two development
identity providers, then plays out the story. Carol at Acme Security sends
an incident report. Eve intercepts it, forges a token and fails. Alice is
authorized. Bob is denied. Tampered, expired and revoked copies are refused.
The audit trail records it all. Every outcome is checked. See
[docs/demo.md](docs/demo.md), and use `svx-demo serve` to keep the stack
running for the CLI or the SDKs.

## Quick start (offline format tools)

Requires Rust 1.88 or later.

```sh
cargo build --release
SVX=target/release/svx

# Test-only keys (production keys belong in a KMS/HSM)
$SVX keygen --kind sign --owner acme-security --out acme
$SVX keygen --kind kem  --owner example-corp  --out example
$SVX keygen --kind kem  --owner svx.example   --out service

echo "fictional demo data" > secret.txt
$SVX pack secret.txt \
  --sign-key acme.sign.key \
  --recipient-key example.kem.pub \
  --service-key service.kem.pub \
  --policy incident-response \
  --expires 2026-10-10T18:00:00Z \
  --classification TLP:AMBER

$SVX inspect secret.svx                         # public header, clearly marked UNVERIFIED
$SVX verify  secret.svx --trust acme.sign.pub   # exit 0 = authentic and intact
```

Change any byte and `svx verify` reports `REJECTED` and exits with status 1.

### Managed Mode

This assumes a service is already running. See [docs/running-locally.md](docs/running-locally.md) for a local stack.

```sh
# Recipient (Example Corp), once:
svx init --service https://svx.example --registry-key <fingerprint> --org example-corp --client-id svx

# Sender (Acme). Recipient and service keys come from the verified registry:
svx pack evidence.zip --sign-key acme.sign.key --recipient example-corp \
  --policy incident-response --expires 2026-10-10T18:00:00Z

# Recipient: sign in, get authorized, decrypt locally into ~/SVX:
svx open evidence.svx
```

### From code

```python
import svx
result = svx.Client().open("evidence.svx", output_dir="~/SVX")
```

```ts
import { Client } from "@svx/sdk";
const result = await Client.load().open("evidence.svx", { outputDir: "/home/me/SVX" });
```

Both SDKs wrap the same Rust client as the CLI. See [docs/sdk-python.md](docs/sdk-python.md) and [docs/sdk-node.md](docs/sdk-node.md).

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p svx-core --release -- --ignored        # 1 GiB streaming test
cargo run -p svx-testvectors -- test-vectors/v1     # regenerate vectors (must be byte-identical)
SVX_TEST_DATABASE_URL=postgres://svx:svx@127.0.0.1:5432/postgres cargo test --workspace  # Managed Mode end to end
cargo run -p svx-demo -- run                         # demo scenarios (exit 0 = all as expected)
(cd sdk/python && maturin develop && pytest)        # Python SDK
(cd sdk/node && npm ci && npm run build && npm test) # Node.js SDK
cd fuzz && cargo +nightly fuzz run parse            # seed corpus: ../test-vectors/v1/*.svx
```

## Status

Phase 4 of 6 (see the [roadmap](docs/roadmap.md)). The format, the cryptography, the managed service, the key agent and the key-release protocol work and are tested end to end. These scenarios are covered:

- Alice, who is authorized, decrypts.
- Bob, who is authenticated but not authorized, is denied.
- Eve is denied, whether she uses the wrong IdP or no token.
- Expired, revoked, tampered and replayed requests are rejected.
- A compromised service cannot obtain the recipient's share.

The `svx` client covers the end-user and admin workflow: `init`, `open`, `status`, `pack --recipient`, `login`, `revoke`, `policy` and `audit`. See [docs/client.md](docs/client.md). The Python and Node.js SDKs expose the same operations, and `svx-demo` runs the whole story as a self-checking script.

**This code has not had an independent security review. Do not use it to protect real data yet.**

## License

[Apache-2.0](LICENSE). This license was chosen for its explicit patent grant, which matters for a security protocol that enterprises adopt.

Security issues: see [SECURITY.md](SECURITY.md).
