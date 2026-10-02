# SVX — Secure Verified Exchange

**SVX is an open, managed format for exchanging encrypted artifacts.** It is built for sending sensitive data between organizations: incident evidence, forensic artifacts, vulnerability reports and similar material.

A `.svx` file is a passive, signed and encrypted container. Its contents stay encrypted while stored and transferred. Decryption capability is released only after the recipient organization's identity provider authenticates the user and the managed service authorizes that user for that specific artifact.

> SVX does not make data impossible to steal. It makes an intercepted or unauthorized `.svx` file cryptographically useless for revealing its protected contents. It also provides strong identity, authorization, integrity, expiration, revocation and audit controls. See the [threat model](threat-model/THREAT_MODEL.md) for what SVX does and does not protect against.

## What is in this repository (Phase 1: Foundations)

| Path | What |
|------|------|
| [`threat-model/THREAT_MODEL.md`](threat-model/THREAT_MODEL.md) | Goals, non-goals, actors, threats T1–T22 with their status |
| [`docs/architecture.md`](docs/architecture.md) | Components, split-key model, opening flow, org trust, key-release protocol, authorization, audit |
| [`docs/key-hierarchy.md`](docs/key-hierarchy.md) | Key types, storage, rotation, revocation, recovery |
| [`spec/SVX-1.0.md`](spec/SVX-1.0.md) | Normative binary container format |
| [`spec/crypto-profile.md`](spec/crypto-profile.md) | Normative cryptographic profile (suite SVX-1) |
| [`docs/roadmap.md`](docs/roadmap.md) | The phased build plan |
| `crates/svx-format` | Strict, bounded, crypto-free parser and writer |
| `crates/svx-crypto` | STREAM ChaCha20-Poly1305, HPKE key envelopes, HKDF key schedule, Ed25519 |
| `crates/svx-core` | Pack, verify and open APIs; key files; trust store |
| `crates/svx-cli` | The `svx` command |
| `crates/svx-testvectors` | Deterministic generator and conformance checks for `test-vectors/v1` |
| `fuzz/` | cargo-fuzz targets: `parse`, `verify_open`, `manifest` |

## Design at a glance

- **No custom cryptography.** The format uses ChaCha20-Poly1305 (STREAM), HPKE (RFC 9180) with X25519, HKDF-SHA256, Ed25519 and SHA-256. There is one suite and no negotiation, so there is nothing to downgrade.
- **Split key.** The payload key is derived from two shares. One is sealed to the managed service and the other to the recipient organization's key agent. Neither party can decrypt alone, so compromising the server does not expose payloads.
- **Integrity before plaintext.** The header hash is the AAD for every chunk. A signed payload commitment covers every chunk. Chunk nonces bind position and finality. A single flipped bit anywhere causes rejection, and a test checks this for every byte of a file.
- **Private metadata.** File names, sizes, classification and description are stored in an encrypted manifest. Only opaque routing identifiers are public.
- **Streaming.** Memory use is constant, so multi-GB forensic images work.
- **No bypass.** The CLI has no local "unpack" path. Opening an artifact requires released shares (Phase 2/3).

## Quick start

Requires Rust 1.85 or later.

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

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p svx-core --release -- --ignored        # 1 GiB streaming test
cargo run -p svx-testvectors -- test-vectors/v1     # regenerate vectors (must be byte-identical)
cd fuzz && cargo +nightly fuzz run parse            # seed corpus: ../test-vectors/v1/*.svx
```

## Status

Phase 1 of 6 (see the [roadmap](docs/roadmap.md)). The format and cryptographic layer work and are tested. The managed service, client login and key release are not built yet.

**This code has not had an independent security review. Do not use it to protect real data yet.**

## License

[Apache-2.0](LICENSE). This license was chosen for its explicit patent grant, which matters for a security protocol that enterprises adopt.

Security issues: see [SECURITY.md](SECURITY.md).
