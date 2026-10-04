# Compatibility

What must keep working when the code changes, and the tests that pin it. Nothing here needs a network, a database or a paid service.

| What | Pinned by | Rule |
|------|-----------|------|
| **`.svx` files** of every suite (SVX-1, SVX-1H, several recipients, SVX-2; formats 1.0–1.3) | `test-vectors/v1` (committed bytes) read by `crates/svx-testvectors/tests/committed.rs`; the Python and Node SDK tests read the same files | Each valid vector must verify and decrypt to the recorded plaintext. Each invalid one must be refused, at the recorded stage. The set can grow, never shrink. |
| **Vectors don't drift** | `cargo run -p svx-testvectors` then `git diff --exit-code test-vectors` (CI job `vectors-reproducible` and `scripts/preflight.sh`) | A change to the writers that alters an existing vector's bytes is a format change. It needs a new suite or version, not a regenerated file. |
| **Account backups** (`*.svxbackup`) | `crates/svx-crypto/tests/backup_compat.rs` and the committed `tests/data/backup-v1.svxbackup` | Older Argon2id costs (64 MiB, 3 passes) and the current ones (256 MiB, 4 passes) must open. The cost is stored in each file. |
| **Wire protocol** | `PROTOCOL_VERSION`; signed org, service and registry records and grants are refused when their version differs (tests in `svx-protocol`, `registry.rs` and `grant.rs`) | No downgrade: a valid signature on an old record format doesn't make it acceptable. A protocol bump needs migrations (see 0005) and a note in the docs. |
| **Old settings and keys** | `svx-client` config tests | Configs and device keys from before SVX-2 are refused with "run setup again", never half-used. |
| **Platforms** | CI runs the tests on Linux, macOS and Windows | Same vectors, same results on all three. |

## Changing a format on purpose

1. Add a new suite or format version; keep the old reader.
2. Add the new vectors (`crates/svx-testvectors`). Leave the existing files untouched.
3. Make `committed.rs` and the SDK tests cover them, then update `docs/phase-checklist.md`.

For backups, only the ignored `make_fixture` test regenerates the fixture. Do that for a deliberate format change, and add a second fixture instead of replacing the old one.
