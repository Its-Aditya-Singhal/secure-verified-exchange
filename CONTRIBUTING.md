# Contributing to SVX

Thanks for your interest. SVX is a security protocol, so the bar for changes is deliberately high.

## Ground rules

1. **No custom cryptography.** Use established, reviewed crates. Never implement a primitive locally.
2. **Fail closed.** Every error path must leave no plaintext and no partial output behind.
3. **Bound before you allocate.** Every length read from input must be checked against `svx_format::limits` first.
4. **No `unsafe`.** The workspace forbids it.
5. **Secrets.** Secret types must zeroize on drop and redact `Debug`. Never log keys, shares, tokens or plaintext.
6. **Spec first.** Any change to bytes on the wire must update `spec/` and `test-vectors/` in the same PR. Regenerated vectors must be reviewed as a diff.
7. **Tests.** Every new rejection rule needs a negative test. Every new threat mitigation needs a test referenced from the threat model.

## Before opening a PR

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

If you touched the parser, also run each fuzz target for a few minutes (`cd fuzz && cargo +nightly fuzz run parse`).

## Licensing

Contributions are accepted under the Apache-2.0 license (see `LICENSE`, section 5).
