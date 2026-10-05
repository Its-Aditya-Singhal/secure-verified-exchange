#!/usr/bin/env bash
# Everything CI checks, run locally (no GitHub Actions minutes):
#
#   scripts/preflight.sh [--quick]     --quick skips the SDKs and the demo
#
# Needs PostgreSQL with a role that can CREATE DATABASE (default
# postgres://svx:svx@127.0.0.1:5432/postgres; set SVX_TEST_DATABASE_URL),
# cargo-deny and cargo-audit (cargo install cargo-deny cargo-audit).
set -euo pipefail
cd "$(dirname "$0")/.."
command -v cargo >/dev/null || export PATH="$(brew --prefix rustup 2>/dev/null)/bin:$PATH"
export SVX_TEST_DATABASE_URL=${SVX_TEST_DATABASE_URL:-postgres://svx:svx@127.0.0.1:5432/postgres}
export SVX_REQUIRE_DB=1
QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

step() { printf '\n== %s\n' "$*"; }

step "format";  cargo fmt --all --check
step "clippy";  cargo clippy --workspace --all-targets -- -D warnings
step "tests";   cargo test --workspace
step "supply chain (cargo-deny)"; cargo deny check
# cargo-audit reads Cargo.lock, which also lists crates that are never
# built. RUSTSEC-2023-0071 (rsa, timing) is only reachable through
# sqlx-mysql: sqlx's lockfile entries name every driver, but only Postgres
# is compiled (`cargo tree -i rsa --target all` prints nothing).
# RUSTSEC-2024-0429 (glib 0.18, unsound VariantStrIter) comes with Tauri's
# GTK3 backend on Linux only; nothing here uses that iterator. Revisit when
# Tauri moves off GTK3 (same as RUSTSEC-2024-0370 in deny.toml).
step "advisories (cargo-audit)"; cargo audit --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2024-0429
step "no hand-written unsafe in the FFI crates"
if grep -rnw unsafe crates/svx-py/src crates/svx-node/src; then exit 1; fi
step "test vectors reproducible"
cargo run -q -p svx-testvectors && git diff --exit-code -- test-vectors
step "desktop UI"; (cd apps/desktop && npm ci --silent && npm run build)
if [ "$QUICK" = 0 ]; then
  step "demo"; cargo run -q -p svx-demo -- run --quiet
  step "Node SDK"; (cd sdk/node && npm ci --silent && npm run build && npm test)
  if [ -x sdk/python/.venv/bin/python ]; then
    step "Python SDK"
    (cd sdk/python && . .venv/bin/activate && maturin develop -q && pytest -q)
  else
    echo "(Python SDK skipped: create sdk/python/.venv with maturin and pytest)"
  fi
fi
printf '\nAll checks passed.\n'
