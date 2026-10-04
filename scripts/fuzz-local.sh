#!/usr/bin/env bash
# Long-running fuzzing on this computer: every target in turn, with a corpus
# kept between runs (fuzz/corpus, not committed) and crashes saved under
# fuzz/artifacts. Meant to run overnight.
#
#   scripts/fuzz-local.sh [HOURS] [TARGET...]     default: 8 hours, all targets
#
# Needs: rustup toolchain install nightly; cargo install cargo-fuzz.
# A crash: reproduce with `cargo +nightly fuzz run TARGET fuzz/artifacts/TARGET/crash-…`,
# fix it, and add the input as a regression test.
set -euo pipefail
cd "$(dirname "$0")/../fuzz"

HOURS=${1:-8}
shift || true
TARGETS=("$@")
if [ ${#TARGETS[@]} -eq 0 ]; then
  TARGETS=(parse verify_open manifest backup_open grant_verify registry_record
           request_auth wire_json folder_extract keyfile_parse password_check update_manifest
           viewer_pdf viewer_image viewer_view_zip)
fi
# Run the targets in rounds of 30 minutes each until the time is up.
ROUND=1800
END=$(( $(date +%s) + HOURS * 3600 ))

seed() {
  local t=$1 dir=corpus/$1
  mkdir -p "$dir"
  case $t in
    parse|verify_open|manifest) cp ../test-vectors/v1/*.svx "$dir/" 2>/dev/null || true ;;
    registry_record|wire_json|update_manifest|grant_verify|keyfile_parse)
      cp ../test-vectors/v1/*.json "$dir/" 2>/dev/null || true ;;
    password_check) printf 'correct horse battery staple\nalice@example.test\nAlice' > "$dir/seed1"
                    printf 'Password123!\nbob@example.test' > "$dir/seed2" ;;
  esac
}

for t in "${TARGETS[@]}"; do seed "$t"; done
cargo +nightly fuzz build -O "${TARGETS[@]/#/}" >/dev/null 2>&1 || cargo +nightly fuzz build -O

while [ "$(date +%s)" -lt "$END" ]; do
  for t in "${TARGETS[@]}"; do
    left=$(( END - $(date +%s) ))
    [ "$left" -gt 0 ] || break
    secs=$(( left < ROUND ? left : ROUND ))
    echo "== $t for ${secs}s ($(date '+%H:%M'))"
    # -timeout: an input taking over 10 s counts as a bug (a hang).
    cargo +nightly fuzz run -O "$t" "corpus/$t" -- \
      -max_total_time="$secs" -rss_limit_mb=2048 -timeout=10 -print_final_stats=1 \
      2>&1 | grep -E "^(#|==|stat::number_of_executed_units|SUMMARY|INFO: a corpus)" | tail -3
    # Keep the corpus small and useful.
    cargo +nightly fuzz cmin -O "$t" "corpus/$t" >/dev/null 2>&1 || true
  done
done
if ls artifacts/*/crash-* artifacts/*/timeout-* artifacts/*/oom-* >/dev/null 2>&1; then
  echo "Findings in fuzz/artifacts:"; ls artifacts/*/
  exit 1
fi
echo "No crashes."
