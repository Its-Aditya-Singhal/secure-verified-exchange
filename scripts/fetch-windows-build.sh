#!/usr/bin/env bash
# Build the Windows installer on GitHub (.github/workflows/windows.yml, started
# by hand, never by a push) and download it:
#
#   scripts/fetch-windows-build.sh VERSION [REF]
#
# REF is the branch to build (default: the current one; it must be pushed).
# The installer lands in dist-release/VERSION/windows/. It is unsigned; pass it
# to scripts/release.sh --windows-package to sign it for the updater and add
# it to the release manifest.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=${1:?usage: $0 VERSION [REF]}
REF=${2:-$(git rev-parse --abbrev-ref HEAD)}
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "VERSION must be major.minor.patch" >&2; exit 2; }
git fetch -q origin "$REF"
[ "$(git rev-parse HEAD)" = "$(git rev-parse "origin/$REF")" ] \
  || { echo "push $REF first: GitHub builds what it has, not your local commits" >&2; exit 1; }

since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
gh workflow run windows.yml --ref "$REF" -f version="$VERSION"
echo "Started the Windows build of $VERSION from $REF; waiting for it to appear..."
run=""
for _ in $(seq 30); do
  sleep 5
  run=$(gh run list --workflow windows.yml --branch "$REF" --event workflow_dispatch \
    --json databaseId,createdAt --jq "map(select(.createdAt >= \"$since\")) | .[0].databaseId // empty")
  [ -n "$run" ] && break
done
[ -n "$run" ] || { echo "the run didn't start; see: gh run list --workflow windows.yml" >&2; exit 1; }
echo "Run $run (about 15-40 minutes)."
gh run watch "$run" --exit-status --interval 60 >/dev/null \
  || { echo "the build failed: gh run view $run --log-failed" >&2; exit 1; }

OUT=dist-release/$VERSION/windows
rm -rf "$OUT"
gh run download "$run" -n "svx-windows-$VERSION" -D "$OUT"
ls -la "$OUT"
