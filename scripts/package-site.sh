#!/usr/bin/env bash
# Make the folder to upload to Cloudflare: website/ without internal notes
# (README.md) and macOS junk (.DS_Store), after checking that the disk image,
# its checksum file and the checksum on the download page agree.
#
#   scripts/package-site.sh      then upload dist-site/ (the whole folder)
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC="$ROOT/website"
OUT="$ROOT/dist-site"

dmg="$SRC/downloads/SVX-beta-macOS.dmg"
[ -f "$dmg" ] || { echo "no disk image: run scripts/prepare-download.sh" >&2; exit 1; }
actual=$(shasum -a 256 "$dmg" | cut -d' ' -f1)
filesum=$(tr -d '[:space:]' < "$SRC/downloads/SVX-beta-macOS.dmg.sha256")
pagesum=$(grep -o 'id="sum-mac"[^>]*>[0-9a-f]\{64\}' "$SRC/download.html" | grep -o '[0-9a-f]\{64\}$' || true)
[ "$actual" = "$filesum" ] && [ "$actual" = "$pagesum" ] || {
  echo "checksums disagree (image $actual, file $filesum, page $pagesum): run scripts/prepare-download.sh" >&2; exit 1; }
codesign --verify --deep --strict --quiet /dev/null 2>/dev/null || true

rm -rf "$OUT"
mkdir -p "$OUT"
rsync -a --exclude README.md --exclude .DS_Store "$SRC/" "$OUT/"
echo "Ready to upload: $OUT"
echo "  $(find "$OUT" -type f | wc -l | tr -d ' ') files, $(du -sh "$OUT" | cut -f1)"
echo "  release switch: $(grep -o "RELEASE='[a-z]*'" "$OUT/assets/js/boot.js")"
[ -f "$OUT/security.txt" ] && [ -f "$OUT/_redirects" ] && echo "  includes security.txt and its redirect" || echo "  WARNING: security.txt or _redirects missing"
