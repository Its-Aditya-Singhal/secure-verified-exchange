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

# Stamp the site's own scripts and stylesheet with a fingerprint of their
# contents (?v=…), so a browser that kept an older copy fetches the new one
# when it changes. hero3d.js first: site.js imports it.
stamp() { shasum -a 256 "$OUT/$1" | cut -c1-10; }
v=$(stamp assets/js/hero3d.js)
sed -i '' "s|'./hero3d.js'|'./hero3d.js?v=$v'|" "$OUT/assets/js/site.js"
for f in assets/css/site.css assets/js/boot.js assets/js/site.js; do
  v=$(stamp "$f")
  sed -i '' "s|\"$f\"|\"$f?v=$v\"|g" "$OUT"/*.html
done
grep -q 'site.css?v=' "$OUT/index.html" || { echo "stamping the stylesheet failed" >&2; exit 1; }
echo "Ready to upload: $OUT"
echo "  $(find "$OUT" -type f | wc -l | tr -d ' ') files, $(du -sh "$OUT" | cut -f1)"
echo "  release switch: $(grep -o "RELEASE='[a-z]*'" "$OUT/assets/js/boot.js")"
[ -f "$OUT/security.txt" ] && [ -f "$OUT/_redirects" ] && echo "  includes security.txt and its redirect" || echo "  WARNING: security.txt or _redirects missing"
