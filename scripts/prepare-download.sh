#!/usr/bin/env bash
# Put the macOS app on the website: build the disk image from the release
# build, write its SHA-256 next to it and into website/download.html.
#
#   scripts/prepare-download.sh
#
# Run it after scripts/release.sh (which builds target/release/bundle/macos/…).
# Then upload the website/ folder. install.sh and the download page both read
# these files, so they must be uploaded together.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
APP="$ROOT/target/release/bundle/macos/Secure Verified Exchange.app"
OUT="$ROOT/website/downloads"
[ -d "$APP" ] || { echo "build the app first: scripts/release.sh" >&2; exit 1; }
codesign --verify --deep --strict "$APP" || { echo "the app's signature doesn't verify" >&2; exit 1; }

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp -R "$APP" "$stage/"
ln -s /Applications "$stage/Applications"
mkdir -p "$OUT"
rm -f "$OUT/SVX-beta-macOS.dmg"
hdiutil create -volname "Secure Verified Exchange" -srcfolder "$stage" -format UDZO "$OUT/SVX-beta-macOS.dmg" >/dev/null
sum=$(shasum -a 256 "$OUT/SVX-beta-macOS.dmg" | cut -d' ' -f1)
printf '%s\n' "$sum" > "$OUT/SVX-beta-macOS.dmg.sha256"

python3 - "$ROOT/website/download.html" "$sum" <<'PY'
import re, sys
p, sum_ = sys.argv[1], sys.argv[2]
s = open(p).read()
s, n = re.subn(r'(<code id="sum-mac"[^>]*>)[^<]*(</code>)', r'\g<1>' + sum_ + r'\g<2>', s, count=1)
assert n == 1, "checksum element not found"
open(p, 'w').write(s)
PY
echo "website/downloads/SVX-beta-macOS.dmg  sha256 $sum"
