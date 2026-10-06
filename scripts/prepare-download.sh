#!/usr/bin/env bash
# Put the apps on the website: build the macOS disk image from the release
# build and copy the Windows installer, write each SHA-256 next to the file
# and into website/download.html.
#
#   scripts/prepare-download.sh [WINDOWS_SETUP_EXE]
#
# Run it after scripts/release.sh (which builds target/release/bundle/macos/…);
# the Windows installer is the one passed to release.sh --windows-package.
# Then upload the website/ folder. install.sh and the download page both read
# these files, so they must be uploaded together.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WIN=${1:-}
[ -z "$WIN" ] || [[ $WIN == *-setup.exe && -f $WIN ]] || { echo "$WIN isn't a Windows *-setup.exe" >&2; exit 2; }
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

put_sum() {
  python3 - "$ROOT/website/download.html" "$1" "$2" <<'PY'
import re, sys
p, el, sum_ = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
s, n = re.subn(r'(<code id="' + el + r'"[^>]*>)[^<]*(</code>)', r'\g<1>' + sum_ + r'\g<2>', s, count=1)
assert n == 1, el + " checksum element not found"
open(p, 'w').write(s)
PY
}
put_sum sum-mac "$sum"
echo "website/downloads/SVX-beta-macOS.dmg  sha256 $sum"

if [ -n "$WIN" ]; then
  cp "$WIN" "$OUT/SVX-beta-Windows.exe"
  wsum=$(shasum -a 256 "$OUT/SVX-beta-Windows.exe" | cut -d' ' -f1)
  printf '%s\n' "$wsum" > "$OUT/SVX-beta-Windows.exe.sha256"
  put_sum sum-win "$wsum"
  echo "website/downloads/SVX-beta-Windows.exe  sha256 $wsum"
fi
