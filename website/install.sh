#!/bin/sh
# Installs Secure Verified Exchange (SVX) on a Mac with an Apple chip.
#   curl -fsSL https://getsvx.me/install.sh | sh
#
# It downloads the disk image from getsvx.me, checks its SHA-256, copies the
# app to /Applications and unmounts the image. An app fetched this way carries
# no "downloaded from the internet" mark, so macOS doesn't show its
# unidentified-developer warning. The app is the same one the download button
# gives you. After installing, updates are verified by the app itself with the
# release key built into it.
set -eu

BASE=${SVX_BASE:-https://getsvx.me/downloads}
APPS=${SVX_APPS_DIR:-/Applications}
NAME="Secure Verified Exchange.app"

[ "$(uname -s)" = Darwin ] || { echo "This installer is for macOS." >&2; exit 1; }
[ "$(uname -m)" = arm64 ] || { echo "SVX needs a Mac with an Apple chip (M1 or newer)." >&2; exit 1; }

tmp=$(mktemp -d)
mnt="$tmp/mnt"
cleanup() { hdiutil detach -quiet "$mnt" 2>/dev/null || true; rm -rf "$tmp"; }
trap cleanup EXIT

echo "Downloading SVX..."
curl -fsSL "$BASE/SVX-beta-macOS.dmg" -o "$tmp/SVX.dmg"
expected=$(curl -fsSL "$BASE/SVX-beta-macOS.dmg.sha256" | tr -d '[:space:]')
actual=$(shasum -a 256 "$tmp/SVX.dmg" | cut -d' ' -f1)
if [ "$expected" != "$actual" ]; then
  echo "The download doesn't match its checksum. Nothing was installed." >&2
  exit 1
fi
echo "Checksum OK ($actual)"

mkdir -p "$mnt"
hdiutil attach -quiet -nobrowse -readonly -mountpoint "$mnt" "$tmp/SVX.dmg"
[ -d "$mnt/$NAME" ] || { echo "The disk image doesn't contain $NAME." >&2; exit 1; }

if [ -d "$APPS/$NAME" ]; then
  echo "Replacing the SVX already installed in $APPS."
  rm -rf "$APPS/$NAME"
fi
cp -R "$mnt/$NAME" "$APPS/"
# Not downloaded by a browser, so there is no quarantine mark; make sure.
xattr -dr com.apple.quarantine "$APPS/$NAME" 2>/dev/null || true

echo "Installed: $APPS/$NAME"
echo "Open it from Launchpad or Spotlight (search for \"Secure Verified Exchange\")."
