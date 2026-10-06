#!/usr/bin/env bash
# Build, sign and publish a release of the desktop app for the update server.
#
#   scripts/release.sh VERSION --update-url URL [--service-url URL --registry-fingerprint HEX]
#                      [--out DIR] [--notes TEXT] [--local] [--build-only]
#
# VERSION      major.minor.patch, e.g. 0.2.0
# --update-url the update server's base URL, built into the app and used for
#              download links, e.g. https://svx.example/v1/updates
# --service-url, --registry-fingerprint
#              the official service the app signs up with and the registry key
#              it pins (built in as SVX_OFFICIAL_SERVICE_URL and
#              SVX_OFFICIAL_REGISTRY_FINGERPRINT). Without them the app has no
#              built-in service (development builds)
# --out        where to put manifest.json and the package (svx-server
#              --updates-dir); default: dist-release/VERSION
# --local      a test build for a plain-http loopback update server
#              (svx-demo serve); never publish such a build
# --build-only build the app with the update source built in, don't sign a
#              release (for the version you install first when testing)
#
# Keys (never in the repository), in $SVX_RELEASE_KEYS (default ~/.svx-release):
#   release.sign.key / .pub   SVX-2 release key: signs manifest.json
#                             (svx keygen --kind sign --owner svx-release --out ~/.svx-release/release)
#   tauri.key, tauri.key.password   Tauri updater key (npx tauri signer generate);
#                             its public half is plugins.updater.pubkey in tauri.conf.json
set -euo pipefail

usage() { sed -n '2,20p' "$0"; exit 2; }
[ $# -ge 1 ] || usage
VERSION=$1; shift
URL="" OUT="" NOTES="" LOCAL=0 BUILD_ONLY=0 SERVICE_URL="" REGISTRY_FP=""
while [ $# -gt 0 ]; do
  case $1 in
    --update-url) URL=$2; shift 2 ;;
    --service-url) SERVICE_URL=$2; shift 2 ;;
    --registry-fingerprint) REGISTRY_FP=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --notes) NOTES=$2; shift 2 ;;
    --local) LOCAL=1; shift ;;
    --build-only) BUILD_ONLY=1; shift ;;
    *) usage ;;
  esac
done
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "VERSION must be major.minor.patch" >&2; exit 2; }
[ -n "$URL" ] || { echo "--update-url is required" >&2; exit 2; }
URL=${URL%/}
if [ -n "$SERVICE_URL" ] || [ -n "$REGISTRY_FP" ]; then
  [ -n "$SERVICE_URL" ] && [ -n "$REGISTRY_FP" ] || { echo "--service-url and --registry-fingerprint go together" >&2; exit 2; }
  [[ $REGISTRY_FP =~ ^[0-9a-f]{64}$ ]] || { echo "--registry-fingerprint must be 64 lowercase hex digits" >&2; exit 2; }
  if [ "$LOCAL" = 0 ] && [[ $SERVICE_URL != https://* ]]; then
    echo "release builds need an https service URL" >&2; exit 2
  fi
  export SVX_OFFICIAL_SERVICE_URL=${SERVICE_URL%/}
  export SVX_OFFICIAL_REGISTRY_FINGERPRINT=$REGISTRY_FP
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
KEYS=${SVX_RELEASE_KEYS:-$HOME/.svx-release}
OUT=${OUT:-$ROOT/dist-release/$VERSION}
for f in release.sign.key release.sign.pub tauri.key tauri.key.password; do
  [ -f "$KEYS/$f" ] || { echo "missing $KEYS/$f (see the top of this script)" >&2; exit 1; }
done
if [ "$LOCAL" = 0 ] && [[ $URL != https://* ]]; then
  echo "release builds need an https update URL (use --local for a loopback test server)" >&2
  exit 2
fi

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) PLATFORM=darwin-aarch64; BUNDLES=app; PKG_GLOB="macos/*.app.tar.gz" ;;
  Darwin-x86_64) PLATFORM=darwin-x86_64; BUNDLES=app; PKG_GLOB="macos/*.app.tar.gz" ;;
  Linux-x86_64) PLATFORM=linux-x86_64; BUNDLES=appimage; PKG_GLOB="appimage/*.AppImage" ;;
  *) echo "build Windows releases with the msi/nsis bundles on Windows" >&2; exit 1 ;;
esac

SVX="cargo run -q --release -p svx-cli --"
FINGERPRINT=$(cd "$ROOT" && $SVX release fingerprint "$KEYS/release.sign.pub")
echo "Release key: $FINGERPRINT"

# Built into the app: where updates come from and which key signs them.
export SVX_UPDATE_URL=$URL
export SVX_RELEASE_KEY=$FINGERPRINT
export TAURI_SIGNING_PRIVATE_KEY=$KEYS/tauri.key
TAURI_SIGNING_PRIVATE_KEY_PASSWORD=$(cat "$KEYS/tauri.key.password")
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD

OVERLAY=tauri.release.conf.json
[ "$LOCAL" = 1 ] && OVERLAY=tauri.localtest.conf.json
VERSION_CFG=$(mktemp -t svx-version).json
printf '{"version":"%s"}\n' "$VERSION" > "$VERSION_CFG"
trap 'rm -f "$VERSION_CFG"' EXIT

(cd "$ROOT/apps/desktop" && npm run tauri -- build --bundles "$BUNDLES" \
  --config "src-tauri/$OVERLAY" --config "$VERSION_CFG")

BUNDLE_DIR=$ROOT/target/release/bundle
# shellcheck disable=SC2086
PKG=$(ls -t $BUNDLE_DIR/$PKG_GLOB | head -1)
echo "Built $PKG"
if [ "$BUILD_ONLY" = 1 ]; then
  echo "Build only: install $(dirname "$PKG") and run it; it checks $URL for updates."
  exit 0
fi

(cd "$ROOT" && $SVX release sign --key "$KEYS/release.sign.key" --version "$VERSION" \
  --notes "$NOTES" --base-url "$URL/files" --platform "$PLATFORM=$PKG" --out "$OUT")
echo "Published $VERSION to $OUT"
