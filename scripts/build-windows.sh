#!/usr/bin/env bash
# Build the Windows installer on this Mac (Tauri's cross-compilation, NSIS only):
#
#   scripts/build-windows.sh VERSION [--service-url URL --registry-fingerprint HEX]
#
# Defaults build in the official service. The installer lands in
# dist-release/VERSION/windows/, unsigned; pass it to
# scripts/release.sh --windows-package to sign it for the updater and add it to
# the release manifest. (scripts/fetch-windows-build.sh builds it on GitHub
# instead, when the account has free build minutes.)
#
# One-time setup:
#   brew install nsis llvm lld
#   cargo install --locked cargo-xwin
#   rustup target add x86_64-pc-windows-msvc
# cargo-xwin downloads Microsoft's Windows SDK and CRT files on first use;
# XWIN_ACCEPT_LICENSE=1 below accepts Microsoft's license for them.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
VERSION=${1:?usage: $0 VERSION [--service-url URL --registry-fingerprint HEX]}; shift
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "VERSION must be major.minor.patch" >&2; exit 2; }
SERVICE_URL=https://api.getsvx.me:8443
REGISTRY_FP=7e37ca3363edce95a7f823e9df8454bb0fa9af93b531ccdf8bae98cbf56948a0
while [ $# -gt 0 ]; do
  case $1 in
    --service-url) SERVICE_URL=$2; shift 2 ;;
    --registry-fingerprint) REGISTRY_FP=$2; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
KEYS=${SVX_RELEASE_KEYS:-$HOME/.svx-release}
scripts/trim-target.sh

command -v cargo >/dev/null || export PATH="$(brew --prefix rustup)/bin:$PATH"
export PATH="$(brew --prefix llvm)/bin:$(brew --prefix lld)/bin:$HOME/.cargo/bin:$PATH"
for t in makensis cargo-xwin clang-cl lld-link; do
  command -v "$t" >/dev/null || { echo "missing $t (see the top of this script)" >&2; exit 1; }
done
# makensis crashes (std::bad_alloc) on Unicode installers without a UTF-8 locale.
export LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8
export XWIN_ACCEPT_LICENSE=1
export SVX_OFFICIAL_SERVICE_URL=${SERVICE_URL%/}
export SVX_OFFICIAL_REGISTRY_FINGERPRINT=$REGISTRY_FP
export SVX_UPDATE_URL=${SERVICE_URL%/}/v1/updates
SVX_RELEASE_KEY=$(cargo run -q --release -p svx-cli -- release fingerprint "$KEYS/release.sign.pub")
export SVX_RELEASE_KEY

VERSION_CFG=$(mktemp -t svx-version).json
trap 'rm -f "$VERSION_CFG"' EXIT
printf '{"version":"%s"}\n' "$VERSION" > "$VERSION_CFG"
BUNDLE=$ROOT/target/x86_64-pc-windows-msvc/release/bundle/nsis
rm -rf "$BUNDLE"
(cd apps/desktop && npx tauri build --runner cargo-xwin --target x86_64-pc-windows-msvc \
  --bundles nsis --config "$VERSION_CFG")

OUT=dist-release/$VERSION/windows
mkdir -p "$OUT"
cp "$BUNDLE"/*_"$VERSION"_x64-setup.exe "$OUT/"
ls -la "$OUT"
shasum -a 256 "$OUT"/*.exe
