#!/usr/bin/env bash
# Regenerate every icon from the brand SVGs (brand/svg). Needs Node (the
# Tauri CLI in apps/desktop rasterizes the SVGs), Python 3 with Pillow (for
# the .ico) and, on macOS, nothing else. Run from anywhere:
#
#   brand/build-icons.sh
#
# Writes:
#   apps/desktop/src-tauri/icons/   app icon (png, icns, ico) and the .svx document icon (svx-file.icns)
#   packaging/linux/icons/          .svx document icon for the freedesktop MIME type
#   packaging/windows/svx-file.ico  .svx document icon for the registry association
#   brand/web/                      favicon and touch icon for the website
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
svg="$root/brand/svg"
icons="$root/apps/desktop/src-tauri/icons"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

tauri_icon() { (cd "$root/apps/desktop" && npx --no-install tauri icon "$@" >/dev/null 2>&1); }

# App icon: macOS .icns and the PNGs Tauri bundles (Linux uses the PNGs).
tauri_icon "$svg/app-icon.svg" -o "$tmp/app"
cp "$tmp/app/32x32.png" "$tmp/app/128x128.png" "$tmp/app/128x128@2x.png" \
   "$tmp/app/icon.png" "$tmp/app/icon.icns" "$icons/"

# Windows .ico: the full-bleed favicon tile for 16-48 px (stays legible),
# the padded app icon for 256 px.
tauri_icon "$svg/favicon.svg" -o "$tmp/small" -p 16,24,32,48
tauri_icon "$svg/app-icon.svg" -o "$tmp/large" -p 256
python3 - "$tmp" "$icons/icon.ico" <<'PY'
import sys
from PIL import Image
tmp, out = sys.argv[1], sys.argv[2]
imgs = [Image.open(f"{tmp}/small/{s}x{s}.png").convert("RGBA") for s in (16, 24, 32, 48)]
imgs.append(Image.open(f"{tmp}/large/256x256.png").convert("RGBA"))
imgs[-1].save(out, format="ICO", sizes=[(i.width, i.height) for i in imgs], append_images=imgs[:-1])
PY

# .svx document icon: the 80x100 page centred on a square canvas.
sed -E 's#<metadata>.*</metadata>##; s#viewBox="0 0 80 100" width="80" height="100"#viewBox="-10 0 100 100" width="100" height="100"#' \
  "$svg/file-icon.svg" > "$tmp/file-square.svg"
tauri_icon "$tmp/file-square.svg" -o "$tmp/doc"
cp "$tmp/doc/icon.icns" "$icons/svx-file.icns"
mkdir -p "$root/packaging/linux/icons"
tauri_icon "$tmp/file-square.svg" -o "$tmp/docpng" -p 16,32,48,64,128,256,512
for s in 16 32 48 64 128 256 512; do
  cp "$tmp/docpng/${s}x${s}.png" "$root/packaging/linux/icons/application-vnd.svx-$s.png"
done
cp "$tmp/file-square.svg" "$root/packaging/linux/icons/application-vnd.svx.svg"
python3 - "$tmp/docpng" "$root/packaging/windows/svx-file.ico" <<'PY'
import sys
from PIL import Image
src, out = sys.argv[1], sys.argv[2]
imgs = [Image.open(f"{src}/{s}x{s}.png").convert("RGBA") for s in (16, 32, 48, 256)]
imgs[-1].save(out, format="ICO", sizes=[(i.width, i.height) for i in imgs], append_images=imgs[:-1])
PY

# Website: SVG favicon, 32 px fallback, 180 px apple-touch-icon.
mkdir -p "$root/brand/web"
sed -E 's#<metadata>.*</metadata>##' "$svg/favicon.svg" > "$root/brand/web/favicon.svg"
tauri_icon "$svg/favicon.svg" -o "$tmp/web" -p 32
tauri_icon "$svg/app-icon.svg" -o "$tmp/touch" -p 180
cp "$tmp/web/32x32.png" "$root/brand/web/favicon-32.png"
cp "$tmp/touch/180x180.png" "$root/brand/web/apple-touch-icon.png"

echo "Icons written."
