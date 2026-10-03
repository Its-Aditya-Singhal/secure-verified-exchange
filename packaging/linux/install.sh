#!/bin/sh
# Register the .svx file type and associate it with `svx open` for the
# current user. Requires `svx` on PATH.
set -eu
here=$(dirname "$0")
data=${XDG_DATA_HOME:-$HOME/.local/share}
mkdir -p "$data/mime/packages" "$data/applications" "$HOME/SVX"
chmod 700 "$HOME/SVX"  # default output directory of `svx open`
cp "$here/svx-mime.xml" "$data/mime/packages/svx.xml"
cp "$here/svx.desktop" "$data/applications/svx.desktop"
# Document icon (from brand/build-icons.sh).
for s in 16 32 48 64 128 256 512; do
  mkdir -p "$data/icons/hicolor/${s}x$s/mimetypes"
  cp "$here/icons/application-vnd.svx-$s.png" "$data/icons/hicolor/${s}x$s/mimetypes/application-vnd.svx.png"
done
mkdir -p "$data/icons/hicolor/scalable/mimetypes"
cp "$here/icons/application-vnd.svx.svg" "$data/icons/hicolor/scalable/mimetypes/"
gtk-update-icon-cache "$data/icons/hicolor" 2>/dev/null || true
update-mime-database "$data/mime" 2>/dev/null || true
update-desktop-database "$data/applications" 2>/dev/null || true
xdg-mime default svx.desktop application/vnd.svx 2>/dev/null || true
echo "Registered application/vnd.svx -> svx open (output: ~/SVX)"
