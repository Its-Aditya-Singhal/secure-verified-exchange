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
update-mime-database "$data/mime" 2>/dev/null || true
update-desktop-database "$data/applications" 2>/dev/null || true
xdg-mime default svx.desktop application/vnd.svx 2>/dev/null || true
echo "Registered application/vnd.svx -> svx open (output: ~/SVX)"
