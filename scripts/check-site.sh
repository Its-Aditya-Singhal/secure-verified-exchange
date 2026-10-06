#!/usr/bin/env bash
# Check the live website the way a new user's Mac would, before announcing it.
#
#   scripts/check-site.sh [https://getsvx.me]
#
# Fails (exit 1) if any download, checksum, installer or contact page is
# missing or inconsistent.
set -uo pipefail
BASE=${1:-https://getsvx.me}
fail=0
ok()  { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; fail=1; }
code() { curl -sS -m 30 -L -o /dev/null -w '%{http_code}' "$BASE/$1" 2>/dev/null || echo 000; }

echo "Pages"
for p in "" security download docs privacy terms; do
  c=$(curl -sS -m 30 -L -o /dev/null -w '%{http_code}' "$BASE/$p" 2>/dev/null || echo 000)
  [ "$c" = 200 ] && ok "/$p" || bad "/$p returned $c"
done

echo "Installer and download"
[ "$(code install.sh)" = 200 ] && ok "/install.sh" || bad "/install.sh missing"
[ "$(code downloads/SVX-beta-macOS.dmg)" = 200 ] && ok "/downloads/SVX-beta-macOS.dmg" || bad "disk image missing"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
if curl -fsS -m 120 "$BASE/downloads/SVX-beta-macOS.dmg" -o "$tmp/d.dmg" 2>/dev/null &&
   expected=$(curl -fsS -m 30 "$BASE/downloads/SVX-beta-macOS.dmg.sha256" | tr -d '[:space:]'); then
  actual=$(shasum -a 256 "$tmp/d.dmg" | cut -d' ' -f1)
  [ "$expected" = "$actual" ] && ok "checksum file matches the disk image" || bad "checksum file ($expected) differs from the image ($actual)"
  page=$(curl -fsS -m 30 -L "$BASE/download" | grep -o 'id="sum-mac"[^>]*>[0-9a-f]\{64\}' | grep -o '[0-9a-f]\{64\}$')
  [ "$page" = "$actual" ] && ok "download page shows the same checksum" || bad "download page shows '${page:-nothing}'"
  hdiutil verify -quiet "$tmp/d.dmg" >/dev/null 2>&1 && ok "disk image verifies" || bad "disk image is damaged"
else
  bad "could not fetch the disk image or its checksum"
fi
if curl -fsS -m 120 "$BASE/downloads/SVX-beta-Windows.exe" -o "$tmp/w.exe" 2>/dev/null &&
   expected=$(curl -fsS -m 30 "$BASE/downloads/SVX-beta-Windows.exe.sha256" | tr -d '[:space:]'); then
  actual=$(shasum -a 256 "$tmp/w.exe" | cut -d' ' -f1)
  [ "$expected" = "$actual" ] && ok "checksum file matches the Windows installer" || bad "Windows checksum file ($expected) differs from the installer ($actual)"
  page=$(curl -fsS -m 30 -L "$BASE/download" | grep -o 'id="sum-win"[^>]*>[0-9a-f]\{64\}' | grep -o '[0-9a-f]\{64\}$')
  [ "$page" = "$actual" ] && ok "download page shows the Windows checksum" || bad "download page shows '${page:-nothing}' for Windows"
  [ "$(head -c 2 "$tmp/w.exe")" = MZ ] && ok "Windows installer is a program (not an HTML error page)" || bad "Windows installer is not a program"
else
  bad "could not fetch the Windows installer or its checksum"
fi
curl -fsS -m 30 -L "$BASE/download" | grep -q 'curl -fsSL https://getsvx.me/install.sh | sh' && ok "download page shows the install command" || bad "install command missing from the download page"
curl -fsS -m 30 "$BASE/install.sh" | head -1 | grep -q '^#!/bin/sh' && ok "install.sh starts with a shell line (not an HTML error page)" || bad "install.sh is not a script"

cc=$(curl -sSI -m 30 "$BASE/assets/js/boot.js" | tr -d '\r' | grep -i '^cache-control' || true)
echo "$cc" | grep -qi immutable && bad "boot.js is cached as immutable: $cc" || ok "scripts are not cached as immutable"
curl -fsS -m 30 "$BASE/assets/js/boot.js" | grep -q "RELEASE='live'" && ok "release switch is live" || bad "release switch is not live (the Download button is hidden)"

echo "Link preview"
# (read the whole page first: grep -q stops early, which pipefail counts as a failure)
home=$(curl -fsS -m 30 -L "$BASE/" || true)
grep -q 'property="og:image" content="https://getsvx.me/assets/brand/share.png"' <<<"$home" && ok "pages name a preview image" || bad "og:image missing"
ct=$(curl -sS -m 30 -o /dev/null -w '%{http_code} %{content_type}' "$BASE/assets/brand/share.png" || echo 000)
[ "$ct" = "200 image/png" ] && ok "preview image is served ($ct)" || bad "preview image: $ct"

echo "Contact"
[ "$(code .well-known/security.txt)" = 200 ] && curl -fsSL -m 30 "$BASE/.well-known/security.txt" | grep -q "^Contact: mailto:security@getsvx.me" && ok "/.well-known/security.txt" || bad "security.txt missing or wrong"
curl -fsS -m 30 -L "$BASE/" | grep -q 'support@getsvx.me' && ok "support address in the footer" || bad "support address missing"

echo "Service"
c=$(curl -sS -m 30 -o /dev/null -w '%{http_code}' "https://api.getsvx.me:8443/v1/service" 2>/dev/null || echo 000)
[ "$c" = 200 ] && ok "api.getsvx.me:8443 answers" || bad "service returned $c"

[ $fail = 0 ] && echo "All good." || { echo "Some checks failed. Don't announce yet."; exit 1; }
