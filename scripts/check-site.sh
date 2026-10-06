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
code() { curl -sS -m 30 -o /dev/null -w '%{http_code}' "$BASE/$1" 2>/dev/null || echo 000; }

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
curl -fsS -m 30 -L "$BASE/download" | grep -q 'curl -fsSL https://getsvx.me/install.sh | sh' && ok "download page shows the install command" || bad "install command missing from the download page"
curl -fsS -m 30 "$BASE/install.sh" | head -1 | grep -q '^#!/bin/sh' && ok "install.sh starts with a shell line (not an HTML error page)" || bad "install.sh is not a script"

echo "Contact"
[ "$(code .well-known/security.txt)" = 200 ] && ok "/.well-known/security.txt" || bad "security.txt missing"
curl -fsS -m 30 -L "$BASE/" | grep -q 'support@getsvx.me' && ok "support address in the footer" || bad "support address missing"

echo "Service"
c=$(curl -sS -m 30 -o /dev/null -w '%{http_code}' "https://api.getsvx.me:8443/v1/service" 2>/dev/null || echo 000)
[ "$c" = 200 ] && ok "api.getsvx.me:8443 answers" || bad "service returned $c"

[ $fail = 0 ] && echo "All good." || { echo "Some checks failed. Don't announce yet."; exit 1; }
