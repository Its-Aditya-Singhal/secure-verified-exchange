#!/usr/bin/env bash
# Make the self-made macOS code-signing certificate the release builds use
# (once; keep it with the other release keys and back it up offline).
#
#   scripts/make-signing-cert.sh
#
# Why: an ad-hoc signed app is identified by a hash of that exact build, so
# after every update macOS treats it as a different app and asks for the
# keychain password before it may read its own keys. Signing every build
# with the same certificate gives every version the same identity
# (identifier "org.svx.desktop" and this certificate), so the keychain's
# "Always Allow" lasts across updates. It is not an Apple certificate:
# Gatekeeper still treats the app as from an unidentified developer.
#
# Writes $SVX_RELEASE_KEYS (default ~/.svx-release)/macos-signing.p12 and
# macos-signing.password (mode 0600). Never commit them. Losing them only
# means one more keychain prompt per user after the next update.
set -euo pipefail
KEYS=${SVX_RELEASE_KEYS:-$HOME/.svx-release}
P12=$KEYS/macos-signing.p12
PW=$KEYS/macos-signing.password
NAME="SVX Release Signing"
[ ! -e "$P12" ] || { echo "$P12 already exists; keep using it" >&2; exit 1; }
mkdir -p "$KEYS"
umask 077
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/cert.cnf" <<CNF
[req]
distinguished_name = dn
x509_extensions = v3
prompt = no
[dn]
CN = $NAME
O = SVX
[v3]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
subjectKeyIdentifier = hash
CNF
# macOS's own openssl (LibreSSL) writes a .p12 that `security import` reads.
/usr/bin/openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 7300 \
  -keyout "$TMP/key.pem" -out "$TMP/cert.pem" -config "$TMP/cert.cnf" 2>/dev/null
/usr/bin/openssl rand -hex 24 > "$PW"
/usr/bin/openssl pkcs12 -export -name "$NAME" -inkey "$TMP/key.pem" -in "$TMP/cert.pem" \
  -out "$P12" -passout "file:$PW"
chmod 600 "$P12" "$PW"
echo "Wrote $P12 (\"$NAME\", valid 20 years)"
/usr/bin/openssl x509 -in "$TMP/cert.pem" -noout -fingerprint -sha1 | sed 's/^/Certificate /'
