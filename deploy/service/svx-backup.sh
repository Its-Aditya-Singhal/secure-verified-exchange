#!/bin/sh
# Nightly encrypted dump of the SVX database. Runs as the postgres user
# (svx-backup.service). The dump is encrypted to a public key kept in
# /etc/svx-backup.pub; the matching private key lives only on the
# operator's computer, so a stolen server can't read old backups.
# Keeps the newest KEEP dumps.
set -eu
DIR=/var/backups/svx
KEEP=${KEEP:-14}
RECIPIENT_FILE=/etc/svx-backup.pub
DB=${SVX_DB:-svx}

umask 077
stamp=$(date -u +%Y%m%dT%H%M%SZ)
tmp="$DIR/.partial-$stamp"
out="$DIR/svx-$stamp.dump.age"

pg_dump --format=custom --no-owner "$DB" | age --recipients-file "$RECIPIENT_FILE" > "$tmp"
# An empty or tiny file means the pipeline failed quietly.
[ "$(wc -c < "$tmp")" -gt 1000 ] || { rm -f "$tmp"; echo "backup too small, discarded" >&2; exit 1; }
mv "$tmp" "$out"
echo "wrote $out ($(wc -c < "$out") bytes)"

# Remove older dumps beyond the newest KEEP.
ls -1t "$DIR"/svx-*.dump.age | tail -n +$((KEEP + 1)) | while read -r old; do rm -f -- "$old"; done
