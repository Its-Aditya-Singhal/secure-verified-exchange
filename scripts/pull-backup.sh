#!/usr/bin/env bash
# Copy the server's encrypted database backups to this computer.
#
#   scripts/pull-backup.sh              fetch new backups
#   scripts/pull-backup.sh --drill      also restore the newest into a scratch
#                                       database and check it, then drop it
#
# The dumps are encrypted to a public key; the private key is
# ~/.svx-service-backup/db-backup-age.key (keep a copy of it offline: without
# it the dumps can't be read). Needs: ssh access to the server, age, rsync and,
# for --drill, a local PostgreSQL role that may create databases.
set -euo pipefail

# The server address is not kept in the repository: SVX_SERVER, or the one line in ~/.svx-server (user@host).
SERVER=${SVX_SERVER:-$(cat "$HOME/.svx-server" 2>/dev/null || true)}
[ -n "$SERVER" ] || { echo "Set SVX_SERVER=user@host, or put user@host in ~/.svx-server" >&2; exit 1; }
SSH_KEY=${SVX_SSH_KEY:-$HOME/.ssh/svx_azure}
DEST=${SVX_BACKUP_DIR:-$HOME/.svx-service-backup/db}
IDENTITY=${SVX_BACKUP_KEY:-$HOME/.svx-service-backup/db-backup-age.key}
ADMIN_URL=${SVX_TEST_DATABASE_URL:-postgres://svx:svx@127.0.0.1:5432/postgres}

umask 077
mkdir -p "$DEST"
rsync -e "ssh -i $SSH_KEY" --rsync-path="sudo rsync" -rt \
  --include='svx-*.dump.age' --exclude='*' "$SERVER:/var/backups/svx/" "$DEST/"
newest=$(ls -1t "$DEST"/svx-*.dump.age | head -1)
echo "have $(ls "$DEST"/svx-*.dump.age | wc -l | tr -d ' ') backups; newest: $(basename "$newest")"

if [ "${1:-}" = "--drill" ]; then
  db="svx_restore_drill_$$"
  work=$(mktemp -d)
  trap 'rm -rf "$work"; psql "$ADMIN_URL" -qc "DROP DATABASE IF EXISTS $db" >/dev/null 2>&1 || true' EXIT
  age -d -i "$IDENTITY" -o "$work/dump" "$newest"
  psql "$ADMIN_URL" -qc "CREATE DATABASE $db"
  url=${ADMIN_URL%/*}/$db
  pg_restore --no-owner --dbname "$url" "$work/dump"
  echo "restored into $db; row counts:"
  psql "$url" -At -c "SELECT 'accounts', count(*) FROM personal_accounts UNION ALL SELECT 'files', count(*) FROM personal_files UNION ALL SELECT 'audit entries', count(*) FROM audit UNION ALL SELECT 'migrations', count(*) FROM _sqlx_migrations"
  echo "drill OK (scratch database dropped)"
fi
