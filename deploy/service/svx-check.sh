#!/bin/sh
# Health check, run every 5 minutes by svx-check.timer (as root). Looks at
# the service, the database, disk, memory and the age of the last backup,
# and sends an email (through the same Gmail account the service uses) when
# something is wrong, once per problem, and again when it is fixed.
# Alerts go to the address in /etc/svx/alert.env (ALERT_TO=...).
set -eu
STATE=/var/lib/svx-check
mkdir -p "$STATE"
. /etc/svx/alert.env
. /etc/svx/smtp.env   # SVX_SMTP_URL, SVX_SMTP_FROM

problems=""
add() { problems="${problems}${problems:+; }$1"; }

systemctl is-active --quiet svx-server || add "svx-server is not running"
curl -ksf -m 10 https://127.0.0.1:8443/healthz >/dev/null || add "the service does not answer on 127.0.0.1:8443"
systemctl is-active --quiet postgresql || add "PostgreSQL is not running"

used=$(df --output=pcent / | tail -1 | tr -dc 0-9)
[ "$used" -lt 85 ] || add "disk is ${used}% full"
avail=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
[ "$avail" -gt 60 ] || add "only ${avail} MB of memory available"

newest=$(ls -1t /var/backups/svx/svx-*.dump.age 2>/dev/null | head -1 || true)
if [ -z "$newest" ]; then
  add "no database backup exists"
else
  age_h=$(( ($(date +%s) - $(stat -c %Y "$newest")) / 3600 ))
  [ "$age_h" -lt 30 ] || add "the last database backup is ${age_h} hours old"
fi

send() { # subject, body
  host=${SVX_SMTP_URL#*@}
  creds=${SVX_SMTP_URL#smtps://}; creds=${creds%@*}
  user=${creds%%:*}; pass=${creds#*:}
  from_addr=$(printf '%s' "$SVX_SMTP_FROM" | sed -E 's/.*<(.*)>.*/\1/')
  printf 'From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s\r\n' "$SVX_SMTP_FROM" "$ALERT_TO" "$1" "$2" |
    curl -sf -m 30 --ssl-reqd "smtps://$host" --mail-from "$from_addr" --mail-rcpt "$ALERT_TO" \
      --user "$(printf '%s' "$user" | sed 's/%40/@/'):$pass" -T - >/dev/null || return 1
  # Count it in the mail account's daily allowance (shown in the admin
  # page). Best effort: the database may be the problem being reported.
  runuser -u postgres -- psql -qX -d svx \
    -c "INSERT INTO email_sends (at, kind) VALUES (extract(epoch from now())::bigint, 'alert')" \
    >/dev/null 2>&1 || true
}

last="$STATE/last"
prev=$(cat "$last" 2>/dev/null || true)
if [ "$problems" != "$prev" ]; then
  if [ -n "$problems" ]; then
    send "[SVX] problem: $problems" "SVX server check at $(date -u +%FT%TZ): $problems"
  else
    send "[SVX] all clear" "The SVX server checks pass again ($(date -u +%FT%TZ))."
  fi
  printf '%s' "$problems" > "$last"
fi
