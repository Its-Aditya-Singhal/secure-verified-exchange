#!/bin/sh
# Open the private SVX admin page in your browser.
#
# It reaches the server only through your SSH key: the page runs on the
# server's 127.0.0.1 and is forwarded to this Mac's 127.0.0.1. Nothing new
# is open on the internet. A fresh one-time login token is made each time
# and sent over SSH on stdin (never on a command line).
#
# Stop: close this Terminal window or press Ctrl-C. The page also stops
# after 30 minutes without use.
#
#   scripts/admin.sh
#   SVX_ADMIN_HOST=user@host SVX_ADMIN_KEY=~/.ssh/key scripts/admin.sh
#   SVX_ADMIN_PRINT_URL=1 scripts/admin.sh   # print the login link instead of opening it
set -eu

# The server address is not kept in the repository: SVX_ADMIN_HOST, or the one line in ~/.svx-server (user@host).
HOST=${SVX_ADMIN_HOST:-$(cat "$HOME/.svx-server" 2>/dev/null || true)}
[ -n "$HOST" ] || { echo "Set SVX_ADMIN_HOST=user@host, or put user@host in ~/.svx-server" >&2; exit 1; }
KEY=${SVX_ADMIN_KEY:-$HOME/.ssh/svx_azure}
REMOTE_PORT=9790

[ -r "$KEY" ] || { echo "SSH key not found: $KEY" >&2; exit 1; }

PORT=9791
while nc -z 127.0.0.1 "$PORT" 2>/dev/null; do
  PORT=$((PORT + 1))
  [ "$PORT" -lt 9890 ] || { echo "no free local port found" >&2; exit 1; }
done

TOKEN=$(openssl rand -hex 32)
URL="http://127.0.0.1:$PORT/login?t=$TOKEN"

echo "Connecting to the SVX server…"
{ printf '%s\n' "$TOKEN"; cat; } |
  ssh -T -i "$KEY" \
    -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 \
    -L "127.0.0.1:$PORT:127.0.0.1:$REMOTE_PORT" \
    "$HOST" "sudo -n svx-admin web --port $REMOTE_PORT" |
  {
    while IFS= read -r line; do
      if [ "$line" = ready ]; then
        echo "Admin page open in your browser. Keep this window open while you use it;"
        echo "close it (or press Ctrl-C) when you're done."
        if [ -n "${SVX_ADMIN_PRINT_URL:-}" ]; then echo "$URL"; else open "$URL"; fi
      else
        echo "$line"
      fi
    done
    echo "The admin session has ended. You can close this window."
  }
