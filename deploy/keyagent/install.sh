#!/bin/sh
# Install the SVX key agent from the release tarball as a systemd service.
# Run as root from the unpacked tarball directory. It installs files and
# never starts the service: configure /etc/svx/agent.toml first.
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root (sudo ./install.sh)" >&2
  exit 1
fi

install -m 0755 svx-keyagent /usr/local/bin/svx-keyagent
# The service runs as a dynamic user: the config and public files must be
# world-readable; secrets reach it only as systemd credentials (keys, TLS
# key) or through /etc/svx/agent.env (DATABASE_URL), both read by systemd.
install -d -m 0755 /etc/svx /etc/svx/tls
install -d -m 0700 /etc/svx/keys
if [ ! -e /etc/svx/agent.toml ]; then
  install -m 0644 agent.toml.example /etc/svx/agent.toml
fi
if [ ! -e /etc/svx/agent.env ]; then
  install -m 0600 /dev/null /etc/svx/agent.env
  echo 'DATABASE_URL=postgres://svx_agent:CHANGE-ME@localhost:5432/svx_agent' > /etc/svx/agent.env
fi
install -m 0644 svx-keyagent.service /etc/systemd/system/svx-keyagent.service
systemctl daemon-reload

cat <<'NEXT'
Installed svx-keyagent.

Next:
  1. Edit /etc/svx/agent.toml (organization, sign-in, keys, TLS) and put the
     database URL in /etc/svx/agent.env (owner-only), not in agent.toml.
  2. Put your keys in /etc/svx/keys and the TLS certificate in /etc/svx/tls
     (chmod 600 for secret files), and match LoadCredential= lines in
     /etc/systemd/system/svx-keyagent.service.
  3. Check:  svx-keyagent --config /etc/svx/agent.toml check
  4. Start:  systemctl enable --now svx-keyagent
NEXT
