# Running the SVX key agent

Every organization that **receives** files runs a key agent. It holds the
organization's encryption keys and releases the organization's half of a
file's key only when:

1. the SVX service has authorized the person for that file, **and**
2. the same person signs in to *your* company login.

The service never gets your half, so a compromised service still can't
decrypt your files. Files themselves never reach the agent; it sees only
the public file header.

## What you need

- A Linux server or container platform reachable over HTTPS by your users'
  devices (it doesn't need to be reachable from the internet if all your
  users are on your network or VPN).
- PostgreSQL 14+ (for one-time transaction IDs and the agent's own audit log).
- A TLS certificate for the agent's host name.
- From SVX: the service ID, the service's grant key file
  (`service-grant.sign.pub`, an SVX-2 key) and, optionally for
  `check`, the registry key fingerprint.
- Your organization's encryption key. An administrator creates it in the
  desktop app: **Admin → Keys → Create a new encryption key…** writes an
  owner-only `*.kem.key` file to a folder they choose. Move that file to
  the agent server and delete the local copy.

## Option 1: Docker

```sh
docker build -f deploy/keyagent/Dockerfile -t svx-keyagent .    # from the repository root
cd deploy/keyagent
mkdir -p config keys tls
cp agent.toml.example config/agent.toml        # edit it
cp /path/to/example-corp-1a2b3c4d.kem.key /path/to/service-grant.sign.pub keys/
cp /path/to/agent.crt /path/to/agent.key tls/
sudo chown -R 65532:65532 keys tls && chmod 600 keys/*.key tls/*.key
export POSTGRES_PASSWORD='choose-a-strong-password'
docker compose run --rm keyagent check
docker compose up -d
```

The image has no shell or package manager, runs as UID 65532 with a
read-only root filesystem and no capabilities, and has a health check
(`svx-keyagent healthcheck`).

## Option 2: systemd

The release tarball (built by CI as `svx-keyagent-linux-x86_64`) contains
the binary, `svx-keyagent.service`, `agent.toml.example` and `install.sh`:

```sh
tar xzf svx-keyagent-linux-x86_64.tar.gz && cd svx-keyagent-linux-x86_64
sudo ./install.sh
sudoedit /etc/svx/agent.toml /etc/svx/agent.env   # settings; DATABASE_URL goes in agent.env
sudo cp current.kem.key /etc/svx/keys/ && sudo chmod 600 /etc/svx/keys/*
sudo svx-keyagent --config /etc/svx/agent.toml check
sudo systemctl enable --now svx-keyagent
```

The unit runs as a throwaway system user with a strict sandbox. Keys and the
TLS key are passed as systemd credentials (owner-only copies under
`/run/credentials/svx-keyagent.service/`); point `kem_keys` and `tls_key` in
`agent.toml` there, and keep `LoadCredential=` lines in the unit in step.

## Configuration

See `deploy/keyagent/agent.toml.example`. Every setting is also a flag
(`svx-keyagent --help`); flags override the file. The agent refuses to start
if:

- TLS isn't configured (except `dev` mode on loopback);
- a secret key file is readable by other users;
- a key file belongs to another organization;
- no MLKEM1024-P384 (SVX-2) encryption key is configured;
- the service grant key isn't an SVX-2 (Ed25519 + ML-DSA-87 + SLH-DSA) key.

`svx-keyagent check` runs these checks, connects to the database and, if
`service_url` and `registry_key` (the registry key fingerprint) are set,
confirms that the service's registry key matches the fingerprint, that
`service_grant_key` is the grant key the service publishes, and that the
registry's active encryption key is one the agent holds. Run it after every
change.

## Rotating the encryption key

1. In the desktop app: **Admin → Keys → Create a new encryption key…**.
2. Install the new `*.kem.key` on the agent and **add** it to `kem_keys`
   (keep the old ones: files already sent still need them). Restart.
3. In the app: **Activate**. The app first asks the agent which keys it holds
   (`GET /v1/agent/keys`, public information) and refuses to activate a key
   the agent doesn't have, so no file is ever sealed to a key the agent
   can't use. The previous key is then retired.
4. Remove an old key from `kem_keys` only once every file sealed to it has
   expired. Destroying it makes those files permanently unreadable.

## Monitoring

- Liveness: `svx-keyagent healthcheck --addr 127.0.0.1:9443` (exit code 0).
- The agent's audit log is the `agent_audit` table (append-only, enforced by
  a trigger): every release and every refusal, with the reason.
- The SVX service's audit trail (desktop app → Admin → Audit trail) records
  the authorization decisions for your organization.
