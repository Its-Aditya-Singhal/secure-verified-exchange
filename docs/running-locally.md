# Running SVX Managed Mode locally

This guide runs every Phase 2 component on loopback. The mock IdPs log anyone in without a password and are for **development only**.

> **Shortcut:** `cargo run -p svx-demo -- serve --state-dir /tmp/svx-stack` starts all of it in one process, with both organizations onboarded, keys registered, a policy and sample artifacts. It writes ready-made `svx` configs to the state directory. See [demo.md](demo.md). The manual steps below show how the pieces fit together and are closer to a real deployment.

## Prerequisites

- Rust 1.88 or later
- PostgreSQL 14 or later

The examples assume Postgres at `postgres://svx@127.0.0.1:5432`.

Without Docker, any local PostgreSQL works. With Homebrew on macOS:

```sh
brew install postgresql@17 && brew services start postgresql@17
psql -h 127.0.0.1 -d postgres -c "CREATE ROLE svx LOGIN PASSWORD 'svx' CREATEDB"
```

That matches the `postgres://svx:svx@127.0.0.1:5432/postgres` URL that `svx-demo` and the tests use by default. Stop it (`brew services stop postgresql@17`) before using `docker compose`, since both use port 5432.

```sh
cargo build --release
B=target/release
createdb svx_service
createdb svx_agent_example
```

## 1. Keys (test-only files; use a KMS/HSM in production)

```sh
$B/svx keygen --kind kem  --owner svx.example   --out service    # receives the service share
$B/svx keygen --kind sign --owner svx.example   --out grant      # signs release grants
$B/svx keygen --kind sign --owner svx.example   --out registry   # signs registry records
$B/svx keygen --kind sign --owner acme-security --out acme       # Acme signs artifacts
$B/svx keygen --kind kem  --owner example-corp  --out example    # Example Corp's org key
```

## 2. Identity providers

```sh
$B/svx-mock-idp --listen 127.0.0.1:8081 --config examples/idp-acme.json &
$B/svx-mock-idp --listen 127.0.0.1:8082 --config examples/idp-example-corp.json &
```

## 3. Managed service and key agent

```sh
$B/svx-server --dev --listen 127.0.0.1:8443 \
  --database-url postgres://svx@127.0.0.1:5432/svx_service --service-id svx.example \
  --kem-key service.kem.key --grant-key grant.sign.key --registry-key registry.sign.key &

$B/svx-keyagent --dev --listen 127.0.0.1:9443 \
  --database-url postgres://svx@127.0.0.1:5432/svx_agent_example \
  --org-id example-corp --idp-issuer http://127.0.0.1:8082 --idp-client-id svx-example-corp \
  --service-id svx.example --service-grant-key grant.sign.pub --kem-key example.kem.key &
```

**TLS outside dev mode.** Without `--dev`, both binaries require `--tls-cert` and `--tls-key`, and refuse to start otherwise.

**Domain verification.** The server verifies domains with real DNS TXT lookups. To onboard an org, register it (`POST /v1/orgs`), publish the returned TXT record, then call verify with an ID token from the org's IdP. The integration tests (`crates/svx-server/tests`) do exactly this against an in-memory resolver. They are the most complete runnable reference until the `svx` CLI commands in Phase 3 automate it.

## Running the integration tests

The end-to-end suite needs a Postgres role that can `CREATE DATABASE`:

```sh
export SVX_TEST_DATABASE_URL=postgres://svx@127.0.0.1:5432/postgres
cargo test -p svx-server
```

Without `SVX_TEST_DATABASE_URL`, these tests are skipped. If `SVX_REQUIRE_DB=1` is also set, as the CI integration job does, a missing URL fails the run instead.

Each test creates databases named `svx_t_<random>_{svc,agent}`. Drop them afterwards with:

```sh
psql -Atc "select 'drop database '||datname||';' from pg_database where datname like 'svx_t_%'" | psql
```

## 4. Use the CLI against the local stack

Onboarding still runs through the API (see the integration tests), because the admin portal arrives in Phase 5. Once an organization is registered, use these commands:

```sh
REG=$(curl -s http://127.0.0.1:8443/v1/service | sed 's/.*"registry_public":"\([0-9a-f]*\)".*/\1/')
$B/svx --config example.toml init --dev --service http://127.0.0.1:8443 \
  --registry-key "$REG" --org example-corp --client-id svx-example-corp
$B/svx --config acme.toml init --dev --service http://127.0.0.1:8443 \
  --registry-key "$REG" --org acme-security --client-id svx-acme

$B/svx --config acme.toml pack secret.txt --sign-key acme.sign.key \
  --recipient example-corp --policy incident-response
$B/svx --config example.toml open secret.svx -o out --dev-user alice   # allowed
$B/svx --config example.toml open secret.svx -o out --dev-user bob     # ACCESS DENIED (exit 1)
```

In a real deployment, obtain the registry fingerprint out of band. Do not read it from the service you are about to trust.
