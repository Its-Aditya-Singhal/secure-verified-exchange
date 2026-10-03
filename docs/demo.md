# The SVX demo: Acme Security → Example Corp

`svx-demo` runs the complete SVX Managed Mode story on your machine in under a
minute and checks every outcome. Everything is real: the managed service,
Example Corp's key agent, two OpenID Connect identity providers, PostgreSQL,
the signed registry, the release protocol and the audit log. Only the
identity providers are development stand-ins that sign people in without a
password.

All organizations, people and data are fictional.

## Run it

You need Rust 1.88+ and a PostgreSQL 14+ that the demo can create (and drop)
databases on.

```sh
docker compose up -d          # PostgreSQL 16 on 127.0.0.1:5432 (svx/svx)
cargo run -p svx-demo -- run
```

With your own PostgreSQL, pass `--database-url` (or set `DATABASE_URL`). The
role needs `CREATEDB`:

```sh
cargo run -p svx-demo -- --database-url postgres://me@127.0.0.1:5432/postgres run
```

Options: `--out DIR` writes the files somewhere you choose, `--keep` keeps
them, `--quiet` prints only the summary and `--no-color` disables colors
(`NO_COLOR` is honored too). The demo exits with status 0 only if every
scenario behaved as expected, so CI runs it as an end-to-end test.

## The cast

| Who | Organization | Groups | Role in the story |
|-----|--------------|--------|-------------------|
| Carol | Acme Security | incident-response | Sends the incident report |
| Alice | Example Corp | incident-response, staff | Authorized recipient |
| Bob | Example Corp | staff | Same company, not authorized |
| Example admin | Example Corp | admins | Revokes, reads the audit trail |
| Eve | none | none | Intercepts the file |

Example Corp's policy `incident-response` allows only its incident-response
group to open artifacts sent under that policy.

## The scenarios

**1. Carol sends the report.** Carol signs in to Acme's IdP and packs
`incident-report.txt` for `example-corp`. The client fetches Example Corp's
encryption key and the service key from registry records signed by the
pinned registry key. Carol never handles recipient key files. The artifact
is registered with the service. The demo checks it is post-quantum hybrid
(suite SVX-1H: X25519 + ML-KEM-768 and Ed25519 + ML-DSA-65).

**2a. Eve intercepts the file.** Eve can read the public header: sender,
recipient, policy name, expiry. The report, its file name and its
classification are encrypted, and the demo checks that no plaintext appears
anywhere in the bytes.

**2b. Eve opens it with her own organization's client.** The signature
checks out, but the artifact is addressed to `example-corp`. The client
refuses before it asks anyone to sign in.

**2c. Eve forges an ID token.** Eve runs her own IdP, mints a token that
names Example Corp's issuer, the user `alice` and the right group, and
calls the release API directly, bypassing the client. The service checks
the signature against Example Corp's published keys and refuses. No key
share is released. The audit trail records an `authentication_failure`.

**2d. Eve tries to sign in to Example Corp.** Example Corp's IdP does not
know her, so login fails and nothing is released.

**3. Alice opens the report.** The flow runs in order: local verification,
recipient and expiry checks, a fresh sign-in bound to a one-time key for
this open, service authorization, key agent authorization, and then local
decryption. The report is written owner-only (mode 0600), and the demo
checks it matches what Carol sent.

**4. Bob opens the report.** Bob signs in successfully, but the policy only
admits the incident-response group, so the service says `not authorized`.
Nothing is written.

**5. A byte is flipped in transit.** The signed payload commitment no longer
matches. The client rejects the file locally and never reaches the login
step.

**6a. An expired artifact.** The signed expiry has passed, so the client
refuses locally.

**6b. A modified client ignores expiry.** The demo skips the client's check
and asks the service for keys directly with a valid, correctly bound Alice
token. The service enforces expiry too and refuses. The client check is a
convenience; the server check is the control.

**7. Revocation.** Example Corp's admin revokes the report. Alice's next
attempt is denied. Revocation stops future access. It cannot recall the copy
Alice decrypted in scenario 3, and SVX never claims otherwise.

**8. The audit trail.** The admin reads Example Corp's audit log:
registration, the shared artifact, Eve's failed authentication, Alice's
approval, Bob's denial, the expired request, the revocation and the denied
access after it. The demo checks that the hash chain is intact.

**9. A folder.** Carol sends a folder of evidence. It is zipped and marked as
a folder inside the encrypted manifest. Alice opens it and gets the folder
back, owner-only, with the same files; no zip or partial files are left
behind.

**10. An older file.** A file sealed before the post-quantum upgrade (suite
SVX-1, X25519 and Ed25519) still opens: the service and key agent keep their
older X25519 keys, and Acme's retired Ed25519 key still verifies files it
signed.

## Try it yourself: `svx-demo serve`

`serve` starts the same stack and keeps it running, so you can drive the real
`svx` CLI or the SDKs by hand:

```sh
cargo build -p svx-cli -p svx-demo
./target/debug/svx-demo serve --state-dir /tmp/svx-stack
```

It writes to the state directory:

| File | What |
|------|------|
| `state.json` | URLs, registry key, IdPs, users, policy and file paths |
| `example.toml`, `acme.toml` | Ready-made `svx` configurations (dev mode) |
| `acme.sign.key` / `.pub` | Acme's registered signing key |
| `incident-report.svx` | A valid sample artifact for Example Corp |
| `expired.svx` | An expired sample artifact |

Then, in another terminal:

```sh
SVX=./target/debug/svx S=/tmp/svx-stack
$SVX --config $S/example.toml open $S/incident-report.svx -o /tmp/svx-out --dev-user alice   # exit 0
$SVX --config $S/example.toml open $S/incident-report.svx -o /tmp/svx-out --dev-user bob     # exit 1
$SVX --config $S/example.toml open $S/expired.svx -o /tmp/svx-out --dev-user alice           # exit 1
$SVX --config $S/acme.toml login --dev-user carol
echo "fictional" > note.txt
$SVX --config $S/acme.toml pack note.txt --recipient example-corp \
  --policy incident-response --sign-key $S/acme.sign.key --register
```

The SDK examples run the same story: `examples/python/demo.py` and
`examples/node/demo.mjs` (see [sdk-python.md](sdk-python.md) and
[sdk-node.md](sdk-node.md)).

Press Ctrl-C to stop. The databases are dropped on exit.

## What the demo is not

- **Not a production deployment.** Services listen on loopback HTTP in dev
  mode. Keys are generated in memory. The IdPs accept anyone they know
  without a password. DNS domain verification is simulated.
- **Not a hardened client.** Plaintext lands on disk for authorized users
  (owner-only, renamed into place atomically). See
  [client.md](client.md) for the limitations of temp files on SSDs and
  copy-on-write filesystems.
