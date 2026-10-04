# Python SDK

The `svx` Python package lets applications open, pack and administer `.svx`
artifacts. It is a thin layer over the Rust `svx-client` library, the same
code the `svx` command-line tool runs. Every security decision happens in
Rust:

- local verification before any login;
- a fresh login bound to each open;
- key release by both the managed service and the recipient's key agent;
- local decryption with atomic, owner-only output.

Python only adds typed results and exceptions.

Requirements: Python 3.9+. Building from source needs Rust 1.88+.

## Install (from source)

The package is not on PyPI yet; signed releases come in Phase 6.

```sh
cd sdk/python
python -m venv .venv && . .venv/bin/activate
pip install maturin
maturin develop --release        # or: maturin build --release && pip install target/wheels/*.whl
```

The extension uses the stable ABI (`abi3`), so one wheel works on every
CPython from 3.9 upward on that platform.

## Configuration

`svx.Client()` reads the same configuration as the CLI:

1. the `config` argument;
2. otherwise `$SVX_CONFIG`;
3. otherwise the platform default, for example `~/.config/svx/config.toml`.

Create it with `svx init`, which pins the registry key. The admin session
cache (`session.json`) lives next to the configuration file.

## Opening an artifact

```python
import svx

client = svx.Client()

status = client.status("incident.svx")      # verified locally; no login, no audit noise
if not status.for_you:
    raise SystemExit(f"addressed to {status.info.recipient_org}")

try:
    result = client.open(
        "incident.svx",
        output_dir="~/SVX",
        on_step=lambda step, detail: print(step, detail or ""),
    )
    print("saved to", result.path, result.manifest.classification)
except svx.AccessDeniedError as e:
    print("denied:", e.deny_reason)           # "not_authorized", "expired_or_revoked", ...
except svx.RefusedError as e:
    print("refused:", e)                      # rejected, not for us, expired
except svx.UnavailableError:
    print("SVX service unreachable; nothing was decrypted")
```

`open` signs the user in through the system browser, using the RFC 8252
loopback flow. Pass `browser=False` to print the sign-in URL instead. The
login happens on every open. This is deliberate: the service releases keys
only to a login whose nonce binds a one-time key generated for that open, so
a cached token can never be reused to decrypt.

`open_bytes()` returns `(OpenResult, bytes)` instead of writing a file.
Python cannot reliably wipe `bytes`, so prefer `open()` for large or highly
sensitive content.

`on_step(name, detail)` receives these steps in order:

1. `verifying`
2. `signature_valid` (detail: the sender)
3. `connecting`
4. `authenticating`
5. `checking_authorization`
6. `access_approved`
7. `decrypting`

With a personal-account configuration there is no `authenticating` step
(requests are signed with the device key), and `awaiting_approval`
(detail: the sender) comes after `checking_authorization` while the sender
decides.

Exceptions raised by the callback are reported as "unraisable" and never
interrupt the open.

View-only files (personal accounts) are shown only in the desktop app: `open` of one raises `AccessDeniedError` with `deny_reason == "view_only"` unless the sender allowed a copy (the CLI's `svx keep` asks for it); a company open refuses it as `RejectedError`.

## Sending an artifact

```python
import time

client.login()                                   # needed only for register=True
packed = client.pack(
    "report.pdf",
    recipient="example-corp",
    policy="incident-response",
    signing_key="~/keys/acme.sign.key",          # an active, registered key of your org
    expires_at=int(time.time()) + 7 * 86400,
    classification="TLP:AMBER",
    register=True,
)
print(packed.path, packed.artifact_id)
```

The recipient's encryption key and the service key come from registry
records signed by the pinned registry key. `pack` refuses if your signing
key is not an active registered key, because every recipient would reject
the artifact.

## Administration

```python
admin = svx.Client()
admin.login()                                    # caches a short-lived, owner-only session
print(admin.whoami())
admin.revoke("incident.svx")                     # or the 32-hex-digit artifact ID
admin.set_policy("incident-response", {"allow_groups": ["incident-response"], "require_acr": ["phr"]})
page = admin.audit(limit=100)
assert page.chain_valid
admin.logout()
```

## Offline functions

These need no service:

```python
info = svx.inspect("incident.svx")                       # UNVERIFIED header fields
v = svx.verify("incident.svx", trust=["acme.sign.pub"])  # raises RejectedError if invalid
svx.generate_signing_key("acme", "acme-security")       # writes acme.sign.key (0600) / .pub
svx.generate_kem_key("example", "example-corp")
```

## Errors

Every exception carries three attributes:

- `kind`: a stable string;
- `exit_code`: the code the CLI would use;
- `deny_reason`: set for access denials.

| Exception | `kind` | Exit code | Meaning |
|-----------|--------|-----------|---------|
| `RejectedError` | `rejected` | 1 | Tampered, malformed or untrusted artifact |
| `NotRecipientError` | `not_recipient` | 1 | Addressed to another organization |
| `ExpiredError` | `expired` | 1 | Past its signed expiry |
| `AccessDeniedError` | `denied` | 1 | Service or key agent refused (see `deny_reason`) |
| `UnavailableError` | `unavailable` | 3 | Service unreachable; nothing decrypted |
| `LoginError` | `login` | 2 | Sign-in failed |
| `NotLoggedInError` | `not_logged_in` | 2 | Admin call without `login()` |
| `ConfigError` | `config` | 2 | Bad configuration or arguments |
| `OutputExistsError` | `output_exists` | 2 | Output exists and `overwrite=False` |
| `SvxError` | `io`, `other` | 2 | Other local errors |

The first four rows are subclasses of `RefusedError`, which separates security
refusals from outages and local problems.

## Threads and the GIL

Calls block until done and release the GIL while waiting on the network or
disk. Each `Client` has its own small async runtime, so separate clients can
be used from separate threads.

## Development

```sh
cd sdk/python && . .venv/bin/activate
maturin develop
SVX_TEST_DATABASE_URL=postgres://svx:svx@127.0.0.1:5432/postgres pytest
```

- **Offline tests** use the committed test vectors.
- **Managed tests** start `svx-demo serve` against that database. They are
  skipped when no database is configured; set `SVX_REQUIRE_DB=1` to make
  that an error instead.
- **Example:** `examples/python/demo.py` runs the full demo story through
  the SDK.
