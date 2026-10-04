# Node.js / TypeScript SDK

`@svx/sdk` lets Node.js applications open, pack and administer `.svx`
artifacts. It is a native addon built with napi-rs over the Rust
`svx-client` library, the same code the `svx` command-line tool runs. Every
security decision happens in Rust:

- local verification before any login;
- a fresh login bound to each open;
- key release by both the managed service and the recipient's key agent;
- local decryption with atomic, owner-only output.

TypeScript only adds typed results and errors.

Requirements: Node.js 18+. Building from source needs Rust 1.88+.

A native addon is used rather than WebAssembly because opening needs real
sockets, the file system and the OS browser, and must run the exact same
client code as the CLI.

## Install (from source)

The package is not on npm yet; signed releases come in Phase 6.

```sh
cd sdk/node
npm ci
npm run build        # builds svx.<platform>.node, then compiles src/ to dist/
```

## Usage

```ts
import { Client, AccessDeniedError, RefusedError, UnavailableError } from "@svx/sdk";

const client = Client.load(); // config argument, else $SVX_CONFIG, else the platform default

const status = await client.status("incident.svx"); // verified locally; no login
if (!status.for_you) throw new Error(`addressed to ${status.info.recipient_org}`);

try {
  const r = await client.open("incident.svx", {
    outputDir: "/home/me/SVX",
    onStep: (step, detail) => console.log(step, detail ?? ""),
  });
  console.log("saved to", r.path, r.manifest.classification);
} catch (e) {
  if (e instanceof AccessDeniedError) console.error("denied:", e.denyReason);
  else if (e instanceof RefusedError) console.error("refused:", e.message);
  else if (e instanceof UnavailableError) console.error("service unreachable; nothing decrypted");
  else throw e;
}
```

All network operations return Promises and run on a background runtime, so
the event loop is never blocked.

`onStep(name, detail)` receives the same steps as the CLI:

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

Calls are delivered asynchronously, in order.

View-only files (personal accounts) are shown only in the desktop app: `open` of one throws `AccessDeniedError` with `denyReason === "view_only"` unless the sender allowed a copy (the CLI's `svx keep` asks for it); a company open refuses it as `RejectedError`.

### Login

`open` signs in through the system browser every time, using the RFC 8252
loopback flow; `browser: false` prints the URL instead. A login can never be
reused for another open, because key release requires a nonce that binds a
one-time key generated for that open. `devUser` works only with development
configurations.

`openBytes(path, options)` resolves to `{ result, data: Buffer }`.
JavaScript cannot reliably wipe memory, so prefer `open` for highly
sensitive content.

### Sending

```ts
await client.login();                      // needed only for register: true
const packed = await client.pack("report.pdf", {
  recipient: "example-corp",
  policy: "incident-response",
  signingKey: "/home/me/keys/acme.sign.key",
  expiresAt: new Date(Date.now() + 7 * 86400_000),
  classification: "TLP:AMBER",
  register: true,
});
```

### Administration

```ts
await admin.login();
await admin.whoami();
await admin.revoke("incident.svx");        // or the hex artifact ID
await admin.setPolicy("incident-response", { allow_groups: ["incident-response"] });
const page = await admin.audit(100);       // page.chain_valid
admin.logout();
```

### Offline functions

```ts
import { inspect, verify, generateSigningKey, generateKemKey } from "@svx/sdk";
inspect("incident.svx");                            // UNVERIFIED header
verify("incident.svx", ["acme.sign.pub"]);          // throws RejectedError if invalid
generateSigningKey("acme", "acme-security");        // acme.sign.key (0600) / .pub
```

## Errors

Every error is an `SvxError` with three properties:

- `kind`: a stable string;
- `exitCode`: the code the CLI would use;
- `denyReason`: set for access denials.

The classes and their meanings are the same as in the Python SDK; see
[sdk-python.md](sdk-python.md#errors). Briefly:

- `RejectedError`, `NotRecipientError`, `ExpiredError` and
  `AccessDeniedError` extend `RefusedError` (exit code 1).
- `UnavailableError` uses exit code 3.
- `LoginError`, `NotLoggedInError`, `ConfigError` and `OutputExistsError`
  use exit code 2.

Data fields use the same snake_case names as the SVX JSON API and the
Python SDK; methods and options use camelCase.

## Development

```sh
cd sdk/node
npm ci && npm run build && npm run typecheck
SVX_TEST_DATABASE_URL=postgres://svx:svx@127.0.0.1:5432/postgres npm test
node ../../examples/node/demo.mjs /tmp/svx-stack   # after `svx-demo serve --state-dir /tmp/svx-stack`
```

Managed tests start `svx-demo serve` and are skipped without a database
(or fail with `SVX_REQUIRE_DB=1`).
