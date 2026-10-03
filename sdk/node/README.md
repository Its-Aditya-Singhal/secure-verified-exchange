# @svx/sdk — Node.js / TypeScript SDK

Node.js bindings for the SVX client, built with napi-rs. Every operation runs
the same Rust code as the `svx` command-line tool: local signature
verification before any login, a fresh login bound to each open, and
decryption only after the managed service and the recipient's key agent both
approve.

See [`docs/sdk-node.md`](../../docs/sdk-node.md) for the full guide.

```ts
import { Client, AccessDeniedError } from "@svx/sdk";

const client = Client.load(); // ~/.config/svx/config.toml or $SVX_CONFIG
try {
  const r = await client.open("incident.svx", { outputDir: "/home/me/SVX" });
  console.log(r.path);
} catch (e) {
  if (e instanceof AccessDeniedError) console.error("denied:", e.denyReason);
  else throw e;
}
```

Build from source (Rust 1.88+, Node 18+):

```sh
npm ci
npm run build
npm test   # managed tests need SVX_TEST_DATABASE_URL
```
