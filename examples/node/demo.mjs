// The Acme Security -> Example Corp demo, written against the Node.js SDK.
//
// Build the SDK and start the dev stack first:
//
//   (cd sdk/node && npm ci && npm run build)
//   cargo run -p svx-demo -- serve --state-dir /tmp/svx-stack
//   node examples/node/demo.mjs /tmp/svx-stack
//
// All organizations, people and data are fictional.

import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as svx from "../../sdk/node/dist/index.js";

const stateDir = process.argv[2];
if (!stateDir) {
  console.error("usage: node examples/node/demo.mjs <svx-demo serve --state-dir>");
  process.exit(2);
}

/** @type {{orgs: {org_id: string, config: string}[], policy: string, acme_signing_key: string, expired_artifact: string}} */
const state = JSON.parse(readFileSync(join(stateDir, "state.json"), "utf8"));
const work = mkdtempSync(join(tmpdir(), "svx-node-demo-"));

/** One config directory per person, so admin sessions stay separate. */
function client(/** @type {string} */ org, /** @type {string} */ who) {
  const cfg = state.orgs.find((o) => o.org_id === org);
  if (!cfg) throw new Error(`unknown org ${org}`);
  mkdirSync(join(work, who));
  copyFileSync(cfg.config, join(work, who, "config.toml"));
  return svx.Client.load(join(work, who, "config.toml"));
}

/** @type {boolean[]} */
const results = [];
function check(/** @type {string} */ name, /** @type {boolean} */ ok, /** @type {string} */ detail) {
  results.push(ok);
  console.log(`${ok ? "✔" : "✘"} ${name}: ${detail}`);
}

/**
 * Expect `p` to reject with an instance of `Cls`.
 * @param {Promise<unknown>} p
 * @param {Function} Cls
 */
async function refused(p, Cls) {
  try {
    await p;
    return { ok: false, detail: "opened!" };
  } catch (e) {
    const err = /** @type {svx.SvxError} */ (e);
    return { ok: e instanceof Cls, detail: `${err.name}: ${err.message}` };
  }
}

const carol = client("acme-security", "carol");
const alice = client("example-corp", "alice");
const bob = client("example-corp", "bob");
const admin = client("example-corp", "example-admin");

// 1. Carol packs a report for Example Corp.
const report = join(work, "incident-report.txt");
writeFileSync(report, "FICTIONAL incident report: lookalike domain login-examplecorp.invalid\n");
await carol.login({ devUser: "carol" });
const packed = await carol.pack(report, {
  recipient: "example-corp",
  policy: state.policy,
  signingKey: state.acme_signing_key,
  expiresAt: new Date(Date.now() + 86_400_000),
  classification: "TLP:AMBER",
  register: true,
});
check("Carol packs", true, `${packed.path} (${packed.artifact_id})`);

// 2. Eve sees metadata only, and another org's client refuses.
const info = svx.inspect(packed.path);
check(
  "Eve inspects",
  !readFileSync(packed.path).includes("lookalike"),
  `sees only ${info.sender_org} -> ${info.recipient_org}`,
);
let r = await refused(carol.open(packed.path, { outputDir: join(work, "eve"), devUser: "carol" }), svx.NotRecipientError);
check("Wrong org opens", r.ok, r.detail);

// 3. Alice is authorized.
const opened = await alice.open(packed.path, {
  outputDir: join(work, "alice-out"),
  devUser: "alice",
  onStep: (step, detail) => console.log(`    ${step}${detail ? ` (${detail})` : ""}`),
});
check(
  "Alice opens",
  readFileSync(opened.path ?? "", "utf8") === readFileSync(report, "utf8"),
  opened.path ?? "",
);

// 4. Bob is not.
r = await refused(bob.open(packed.path, { outputDir: join(work, "bob-out"), devUser: "bob" }), svx.AccessDeniedError);
check("Bob opens", r.ok, r.detail);

// 5. Tampered copy.
const bytes = readFileSync(packed.path);
bytes[bytes.length >> 1] ^= 1;
const tampered = join(work, "tampered.svx");
writeFileSync(tampered, bytes);
r = await refused(alice.open(tampered, { outputDir: join(work, "t"), devUser: "alice" }), svx.RejectedError);
check("Tampered", r.ok, r.detail);

// 6. Expired.
r = await refused(alice.open(state.expired_artifact, { outputDir: join(work, "x"), devUser: "alice" }), svx.ExpiredError);
check("Expired", r.ok, r.detail);

// 7. Revoked.
await admin.login({ devUser: "example-admin" });
await admin.revoke(packed.path);
r = await refused(alice.open(packed.path, { outputDir: join(work, "again"), devUser: "alice" }), svx.AccessDeniedError);
check("Revoked", r.ok, r.detail);

// 8. Audit.
const page = await admin.audit(100);
for (const e of page.entries.sort((a, b) => a.seq - b.seq).slice(-6)) {
  console.log(`    #${e.seq} ${e.event} ${e.subject ?? "-"}`);
}
check("Audit chain", page.chain_valid, `${page.entries.length} events`);

console.log(`\n${results.filter(Boolean).length}/${results.length} checks as expected. Files in ${work}`);
process.exit(results.every(Boolean) ? 0 : 1);
