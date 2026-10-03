import assert from "node:assert/strict";
import { copyFileSync, existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";

import * as svx from "../dist/index.js";
import { configFor, startStack, tmp } from "./helpers.mjs";

let stack;
before(async () => {
  stack = await startStack();
});
after(async () => {
  if (stack) await stack.stop();
});

const STEPS = [
  "verifying",
  "signature_valid",
  "connecting",
  "authenticating",
  "checking_authorization",
  "access_approved",
  "decrypting",
];

function artifact() {
  const p = join(tmp(), "incident-report.svx");
  copyFileSync(stack.sample_artifact, p);
  return p;
}

describe("managed", () => {
  test("alice opens", async (t) => {
    if (!stack) return t.skip("SVX_TEST_DATABASE_URL not set");
    const c = svx.Client.load(configFor(stack, "example-corp"));
    const steps = [];
    const out = join(tmp(), "out");
    const a = artifact();
    const r = await c.open(a, {
      outputDir: out,
      devUser: "alice",
      onStep: (name, detail) => steps.push([name, detail]),
    });
    assert.equal(readFileSync(r.path, "utf8"), stack.sample_plaintext);
    assert.equal(r.sender_org, "acme-security");
    // Callbacks are delivered asynchronously; let the event loop drain.
    await new Promise((res) => setImmediate(res));
    assert.deepEqual(
      steps.map((s) => s[0]),
      STEPS,
    );
    assert.equal(steps[1][1], "acme-security");
    if (process.platform !== "win32") assert.equal(statSync(r.path).mode & 0o777, 0o600);
    await assert.rejects(c.open(a, { outputDir: out, devUser: "alice" }), svx.OutputExistsError);
  });

  test("openBytes", async (t) => {
    if (!stack) return t.skip("no database");
    const c = svx.Client.load(configFor(stack, "example-corp"));
    const { result, data } = await c.openBytes(artifact(), { devUser: "alice" });
    assert.equal(data.toString("utf8"), stack.sample_plaintext);
    assert.equal(result.path, null);
  });

  test("bob denied", async (t) => {
    if (!stack) return t.skip("no database");
    const c = svx.Client.load(configFor(stack, "example-corp"));
    const out = join(tmp(), "bob");
    await assert.rejects(c.open(artifact(), { outputDir: out, devUser: "bob" }), (e) => {
      assert.ok(e instanceof svx.AccessDeniedError);
      assert.equal(e.denyReason, "not_authorized");
      assert.equal(e.exitCode, 1);
      return true;
    });
    assert.equal(existsSync(out), false);
  });

  test("tampered rejected before login", async (t) => {
    if (!stack) return t.skip("no database");
    const c = svx.Client.load(configFor(stack, "example-corp"));
    const b = readFileSync(artifact());
    b[b.length >> 1] ^= 1;
    const bad = join(tmp(), "bad.svx");
    writeFileSync(bad, b);
    const steps = [];
    await assert.rejects(
      c.open(bad, { outputDir: join(tmp(), "o"), devUser: "alice", onStep: (n) => steps.push(n) }),
      svx.RejectedError,
    );
    await new Promise((res) => setImmediate(res));
    assert.ok(!steps.includes("authenticating"));
  });

  test("wrong org, expired, unknown user", async (t) => {
    if (!stack) return t.skip("no database");
    const acme = svx.Client.load(configFor(stack, "acme-security"));
    await assert.rejects(
      acme.open(artifact(), { outputDir: join(tmp(), "o"), devUser: "carol" }),
      svx.NotRecipientError,
    );
    const ex = svx.Client.load(configFor(stack, "example-corp"));
    await assert.rejects(
      ex.open(stack.expired_artifact, { outputDir: join(tmp(), "o"), devUser: "alice" }),
      svx.ExpiredError,
    );
    await assert.rejects(
      ex.open(artifact(), { outputDir: join(tmp(), "o"), devUser: "eve" }),
      svx.LoginError,
    );
  });

  test("status", async (t) => {
    if (!stack) return t.skip("no database");
    const s = await svx.Client.load(configFor(stack, "example-corp")).status(artifact());
    assert.equal(s.for_you, true);
    assert.equal(s.expired, false);
    assert.equal(s.info.post_quantum, true);
    assert.equal(s.info.suite_id, 0x0003);
  });

  test("pack, register, open, revoke, audit", async (t) => {
    if (!stack) return t.skip("no database");
    const acme = svx.Client.load(configFor(stack, "acme-security"));
    await acme.login({ devUser: "carol" });
    const src = join(tmp(), "findings.txt");
    writeFileSync(src, "FICTIONAL findings for the Node SDK test\n");
    const packed = await acme.pack(src, {
      recipient: "example-corp",
      policy: stack.policy,
      signingKey: stack.acme_signing_key,
      expiresAt: new Date(Date.now() + 3600_000),
      classification: "TLP:GREEN",
      register: true,
    });
    assert.ok(packed.registered);
    assert.match(packed.protection, /^post-quantum hybrid/);
    assert.equal(svx.inspect(packed.path).artifact_id, packed.artifact_id);

    const ex = svx.Client.load(configFor(stack, "example-corp"));
    const r = await ex.open(packed.path, { outputDir: join(tmp(), "out"), devUser: "alice" });
    assert.equal(readFileSync(r.path, "utf8"), readFileSync(src, "utf8"));
    assert.equal(r.manifest.classification, "TLP:GREEN");

    await assert.rejects(ex.revoke(packed.path), svx.NotLoggedInError);
    const who = await ex.login({ devUser: "example-admin" });
    assert.equal(who.sub, "example-admin");
    assert.equal((await ex.whoami()).org_id, "example-corp");
    assert.equal(await ex.revoke(packed.path), packed.artifact_id);
    await assert.rejects(
      ex.open(packed.path, { outputDir: join(tmp(), "again"), devUser: "alice" }),
      (e) => e instanceof svx.AccessDeniedError && e.denyReason === "expired_or_revoked",
    );
    const page = await ex.audit(100);
    assert.ok(page.chain_valid);
    const events = new Set(page.entries.map((e) => e.event));
    for (const ev of ["decryption_authorized", "artifact_revoked", "revoked_artifact_access"]) {
      assert.ok(events.has(ev), ev);
    }
    const saved = await ex.setPolicy("node-test", { allow_groups: ["staff"] });
    assert.deepEqual(saved.allow_groups, ["staff"]);
    assert.ok("node-test" in (await ex.policies()));
    assert.equal(ex.logout(), true);
    assert.equal(ex.logout(), false);
  });

  test("org record", async (t) => {
    if (!stack) return t.skip("no database");
    const rec = await svx.Client.load(configFor(stack, "example-corp")).orgRecord("acme-security");
    assert.equal(rec.org_id, "acme-security");
    assert.ok(rec.keys.some((k) => k.kind === "ed25519"));
  });

  test("service down is unavailable", async (t) => {
    if (!stack) return t.skip("no database");
    const cfg = configFor(stack, "example-corp");
    writeFileSync(cfg, readFileSync(cfg, "utf8").replace(stack.service_url, "http://127.0.0.1:9"));
    const out = join(tmp(), "o");
    await assert.rejects(
      svx.Client.load(cfg).open(artifact(), { outputDir: out, devUser: "alice" }),
      (e) => e instanceof svx.UnavailableError && e.exitCode === 3,
    );
    assert.equal(existsSync(out), false);
  });
});
