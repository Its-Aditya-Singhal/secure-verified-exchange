import assert from "node:assert/strict";
import { statSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import * as svx from "../dist/index.js";
import { VECTORS, tmp } from "./helpers.mjs";

function vectorTrust() {
  const keys = JSON.parse(readFileSync(join(VECTORS, "keys.json"), "utf8"));
  const p = join(tmp(), "acme.sign.pub");
  writeFileSync(
    p,
    JSON.stringify({
      svx_key: 1,
      type: "ed25519-public",
      owner: "acme-security",
      key_id: keys["acme-security"].key_id,
      key: keys["acme-security"].ed25519_public,
    }),
  );
  return p;
}

test("version", () => {
  assert.match(svx.version, /^\d+\.\d+\.\d+/);
});

test("generate keys", () => {
  const d = tmp();
  assert.equal(svx.generateSigningKey(join(d, "acme"), "acme-security").length, 32);
  assert.equal(svx.generateKemKey(join(d, "ex"), "example-corp").length, 32);
  if (process.platform !== "win32") {
    assert.equal(statSync(join(d, "acme.sign.key")).mode & 0o077, 0);
  }
  assert.throws(() => svx.generateSigningKey(join(d, "x"), "Not Valid!"), svx.ConfigError);
});

test("inspect a vector", () => {
  const i = svx.inspect(join(VECTORS, "valid-basic.svx"));
  assert.equal(i.sender_org, "acme-security");
  assert.equal(i.recipient_org, "example-corp");
  assert.equal(i.artifact_id, "3a167c54ea43dca97f767134638bec0b");
});

test("verify a vector", () => {
  const v = svx.verify(join(VECTORS, "valid-basic.svx"), [vectorTrust()]);
  assert.equal(v.chunk_count, 3);
});

for (const name of [
  "invalid-chunk-tampered",
  "invalid-signature-tampered",
  "invalid-policy-tampered",
  "invalid-truncated",
]) {
  test(`reject ${name}`, () => {
    assert.throws(
      () => svx.verify(join(VECTORS, `${name}.svx`), [vectorTrust()]),
      (e) => e instanceof svx.RejectedError && e instanceof svx.RefusedError && e.exitCode === 1,
    );
  });
}

test("missing file is a local error", () => {
  assert.throws(
    () => svx.inspect("/nonexistent/file.svx"),
    (e) => e instanceof svx.SvxError && !(e instanceof svx.RefusedError) && e.exitCode === 2,
  );
});

test("missing config", () => {
  assert.throws(() => svx.Client.load(join(tmp(), "nope.toml")), svx.ConfigError);
});
