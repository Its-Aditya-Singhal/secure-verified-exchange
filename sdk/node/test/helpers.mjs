// Shared test helpers: start `svx-demo serve` against SVX_TEST_DATABASE_URL
// (the variable the Rust and Python tests use).
import { spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
export const VECTORS = join(REPO, "test-vectors", "v1");

export function tmp() {
  return mkdtempSync(join(tmpdir(), "svx-node-test-"));
}

function demoBinary() {
  if (process.env.SVX_DEMO_BIN) return process.env.SVX_DEMO_BIN;
  const exe = process.platform === "win32" ? "svx-demo.exe" : "svx-demo";
  const p = join(REPO, "target", "debug", exe);
  if (!existsSync(p)) {
    const r = spawnSync("cargo", ["build", "-q", "-p", "svx-demo"], { cwd: REPO, stdio: "inherit" });
    if (r.status !== 0) throw new Error("building svx-demo failed");
  }
  return p;
}

/** Start the stack, or return null (test skipped) without a database. */
export async function startStack() {
  const url = process.env.SVX_TEST_DATABASE_URL;
  if (!url) {
    if (process.env.SVX_REQUIRE_DB) {
      throw new Error("SVX_TEST_DATABASE_URL must be set when SVX_REQUIRE_DB is set");
    }
    return null;
  }
  const dir = tmp();
  const proc = spawn(demoBinary(), ["--database-url", url, "serve", "--state-dir", dir], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  proc.stdout.on("data", (d) => (log += d));
  proc.stderr.on("data", (d) => (log += d));
  const deadline = Date.now() + 60_000;
  while (!existsSync(join(dir, "state.json"))) {
    if (proc.exitCode !== null) throw new Error(`svx-demo serve exited:\n${log}`);
    if (Date.now() > deadline) throw new Error(`svx-demo serve did not start:\n${log}`);
    await new Promise((r) => setTimeout(r, 200));
  }
  const state = JSON.parse(readFileSync(join(dir, "state.json"), "utf8"));
  state.dir = dir;
  state.stop = () =>
    new Promise((res) => {
      proc.once("exit", res);
      proc.kill("SIGTERM");
    });
  return state;
}

/** A private copy of an org's config (own directory → own session cache). */
export function configFor(state, orgId) {
  const org = state.orgs.find((o) => o.org_id === orgId);
  const d = join(tmp(), orgId);
  mkdirSync(d);
  const dst = join(d, "config.toml");
  cpSync(org.config, dst);
  return dst;
}
