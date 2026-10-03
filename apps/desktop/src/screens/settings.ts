// Settings: current setup, output folder, change setup.

import { api, asAppError } from "../api";
import { card, errorPanel, facts, note } from "../components";
import { button, clear, h } from "../dom";
import type { Ctx } from "../main";

export function settingsScreen(ctx: Ctx, root: HTMLElement): void {
  const s = ctx.state;
  const out = h("div", {});
  const keyOut = h("div", {});

  async function changeOutput() {
    const dir = await api.pick("output_dir").catch(() => null);
    if (!dir) return;
    clear(out);
    try {
      // Re-saving goes through the same verification as first setup.
      const form = await api.readConfigFile(s.config_path);
      await api.setupSave({ ...form, default_output_dir: dir }, true);
      await ctx.refreshState();
      ctx.go("settings");
    } catch (e) {
      out.appendChild(errorPanel(asAppError(e)));
    }
  }

  async function changeSetup() {
    try {
      ctx.go("setup", { replace: true, form: await api.readConfigFile(s.config_path) });
    } catch {
      ctx.go("setup", { replace: true });
    }
  }

  root.append(
    h("header", { class: "screen-head" }, h("h1", {}, "Settings")),
    card(
      "Setup",
      facts([
        ["Organization", s.org_id ?? "–"],
        ["SVX service", s.service_url ?? "–"],
        ["Company sign-in", s.idp_issuer ?? "–"],
        ["Configuration file", h("span", { class: "mono small" }, s.config_path)],
      ]),
      s.dev ? note("Development mode is on: http and test users are allowed. Never use this with real data.", "warn") : null,
      h("div", { class: "actions" }, button("Change setup…", () => void changeSetup())),
    ),
    card(
      "Opened files",
      facts([["Saved to", h("span", { class: "mono small" }, s.output_dir ?? "–")]]),
      h("p", { class: "muted" }, "Opened files are private to your user account and never replace an existing file."),
      h("div", { class: "actions" }, button("Change folder…", () => void changeOutput())),
      out,
    ),
    card(
      "Signing key",
      facts([["Used for sending", h("span", { class: "mono small" }, s.prefs.signing_key ?? "None yet")]]),
      h("p", { class: "muted" }, "Keys kept in this computer's keychain can't be copied off it as a file. You can move an existing .sign.key file into the keychain; delete the file afterwards."),
      h("div", { class: "actions" }, button("Move a key file into the keychain…", async () => {
        clear(keyOut);
        try {
          const k = await api.importSigningKey();
          if (k) {
            await ctx.refreshState();
            ctx.go("settings");
          }
        } catch (e) {
          keyOut.appendChild(errorPanel(asAppError(e)));
        }
      })),
      keyOut,
    ),
    card(
      "About",
      h("p", {}, "Secure Verified Exchange 0.1.0. All checks, sign-in binding and decryption run in the SVX client library on this device; this window only shows the results."),
      h("p", { class: "muted small" }, "The svx command-line tool uses the same setup and sign-in session."),
    ),
  );
}
