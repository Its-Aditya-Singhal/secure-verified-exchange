// First run (and "Change setup"): service URL, registry key fingerprint, organization.
// Verification against the pinned registry key happens in Rust
// (svx_client::setup); Save verifies again before writing.

import { type SetupForm, type SetupPreview, api, asAppError } from "../api";
import { card, errorPanel, facts, note } from "../components";
import { busy, button, clear, field, h, icon } from "../dom";
import type { Ctx } from "../main";
import { onboardScreen } from "./onboard";

export function setupScreen(ctx: Ctx, root: HTMLElement, replace: boolean, initial?: SetupForm): void {
  // A registration in progress resumes where it stopped.
  if (ctx.state.prefs.pending_org) {
    onboardScreen(ctx, root, replace);
    return;
  }
  const service = h("input", { type: "url", placeholder: "https://svx.example.com", spellcheck: "false", autocomplete: "off" });
  const key = h("input", { type: "text", placeholder: "64 hex characters", spellcheck: "false", autocomplete: "off", class: "mono" });
  const org = h("input", { type: "text", placeholder: "e.g. example-corp", spellcheck: "false", autocomplete: "off" });
  const clientId = h("input", { type: "text", placeholder: "e.g. svx-desktop", spellcheck: "false", autocomplete: "off" });
  const dev = h("input", { type: "checkbox" });
  let outputDir: string | null = null;

  const fill = (f: SetupForm) => {
    service.value = f.service_url;
    key.value = f.registry_key;
    org.value = f.org_id;
    clientId.value = f.idp_client_id;
    dev.checked = f.dev;
    outputDir = f.default_output_dir;
  };
  if (initial) fill(initial);

  const form = (): SetupForm => ({
    service_url: service.value.trim(),
    registry_key: key.value.trim(),
    org_id: org.value.trim(),
    idp_client_id: clientId.value.trim(),
    dev: dev.checked,
    default_output_dir: outputDir,
  });

  const out = h("div", { class: "stack" });
  const verifyBtn = button("Verify", () => void verify(), "primary");
  const importBtn = button("Import config file…", () => void importFile());

  async function importFile() {
    const p = await api.pick("config").catch(() => null);
    if (!p) return;
    clear(out);
    try {
      fill(await api.readConfigFile(p));
      out.appendChild(note("Details imported. Verify them before saving.", "info"));
    } catch (e) {
      out.appendChild(errorPanel(asAppError(e)));
    }
  }

  async function verify() {
    clear(out);
    if (!service.value.trim() || !key.value.trim() || !org.value.trim() || !clientId.value.trim()) {
      out.appendChild(note("Fill in all four fields.", "warn"));
      return;
    }
    await busy(verifyBtn, "Verifying…", async () => {
      try {
        preview(await api.setupVerify(form()));
      } catch (e) {
        const err = asAppError(e);
        out.appendChild(
          errorPanel(
            err.kind === "other" || err.kind === "rejected"
              ? { ...err, kind: "config", message: `Couldn't verify with this registry key fingerprint: ${err.message}` }
              : err,
          ),
        );
      }
    });
  }

  function preview(p: SetupPreview) {
    const save = button("Save and continue", async () => {
      await busy(save, "Saving…", async () => {
        try {
          await api.setupSave(form(), replace);
          await ctx.refreshState();
          ctx.go("open");
          await ctx.pickUpPending();
        } catch (e) {
          clear(out);
          out.appendChild(errorPanel(asAppError(e)));
        }
      });
    }, "primary");
    out.appendChild(
      h("div", { class: "panel panel-ok" },
        h("div", { class: "panel-head" }, icon("ok"), h("h3", {}, "Verified with the registry key")),
        facts([
          ["Service", `${p.service_id} (${p.service_url})`],
          ["Your organization", `${p.org_display_name} (${p.org_id})`],
          ["Company sign-in", p.idp_issuer],
          ["Can receive files", p.can_receive ? "Yes" : "No (no key agent yet; you can still send)"],
        ]),
        h("div", { class: "actions" }, save),
      ),
    );
    save.focus();
  }

  root.append(
    h("header", { class: "screen-head" },
      h("h1", {}, replace ? "Change setup" : "Set up Secure Verified Exchange"),
      h("p", { class: "lede" },
        "Your administrator gives you these details. The registry key fingerprint is how the app knows it's talking to the real SVX service, so copy it exactly.")),
    h("div", { class: "panel panel-info" },
      h("p", {}, "Setting up SVX for a new organization? ",
        button("Register a new organization…", () => {
          clear(root);
          onboardScreen(ctx, root, replace);
        }, "link"))),
    card(
      null,
      field("SVX service URL", service),
      field("Registry key fingerprint", key, "Published by your SVX service. Every organization's keys are checked against the key it identifies."),
      h("div", { class: "grid2" },
        field("Your organization ID", org),
        field("Sign-in client ID", clientId, "The SVX app's client ID at your company login."),
      ),
      h("label", { class: "check" }, dev, h("span", {}, "Development mode (local test stack only: allows http and test users)")),
      h("div", { class: "actions" }, verifyBtn, importBtn,
        replace ? button("Cancel", () => ctx.go("settings"), "link") : null),
    ),
    out,
  );
}
