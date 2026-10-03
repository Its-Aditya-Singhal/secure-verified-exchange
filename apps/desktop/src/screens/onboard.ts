// Register a new organization: details → DNS record → sign in (first
// administrator) → create keys. Registration, verification and key
// creation all happen in Rust (svx_client::onboard, keyadmin).

import { type OnboardRequest, type PendingOrg, api, asAppError } from "../api";
import { card, errorPanel, facts, note } from "../components";
import { busy, button, clear, field, h, icon } from "../dom";
import type { Ctx } from "../main";

function copyButton(text: string): HTMLButtonElement {
  const b = button("Copy", async () => {
    try {
      await navigator.clipboard.writeText(text);
      b.textContent = "Copied";
      setTimeout(() => (b.textContent = "Copy"), 1500);
    } catch {
      b.textContent = "Select and copy";
    }
  });
  return b;
}

function steps(current: number): HTMLElement {
  const names = ["Details", "Prove your domain", "Sign in", "Keys"];
  return h("ol", { class: "wizard" },
    ...names.map((n, i) =>
      h("li", { class: i < current ? "is-done" : i === current ? "is-active" : "" }, n)));
}

export function onboardScreen(ctx: Ctx, root: HTMLElement, replace: boolean): void {
  const pending = ctx.state.prefs.pending_org;
  if (pending) dnsStep(ctx, root, pending, replace);
  else detailsStep(ctx, root, replace);
}

function detailsStep(ctx: Ctx, root: HTMLElement, replace: boolean): void {
  clear(root);
  const input = (placeholder: string, extra: Record<string, string> = {}) =>
    h("input", { type: "text", placeholder, spellcheck: "false", autocomplete: "off", ...extra });
  const service = input("https://svx.example.com", { type: "url" });
  const key = input("64 hex characters", { class: "mono" });
  const name = input("e.g. Example Labs");
  const org = input("e.g. example-labs");
  const domain = input("e.g. example-labs.example");
  const issuer = input("https://login.example-labs.example", { type: "url" });
  const clientId = input("e.g. svx-desktop");
  const agent = input("https://svx-agent.example-labs.example (optional)", { type: "url" });
  const dev = h("input", { type: "checkbox" });

  // Suggest an ID from the name.
  name.addEventListener("input", () => {
    if (!org.dataset.touched) {
      org.value = name.value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 63);
    }
  });
  org.addEventListener("input", () => (org.dataset.touched = "1"));

  const out = h("div", { class: "stack" });
  const go = button("Register", async () => {
    clear(out);
    const req: OnboardRequest = {
      service_url: service.value.trim(),
      registry_key: key.value.trim(),
      org_id: org.value.trim(),
      display_name: name.value.trim(),
      domain: domain.value.trim().toLowerCase(),
      idp_issuer: issuer.value.trim(),
      idp_client_id: clientId.value.trim(),
      group_claim: null,
      key_agent_url: agent.value.trim() || null,
      dev: dev.checked,
      default_output_dir: null,
    };
    const missing = Object.entries(req).filter(
      ([k, v]) => typeof v === "string" && !v && k !== "key_agent_url",
    );
    if (missing.length) {
      out.appendChild(note("Fill in every field (the key agent is optional).", "warn"));
      return;
    }
    await busy(go, "Registering…", async () => {
      try {
        const p = await api.onboardRegister(req);
        await ctx.refreshState();
        dnsStep(ctx, root, p, replace);
      } catch (e) {
        out.appendChild(errorPanel(asAppError(e)));
      }
    });
  }, "primary");

  root.append(
    h("header", { class: "screen-head" },
      h("h1", {}, "Register a new organization"),
      h("p", { class: "lede" },
        "You'll prove that your organization controls its domain and its company sign-in. The person who signs in at the end becomes its first administrator.")),
    steps(0),
    card(
      "SVX service",
      field("SVX service URL", service),
      field("Registry key fingerprint", key, "Published by the SVX service. The app checks the service's post-quantum registry key against it before sending anything."),
    ),
    card(
      "Your organization",
      h("div", { class: "grid2" },
        field("Name", name),
        field("Organization ID", org, "Lowercase letters, digits and dashes. Others use it to send you files."),
        field("Domain", domain, "You'll add a DNS record to it."),
        field("Key agent URL", agent, "Needed to receive files. You can add it later."),
      ),
    ),
    card(
      "Company sign-in",
      h("div", { class: "grid2" },
        field("Sign-in issuer URL", issuer, "Your identity provider (Entra ID, Okta, Google…)."),
        field("Client ID", clientId, "The SVX app registered at your identity provider."),
      ),
      h("label", { class: "check" }, dev, h("span", {}, "Development mode (local test stack only)")),
    ),
    h("div", { class: "actions" }, go,
      button("Back", () => ctx.go("setup", { replace }), "link")),
    out,
  );
}

function dnsStep(ctx: Ctx, root: HTMLElement, p: PendingOrg, replace: boolean): void {
  clear(root);
  const devUser = h("input", { type: "text", placeholder: "first administrator's test user", spellcheck: "false" });
  const out = h("div", { class: "stack" });
  const verify = button("Verify and sign in", async () => {
    clear(out);
    await busy(verify, "Waiting for sign-in…", async () => {
      try {
        await api.onboardComplete(p.request.dev ? devUser.value.trim() || null : null, replace);
        await ctx.refreshState();
        keysStep(ctx, root);
      } catch (e) {
        const err = asAppError(e);
        out.appendChild(errorPanel(
          err.kind === "invalid" && /DNS/.test(err.message)
            ? { ...err, message: "The DNS record wasn't found yet. DNS changes can take a while; try again in a few minutes." }
            : err,
        ));
      }
    });
  }, "primary");

  root.append(
    h("header", { class: "screen-head" },
      h("h1", {}, `Prove ${p.request.domain} is yours`),
      h("p", { class: "lede" }, "Ask whoever manages your domain to add this TXT record, then verify. You can close the app and come back; this step is remembered.")),
    steps(1),
    card(
      "DNS record",
      facts([
        ["Type", "TXT"],
        ["Name", h("span", { class: "row" }, h("span", { class: "mono" }, p.txt_name), copyButton(p.txt_name))],
        ["Value", h("span", { class: "row" }, h("span", { class: "mono" }, p.txt_value), copyButton(p.txt_value))],
      ]),
    ),
    card(
      "Then sign in",
      h("p", {}, `Your browser opens ${p.request.idp_issuer}. Sign in as the person who will administer ${p.request.display_name} in SVX.`),
      p.request.dev ? field("Test user", devUser) : null,
      h("div", { class: "actions" }, verify,
        button("Start over", async () => {
          await api.onboardCancel().catch(() => undefined);
          await ctx.refreshState();
          detailsStep(ctx, root, replace);
        }, "link")),
      out,
    ),
  );
}

function keysStep(ctx: Ctx, root: HTMLElement): void {
  clear(root);
  const out = h("div", { class: "stack" });
  const create = button("Create this computer's signing key", async () => {
    clear(out);
    await busy(create, "Creating…", async () => {
      try {
        const k = await api.createSigningKey();
        await ctx.refreshState();
        out.appendChild(note(`Signing key ${k.key_id.slice(0, 12)}… created in this computer's keychain and registered.`, "ok"));
        create.disabled = true;
      } catch (e) {
        out.appendChild(errorPanel(asAppError(e)));
      }
    });
  }, "primary");
  root.append(
    h("header", { class: "screen-head" },
      h("h1", {}, `Welcome, ${ctx.state.org_id ?? ""} is verified`),
      h("p", { class: "lede" }, "You're its first administrator. One last step lets you send files.")),
    steps(3),
    card(
      "Signing key",
      h("p", {}, "Files you send are signed with a post-quantum key (Ed25519 + ML-DSA-65) kept in this computer's keychain. It never leaves this device."),
      h("div", { class: "actions" }, create),
      out,
    ),
    card(
      "Receiving files",
      h("p", { class: "muted" }, "To receive files, your IT team runs the SVX key agent (see the key agent guide), then you add its URL and encryption key on the Admin page."),
      h("p", {}, icon("info"), " You can do this later."),
    ),
    h("div", { class: "actions" }, button("Done", () => ctx.go("admin"), "primary")),
  );
}
