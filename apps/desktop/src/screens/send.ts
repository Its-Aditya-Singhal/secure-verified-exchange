// Protect & Send: pick a file or folder, choose the receiving organization
// (verified registry record), set options, produce a .svx file.

import { type PackResult, type Recipient, api, asAppError } from "../api";
import { card, dropZone, errorPanel, facts, note } from "../components";
import { baseName, busy, button, clear, field, fmtTime, h, icon, revealLabel } from "../dom";
import type { Ctx } from "../main";

const DAY = 86_400;
const EXPIRY: [string, number | null][] = [
  ["1 day", DAY],
  ["7 days", 7 * DAY],
  ["30 days", 30 * DAY],
  ["90 days", 90 * DAY],
  ["Never", null],
];
const CLASSIFICATIONS = ["", "TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"];

export function sendScreen(ctx: Ctx, root: HTMLElement): void {
  const prefs = ctx.state.prefs;
  let input: string | null = null;
  let recipient: Recipient | null = null;
  let signingKey: string | null = prefs.signing_key;

  const view = h("div", { class: "stack" });
  root.appendChild(view);

  // 1. What
  const chosen = h("div", { class: "chosen" });
  const what = card(
    "1. What do you want to protect?",
    dropZone("Drop a file or folder here", "Folders are packed into one file and unpacked again for the recipient.", [
      button("Choose file…", () => void pick("send_file"), "primary"),
      button("Choose folder…", () => void pick("send_folder")),
    ]),
    chosen,
  );
  const setInput = (p: string) => {
    input = p;
    clear(chosen);
    chosen.appendChild(note(`Selected: ${baseName(p)}`, "ok"));
    chosen.appendChild(h("p", { class: "muted mono small" }, p));
  };
  async function pick(kind: "send_file" | "send_folder") {
    const p = await api.pick(kind).catch(() => null);
    if (p) setInput(p);
  }

  // 2. Who
  const org = h("input", { type: "text", placeholder: "e.g. example-corp", autocomplete: "off", spellcheck: "false" });
  const orgResult = h("div", {});
  const checkBtn = button("Check", () => void lookup());
  async function lookup() {
    const id = org.value.trim();
    recipient = null;
    clear(orgResult);
    if (!id) return;
    await busy(checkBtn, "Checking…", async () => {
      try {
        const r = await api.recipient(id);
        recipient = r;
        orgResult.appendChild(
          r.can_receive
            ? h("div", { class: "recipient" }, icon("ok"),
                h("div", {}, h("strong", {}, r.display_name), h("span", { class: "muted" }, ` · ${r.domain} · verified by the registry`)))
            : note(`${r.display_name} is registered but can't receive files yet (no key agent).`, "warn"),
        );
        if (!r.can_receive) recipient = null;
      } catch (e) {
        const err = asAppError(e);
        orgResult.appendChild(
          note(err.kind === "unavailable" ? "Can't reach the SVX service. Try again." : `No verified organization "${id}".`, "stop"),
        );
      }
    });
  }
  org.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") void lookup();
  });
  org.addEventListener("change", () => void lookup());
  const recents = prefs.recent_recipients.length
    ? h("div", { class: "chips" }, h("span", { class: "muted small" }, "Recent:"),
        ...prefs.recent_recipients.map((r) =>
          h("button", { type: "button", class: "chip", onclick: () => { org.value = r; void lookup(); } }, r)))
    : null;
  const who = card(
    "2. Which organization receives it?",
    h("div", { class: "row" }, field("Organization ID", org), checkBtn),
    h("span", { class: "field-hint" }, "Ask the recipient for their SVX organization ID."),
    recents,
    orgResult,
  );

  // 3. Options
  const policy = h("input", { type: "text", value: prefs.last_policy ?? "", placeholder: "e.g. incident-response", spellcheck: "false" });
  const expiry = h("select", {}, ...EXPIRY.map(([label], i) => h("option", { value: String(i), selected: i === 1 }, label)));
  const classification = h("select", {}, ...CLASSIFICATIONS.map((c) => h("option", { value: c }, c || "None")));
  const description = h("input", { type: "text", placeholder: "Optional note shown to the recipient after opening", maxlength: "500" });
  const register = h("input", { type: "checkbox" });
  const keyText = (k: string | null) =>
    !k ? "No key chosen"
      : k.startsWith("keychain:") ? `This computer's keychain key (${k.split("/").pop()?.slice(0, 12)}…)`
      : k;
  const keyLabel = h("span", { class: "mono small" }, keyText(signingKey));
  const opts = card(
    "3. Options",
    h("div", { class: "grid2" },
      field("Recipient policy", policy, "The recipient organization's policy that decides who may open it."),
      field("Expires after", expiry),
      field("Classification", classification),
      field("Note", description),
    ),
    field(
      "Your organization's signing key",
      h("div", { class: "row" }, keyLabel, button("Choose…", async () => {
        const p = await api.pick("signing_key").catch(() => null);
        if (p) {
          signingKey = p;
          keyLabel.textContent = keyText(p);
        }
      })),
      "Your keychain key (created on the Admin page), or a .sign.key file. Only a reference is remembered, never the key.",
    ),
    h("label", { class: "check" }, register, h("span", {}, "Record this file with the SVX service (needs administrator sign-in on the Admin page)")),
  );

  // Go
  const result = h("div", { class: "stack" });
  const go = button("Protect file", () => void protect(), "primary");
  async function protect() {
    clear(result);
    const problems: string[] = [];
    if (!input) problems.push("choose a file or folder");
    if (!recipient) problems.push("choose a verified recipient organization");
    if (!policy.value.trim()) problems.push("enter the recipient policy");
    if (!signingKey) problems.push("choose your signing key");
    if (problems.length) {
      result.appendChild(note(`To continue, ${problems.join(", ")}.`, "warn"));
      return;
    }
    const ttl = EXPIRY[Number(expiry.value)][1];
    await busy(go, "Protecting…", async () => {
      try {
        const r = await api.send({
          input: input!,
          recipient: recipient!.org_id,
          policy: policy.value.trim(),
          expires_at: ttl === null ? null : Math.floor(Date.now() / 1000) + ttl,
          classification: classification.value || null,
          description: description.value.trim() || null,
          signing_key: signingKey!,
          register: register.checked,
        });
        await ctx.refreshState();
        done(r, recipient!);
      } catch (e) {
        result.appendChild(errorPanel(asAppError(e)));
      }
    });
  }

  function done(r: PackResult, to: Recipient) {
    clear(view);
    view.appendChild(
      h("div", { class: "panel panel-ok", role: "status" },
        h("div", { class: "panel-head" }, icon("ok"), h("h3", {}, "Protected and ready to send")),
        facts([
          ["File", baseName(r.path)],
          ["For", `${to.display_name} (${r.recipient_org})`],
          ["Policy", r.policy],
          ["Expires", fmtTime(r.expires_at)],
          ["Protection", r.protection],
          ["Recorded with service", r.registered ? "Yes" : "No"],
          ["Artifact ID", h("span", { class: "mono" }, r.artifact_id)],
        ]),
        h("p", {}, `Send ${baseName(r.path)} any way you like: email, chat or a file share. Only people at ${to.display_name} whom their policy allows can open it, after signing in.`),
        h("div", { class: "actions" },
          button(revealLabel(), () => void api.reveal(r.path), "primary"),
          button("Protect another", () => ctx.go("send"))),
      ),
    );
  }

  view.append(
    h("header", { class: "screen-head" }, h("h1", {}, "Protect & send"),
      h("p", { class: "lede" }, "Encrypt a file or folder so only the organization you choose can open it.")),
    what, who, opts,
    h("div", { class: "actions actions-end" }, go),
    result,
  );

  ctx.onFiles = (paths) => {
    if (paths.length) setInput(paths[0]);
  };
}
