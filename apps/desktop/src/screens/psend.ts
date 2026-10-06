// Send (personal accounts): a file or folder, recipients by email (each
// checked in the signed directory, in Rust), and the rules the sender keeps
// control of after sending.

import { type Contact, type SendResult, type ViewCheck, api, asAppError } from "../api";
import { card, dropZone, errorPanel, facts, note } from "../components";
import { baseName, busy, button, clear, field, fmtTime, h, icon, revealLabel } from "../dom";
import type { Ctx } from "../main";

const DAY = 86_400;
const EXPIRY: [string, number | null][] = [
  ["Never", null],
  ["1 day", DAY],
  ["7 days", 7 * DAY],
  ["30 days", 30 * DAY],
];

interface Chip {
  email: string;
  contact: Contact | null;
  problem: string | null;
  el: HTMLElement;
}

export function personalSendScreen(ctx: Ctx, root: HTMLElement, arg: { to?: string[] } | null): void {
  let input: string | null = null;
  const chips: Chip[] = [];
  // Problems with the user's own account (not with a recipient) show here.
  const accountProblem = h("div", {});
  const view = h("div", { class: "stack" });
  root.appendChild(view);

  // 1. What
  const chosen = h("div", { class: "chosen" });
  const setInput = (p: string) => {
    input = p;
    clear(chosen);
    chosen.append(note(`Selected: ${baseName(p)}`, "ok"), h("p", { class: "muted mono small" }, p));
    void checkView(p);
  };
  const pick = async (kind: "send_file" | "send_folder") => {
    const p = await api.pick(kind).catch(() => null);
    if (p) setInput(p);
  };
  const what = card(
    "What do you want to send?",
    dropZone("Drop a file or folder here", "It's encrypted on this computer before it goes anywhere.", [
      button("Choose file…", () => void pick("send_file"), "primary"),
      button("Choose folder…", () => void pick("send_folder")),
    ]),
    chosen,
  );

  // 2. Who
  const chipBox = h("div", { class: "chips email-chips" });
  const email = h("input", { type: "email", placeholder: "name@example.com", autocomplete: "off", spellcheck: "false" });
  const renderChip = (c: Chip) => {
    const state = c.contact ? icon("ok") : c.problem ? icon("stop") : h("span", { class: "spinner", "aria-hidden": "true" });
    const remove = h("button", { type: "button", class: "chip-x", "aria-label": `Remove ${c.email}` }, "×");
    remove.addEventListener("click", () => {
      chips.splice(chips.indexOf(c), 1);
      c.el.remove();
    });
    const el = h("span", { class: `chip chip-email${c.problem ? " is-bad" : ""}`, title: c.problem ?? (c.contact ? "Verified account" : "Checking…") },
      state, c.email, remove);
    c.el.replaceWith(el);
    c.el = el;
  };
  const add = (raw: string) => {
    for (const part of raw.split(/[\s,;]+/)) {
      const e = part.trim();
      if (!e) continue;
      if (chips.some((c) => c.email.toLowerCase() === e.toLowerCase())) continue;
      const c: Chip = { email: e, contact: null, problem: null, el: h("span", {}) };
      chips.push(c);
      chipBox.appendChild(c.el);
      renderChip(c);
      api.lookup(e).then(
        (contact) => { c.contact = contact; renderChip(c); },
        (err) => {
          const x = asAppError(err);
          if (x.kind === "suspended" && !accountProblem.firstChild) accountProblem.appendChild(errorPanel(x));
          c.problem = x.kind === "suspended" ? "Couldn't check: your own account is suspended"
            : x.kind === "invalid" ? x.message : x.kind === "config" ? "Not an email address" : "Couldn't check right now";
          renderChip(c);
        },
      );
    }
    email.value = "";
  };
  email.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" || ev.key === "," || ev.key === " ") {
      ev.preventDefault();
      add(email.value);
    } else if (ev.key === "Backspace" && !email.value && chips.length) {
      chips.pop()!.el.remove();
    }
  });
  // Pasted or typed lists: split on spaces, commas and semicolons.
  email.addEventListener("input", () => {
    if (/[\s,;]/.test(email.value)) add(email.value);
  });
  email.addEventListener("blur", () => add(email.value));
  for (const e of arg?.to ?? []) add(e);
  const who = card(
    "Who can open it?",
    accountProblem,
    field("Email addresses", h("div", { class: "email-input" }, chipBox, email),
      "Press Enter after each one. They need an SVX account; the app checks each address and finds their keys."),
  );

  // 3. Rules
  const approval = h("input", { type: "checkbox", checked: true });
  const oneTime = h("input", { type: "checkbox", checked: true });
  const expiry = h("select", {}, ...EXPIRY.map(([label], i) => h("option", { value: String(i) }, label)));
  // View only: shown in the app, never saved. Whether this file can be, comes from Rust.
  const viewOnly = h("input", { type: "checkbox", disabled: true });
  const viewHint = h("span", { class: "muted small" }, "Choose a file first.");
  const keepCopy = h("input", { type: "checkbox", disabled: true });
  const keepRow = h("label", { class: "toggle toggle-sub" }, keepCopy,
    h("span", {}, h("strong", {}, "Let them ask to keep a copy"),
      h("span", { class: "muted small" }, "They can ask in the viewer; you decide under Requests. If you allow it, they can save the file, and that can't be taken back.")));
  const viewWarn = h("div", {});
  let viewState: ViewCheck | null = null;
  let checkSeq = 0;
  const syncView = () => {
    keepCopy.disabled = !viewOnly.checked;
    if (!viewOnly.checked) keepCopy.checked = false;
    keepRow.hidden = !viewOnly.checked;
    clear(viewWarn);
    if (viewOnly.checked && oneTime.checked && keepCopy.checked) {
      viewWarn.appendChild(note(
        "With one-time on, someone who has viewed the file once can't save a copy afterwards, even if you allow it. " +
          "Turn one-time off if they should be able to ask later.", "warn"));
    }
  };
  async function checkView(p: string) {
    const seq = ++checkSeq;
    viewHint.textContent = "Checking…";
    viewOnly.disabled = true;
    viewOnly.checked = false;
    try {
      const c = await api.viewCheck(p);
      if (seq !== checkSeq) return;
      viewState = c;
      viewOnly.disabled = !c.ok;
      viewHint.textContent = c.ok
        ? c.office
          ? "They view it in this app but can't save, copy or print it. It's turned into a PDF on this computer for viewing; if you let them keep a copy, they get your original."
          : "They view it in this app but can't save, copy or print it."
        : c.reason ?? "This file can't be sent view-only.";
    } catch {
      if (seq !== checkSeq) return;
      viewHint.textContent = "This file can't be checked right now.";
    }
    syncView();
  }
  viewOnly.addEventListener("change", syncView);
  keepCopy.addEventListener("change", syncView);
  keepRow.hidden = true;

  const rules = card(
    "Your controls",
    h("label", { class: "toggle" }, approval,
      h("span", {}, h("strong", {}, "Ask me before each open"),
        h("span", { class: "muted small" }, "You get a request in this app and by email, and approve it here. Check it's really them first."))),
    h("label", { class: "toggle" }, oneTime,
      h("span", {}, h("strong", {}, "One-time"),
        h("span", { class: "muted small" }, "Each person can open it once. The same .svx file won't open again for them."))),
    h("label", { class: "toggle" }, viewOnly,
      h("span", {}, h("strong", {}, "View only"), viewHint)),
    keepRow,
    viewWarn,
    h("p", { class: "muted small" },
      "View only stops saving, copying, printing and screenshots inside the SVX app. It can't stop someone photographing their screen, and it needs a Mac or Windows computer to view."),
    field("Stops opening after", expiry, "You can also revoke it or bring the date forward later, from History."),
  );
  oneTime.addEventListener("change", syncView);

  // Go
  const result = h("div", { class: "stack" });
  const go = button("Encrypt and send", () => void send(), "primary");
  async function send() {
    clear(result);
    add(email.value);
    const problems: string[] = [];
    if (!input) problems.push("choose a file or folder");
    if (!chips.length) problems.push("add at least one email address");
    if (chips.some((c) => c.problem)) problems.push("remove the addresses marked in red");
    if (problems.length) {
      result.appendChild(note(`To continue, ${problems.join(", ")}.`, "warn"));
      return;
    }
    const ttl = EXPIRY[Number(expiry.value)][1];
    await busy(go, "Encrypting…", async () => {
      try {
        const r = await api.sendPersonal({
          input: input!,
          to: chips.map((c) => c.email),
          require_approval: approval.checked,
          one_time: oneTime.checked,
          expires_at: ttl === null ? null : Math.floor(Date.now() / 1000) + ttl,
          view_only: viewOnly.checked && viewState?.ok === true,
          allow_share_requests: viewOnly.checked && keepCopy.checked,
        });
        done(r);
      } catch (e) {
        result.appendChild(errorPanel(asAppError(e)));
      }
    });
  }

  function done(r: SendResult) {
    clear(view);
    const people = r.recipients.map((c) => c.email).join(", ");
    view.appendChild(
      h("div", { class: "panel panel-ok", role: "status" },
        h("div", { class: "panel-head" }, icon("ok"), h("h3", {}, "Encrypted and ready to share")),
        facts([
          ["File", baseName(r.path)],
          ["For", people],
          ["Ask me before each open", r.rules.require_approval ? "Yes" : "No"],
          ["One-time", r.rules.one_time ? "Yes" : "No"],
          ...(r.rules.view_only
            ? ([["View only", r.rules.allow_share_requests ? "Yes, they can ask to keep a copy" : "Yes"]] as [string, string][])
            : []),
          ["Stops opening", r.expires_at ? fmtTime(r.expires_at) : "Never (you can revoke it)"],
          ["Protection", r.protection],
        ]),
        h("p", {}, `Now share ${baseName(r.path)} any way you like: email, chat, a USB stick. It's useless to anyone but ${people}, and you can change the rules or revoke it from History.`),
        h("div", { class: "actions" },
          button(revealLabel(), () => void api.reveal(r.path), "primary"),
          button("See it in History", () => ctx.go("file", r.artifact_id)),
          button("Send another", () => ctx.go("send"))),
      ),
    );
  }

  view.append(
    h("header", { class: "screen-head" }, h("h1", {}, "Send securely"),
      h("p", { class: "lede" }, "Encrypt a file or folder for specific people. Only they can open it, and only while you allow it.")),
    what, who, rules,
    h("div", { class: "actions actions-end" }, go),
    result,
  );

  ctx.onFiles = (paths) => {
    if (paths.length) setInput(paths[0]);
  };
}
