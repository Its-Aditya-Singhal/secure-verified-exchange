// Open: a .svx file arrives (double-click, drop, picker). Verify it without
// signing in, then run the full open flow with a live timeline.

import { listen } from "@tauri-apps/api/event";
import { type AppError, type OpenResult, type Progress, type StatusView, api, asAppError } from "../api";
import { card, dropZone, errorPanel, facts, note, retryButton } from "../components";
import { baseName, button, clear, field, fmtSize, fmtTime, h, icon, revealLabel } from "../dom";
import type { Ctx } from "../main";

const STEPS: { step: string; label: string; hint?: string }[] = [
  { step: "verifying", label: "Checking the file" },
  { step: "signature_valid", label: "Sender's signature verified" },
  { step: "connecting", label: "Connecting to the SVX service" },
  { step: "authenticating", label: "Signing you in", hint: "Finish signing in in your browser, then come back here." },
  { step: "checking_authorization", label: "Checking you're allowed to open it" },
  { step: "access_approved", label: "Access approved" },
  { step: "decrypting", label: "Decrypting on this device" },
];

export function openScreen(ctx: Ctx, root: HTMLElement, initialPath: string | null): void {
  const view = h("div", { class: "stack" });
  root.appendChild(view);

  const show = (...nodes: (Node | null)[]) => {
    clear(view);
    for (const n of nodes) if (n) view.appendChild(n);
  };

  const pickAndCheck = async () => {
    const p = await api.pick("artifact").catch(() => null);
    if (p) void check(p);
  };

  const idle = () =>
    show(
      h("header", { class: "screen-head" }, h("h1", {}, "Open a secure file"), h("p", { class: "lede" },
        "Double-click any .svx file, drop it here, or choose it. The file is checked before you're asked to sign in.")),
      dropZone("Drop an .svx file here", "Files you open are saved to " + (ctx.state.output_dir ?? "your SVX folder"), [
        button("Choose file…", () => void pickAndCheck(), "primary"),
      ]),
    );

  const refused = (path: string, e: AppError) =>
    show(
      fileHeader(path),
      errorPanel(e, [
        ...(e.kind === "unavailable" ? [retryButton(() => void check(path))] : []),
        button("Open another file", idle),
      ]),
    );

  async function check(path: string) {
    show(fileHeader(path), note("Checking the file against the registry…", "info"));
    let s: StatusView;
    try {
      s = await api.status(path);
    } catch (e) {
      refused(path, asAppError(e));
      return;
    }
    if (!s.for_you) {
      refused(path, {
        kind: "not_recipient",
        message: `this artifact is addressed to ${s.recipient_org}, not to your organization (${s.my_org})`,
        deny_reason: null,
        exit_code: 1,
        path: null,
      });
      return;
    }
    if (s.expired) {
      refused(path, { kind: "expired", message: "artifact expired", deny_reason: null, exit_code: 1, path: null });
      return;
    }
    ready(path, s);
  }

  function ready(path: string, s: StatusView) {
    const devUser = h("input", { type: "text", placeholder: "alice", autocomplete: "off", spellcheck: "false" });
    const openBtn = button("Open securely", () => void run(path, s, null, devUser.value.trim() || null), "primary");
    show(
      fileHeader(path),
      card(
        null,
        facts([
          ["From", h("span", {}, s.sender_org, " ", h("span", { class: "badge badge-ok" }, icon("ok"), "signature verified"))],
          ["To", `${s.recipient_org} (your organization)`],
          ["Sent", fmtTime(s.created_at)],
          ["Expires", fmtTime(s.expires_at)],
          ["Policy", s.policy],
          ["Protection", s.post_quantum
            ? h("span", {}, h("span", { class: "badge badge-ok" }, icon("ok"), "post-quantum"), " ", s.protection)
            : h("span", {}, h("span", { class: "badge badge-warn" }, "classical"), " ", s.protection)],
        ]),
        h("p", { class: "muted" },
          ctx.state.dev
            ? "Development mode: sign in as a test user of your organization."
            : "Next, your browser opens your company sign-in. The file is decrypted only if your organization allows it."),
        ctx.state.dev ? field("Test user", devUser, "Dev stack users: alice (allowed), bob (not allowed)") : null,
        h("div", { class: "actions" }, openBtn, button("Cancel", idle)),
      ),
    );
    if (!ctx.state.dev) openBtn.focus();
    else devUser.focus();
    devUser.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") openBtn.click();
    });
  }

  async function run(path: string, s: StatusView, outputDir: string | null, devUser: string | null) {
    const items = STEPS.map((st) =>
      h("li", { class: "step is-pending", "data-step": st.step },
        h("span", { class: "step-mark", "aria-hidden": "true" }),
        h("span", { class: "step-text" }, h("span", { class: "step-label" }, st.label),
          st.hint && !ctx.state.dev ? h("span", { class: "step-hint" }, st.hint) : null)),
    );
    const timeline = h("ol", { class: "timeline", "aria-live": "polite" }, ...items);
    const below = h("div", { class: "stack" });
    show(fileHeader(path), card(null, timeline), below);

    let current = 0;
    const mark = (index: number, sender: string | null) => {
      current = index;
      items.forEach((li, i) => {
        li.classList.remove("is-pending", "is-active", "is-done");
        li.classList.add(i + 1 < index ? "is-done" : i + 1 === index ? "is-active" : "is-pending");
      });
      if (sender) {
        const label = items[1].querySelector(".step-label");
        if (label) label.textContent = `Sender's signature verified (${sender})`;
      }
    };
    const unlisten = await listen<Progress>("open-progress", (ev) => mark(ev.payload.index, ev.payload.sender));
    try {
      const r = await api.open(path, outputDir, devUser);
      items.forEach((li) => {
        li.classList.remove("is-pending", "is-active");
        li.classList.add("is-done");
      });
      append(below, opened(r));
    } catch (err) {
      const e = asAppError(err);
      const failed = items[Math.max(0, current - 1)];
      failed.classList.remove("is-active");
      failed.classList.add("is-failed");
      const actions: HTMLElement[] = [];
      if (e.kind === "output_exists") {
        actions.push(
          button("Choose another folder…", async () => {
            const d = await api.pick("output_dir").catch(() => null);
            if (d) void run(path, s, d, devUser);
          }, "primary"),
        );
      } else if (explainRetry(e)) {
        actions.push(retryButton(() => ready(path, s)));
      }
      actions.push(button("Open another file", idle));
      append(below, errorPanel(e, actions));
    } finally {
      unlisten();
    }
  }

  function opened(r: OpenResult): HTMLElement {
    const reveal = button(revealLabel(), () => void api.reveal(r.path), r.can_open ? "secondary" : "primary");
    const openBtn = r.can_open ? button("Open", () => void api.openDocument(r.path), "primary") : null;
    return h(
      "div",
      { class: "panel panel-ok", role: "status" },
      h("div", { class: "panel-head" }, icon("ok"), h("h3", {}, r.is_folder ? "Folder opened" : "File opened")),
      facts([
        [r.is_folder ? "Folder" : "File", r.name],
        ["Size", fmtSize(r.size)],
        ["From", r.sender_org],
        ...(r.classification ? [["Classification", r.classification] as [string, string]] : []),
        ...(r.description ? [["Note", r.description] as [string, string]] : []),
        ["Saved to", h("span", { class: "mono" }, r.path)],
      ]),
      r.can_open || r.is_folder
        ? null
        : h("p", { class: "muted" }, "This kind of file isn't opened automatically. Use " + revealLabel() + " and open it yourself if you trust it."),
      h("div", { class: "actions" }, openBtn, reveal, button("Open another file", idle)),
    );
  }

  if (initialPath) void check(initialPath);
  else idle();

  ctx.onFiles = (paths) => {
    if (paths.length) void check(paths[0]);
  };
}

function explainRetry(e: AppError): boolean {
  return e.kind === "unavailable" || e.kind === "login" || e.kind === "other";
}

function fileHeader(path: string): HTMLElement {
  return h(
    "header",
    { class: "screen-head file-head" },
    h("div", { class: "file-icon", "aria-hidden": "true" }, "SVX"),
    h("div", {}, h("h1", {}, baseName(path)), h("p", { class: "muted mono small" }, path)),
  );
}

function append(parent: HTMLElement, child: HTMLElement) {
  parent.appendChild(child);
}
