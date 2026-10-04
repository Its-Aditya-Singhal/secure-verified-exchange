// History: files I sent and files sent to me, with who and when. File
// names come from this computer only; the service never has them.

import { type HistoryView, type RecipientState, type SentFile, api, asAppError } from "../api";
import { errorPanel, note } from "../components";
import { clear, fmtTime, h } from "../dom";
import type { Ctx } from "../main";

export const STATE_LABEL: Record<RecipientState, string> = {
  not_opened: "Not opened",
  requested: "Waiting for you",
  approved: "Approved",
  opened: "Opened",
  declined: "Declined",
  revoked: "Revoked",
};

const RECEIVED_LABEL: Record<RecipientState, string> = {
  ...STATE_LABEL,
  requested: "Waiting for sender",
};

export function stateChip(label: string, state: RecipientState | "expired"): HTMLElement {
  return h("span", { class: `status status-${state}` }, label);
}

/** A small "View only" marker next to a file's name. */
export function viewOnlyBadge(on: boolean): HTMLElement | null {
  return on ? h("span", { class: "badge badge-warn", title: "Can be viewed in the app, not saved" }, "View only") : null;
}

export function fileLabel(name: string | null, id: string): string {
  return name ?? `File ${id.slice(0, 8)}…`;
}

export function isExpired(f: { signed_expires_at: number | null; rules: { expires_at: number | null } }): boolean {
  const now = Date.now() / 1000;
  return [f.signed_expires_at, f.rules.expires_at].some((t) => t !== null && t <= now);
}

/** One word for a sent file across its recipients. */
function sentSummary(f: SentFile): [string, RecipientState | "expired"] {
  if (f.revoked_at) return ["Revoked", "revoked"];
  if (isExpired(f)) return ["Expired", "expired"];
  const waiting = f.recipients.filter((r) => r.state === "requested").length;
  if (waiting) return [`${waiting} waiting for you`, "requested"];
  const opened = f.recipients.filter((r) => r.state === "opened").length;
  if (opened) return [`Opened by ${opened} of ${f.recipients.length}`, "opened"];
  return ["Not opened yet", "not_opened"];
}

export function historyScreen(ctx: Ctx, root: HTMLElement, tab: "sent" | "received"): void {
  const body = h("div", { class: "stack" });
  const tabs = h("div", { class: "tabs", role: "tablist" },
    ...(["sent", "received"] as const).map((t) =>
      h("button", {
        type: "button", role: "tab", class: `tab${t === tab ? " is-current" : ""}`,
        "aria-selected": t === tab ? "true" : "false",
        onclick: () => ctx.go("history", t),
      }, t === "sent" ? "Sent" : "Received")));
  root.append(
    h("header", { class: "screen-head" }, h("h1", {}, "History"),
      h("p", { class: "lede" }, "Who you've exchanged files with, and what happened to each one.")),
    tabs,
    body,
  );

  const render = (v: HistoryView) => {
    clear(body);
    if (tab === "sent") {
      if (!v.sent.length) {
        body.appendChild(note("Nothing sent yet. Files you send appear here, and you can change their rules or revoke them.", "info"));
        return;
      }
      body.appendChild(h("ul", { class: "list" }, ...v.sent.map((f) => {
        const [label, state] = sentSummary(f);
        const to = f.recipients.map((r) => r.email ?? r.account).join(", ");
        return h("li", {},
          h("button", { type: "button", class: "list-row", onclick: () => ctx.go("file", f.artifact_id) },
            h("span", { class: "list-main" },
              h("span", { class: "list-title" }, fileLabel(f.file_name, f.artifact_id), " ", viewOnlyBadge(f.rules.view_only)),
              h("span", { class: "muted small" }, `To ${to} · ${fmtTime(f.created_at)}`)),
            stateChip(label, state),
            h("span", { class: "chevron", "aria-hidden": "true" }, "›")));
      })));
    } else {
      if (!v.received.length) {
        body.appendChild(note("Nothing received yet. Files people send to your email address appear here once you open them or ask to.", "info"));
        return;
      }
      body.appendChild(h("ul", { class: "list" }, ...v.received.map((f) =>
        h("li", {},
          h("div", { class: "list-row is-static" },
            h("span", { class: "list-main" },
              h("span", { class: "list-title" }, fileLabel(f.file_name, f.artifact_id), " ", viewOnlyBadge(f.view_only)),
              h("span", { class: "muted small" },
                `From ${f.sender_email ?? f.sender} · sent ${fmtTime(f.created_at)}`,
                f.opened_at ? ` · opened ${fmtTime(f.opened_at)}` : "")),
            stateChip(RECEIVED_LABEL[f.state], f.state))))));
    }
  };

  body.appendChild(note("Loading…", "info"));
  api.history().then(render, (e) => {
    clear(body);
    body.appendChild(errorPanel(asAppError(e)));
  });
}
