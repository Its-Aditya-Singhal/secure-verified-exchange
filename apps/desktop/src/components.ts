// Shared UI pieces.

import type { AppError } from "./api";
import { button, h, icon } from "./dom";
import { explain } from "./messages";

/** A friendly error panel with optional actions. */
export function errorPanel(e: AppError, actions: HTMLElement[] = []): HTMLElement {
  const x = explain(e);
  return h(
    "div",
    { class: `panel panel-${x.tone}`, role: "alert" },
    h("div", { class: "panel-head" }, icon(x.tone), h("h3", {}, x.title)),
    h("p", {}, x.body),
    e.kind !== "rejected" && e.kind !== "not_recipient" && x.body !== e.message
      ? h("details", {}, h("summary", {}, "Details"), h("code", { class: "mono" }, e.message))
      : null,
    actions.length ? h("div", { class: "actions" }, ...actions) : null,
  );
}

/** A small inline message (validation, success notes). */
export function note(text: string, tone: "ok" | "warn" | "stop" | "info" = "info"): HTMLElement {
  return h("p", { class: `note note-${tone}` }, icon(tone), text);
}

/** Key/value rows. */
export function facts(rows: [string, Node | string][]): HTMLElement {
  return h(
    "dl",
    { class: "facts" },
    ...rows.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]),
  );
}

/** A drop zone that also offers pickers. */
export function dropZone(title: string, hint: string, buttons: HTMLButtonElement[]): HTMLElement {
  return h(
    "div",
    { class: "dropzone" },
    h("div", { class: "dropzone-icon", "aria-hidden": "true" }, "⇣"),
    h("p", { class: "dropzone-title" }, title),
    h("p", { class: "dropzone-hint" }, hint),
    h("div", { class: "actions" }, ...buttons),
  );
}

export function card(title: string | null, ...children: (Node | null)[]): HTMLElement {
  return h("section", { class: "card" }, title ? h("h2", {}, title) : null, ...children);
}

export function retryButton(onRetry: () => void): HTMLButtonElement {
  return button("Try again", onRetry, "primary");
}
