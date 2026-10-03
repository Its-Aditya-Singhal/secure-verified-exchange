// Minimal DOM helpers. Strings always become text nodes (never HTML), so
// nothing from a file, the service or the user is ever parsed as markup.

type Child = Node | string | number | null | undefined | false;
type Attrs = Record<string, string | boolean | number | EventListener | undefined>;

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue;
    if (k.startsWith("on") && typeof v === "function") {
      el.addEventListener(k.slice(2), v as EventListener);
    } else if (k === "class") {
      el.className = String(v);
    } else if (v === true) {
      el.setAttribute(k, "");
    } else {
      el.setAttribute(k, String(v));
    }
  }
  append(el, ...children);
  return el;
}

export function append(el: Node, ...children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
  }
}

export function clear(el: Element): void {
  while (el.firstChild) el.removeChild(el.firstChild);
}

export function field(label: string, input: HTMLElement, hint?: string): HTMLElement {
  return h(
    "label",
    { class: "field" },
    h("span", { class: "field-label" }, label),
    input,
    hint ? h("span", { class: "field-hint" }, hint) : null,
  );
}

export function button(
  label: string,
  onclick: () => void,
  kind: "primary" | "secondary" | "danger" | "link" = "secondary",
): HTMLButtonElement {
  return h("button", { type: "button", class: `btn btn-${kind}`, onclick: () => onclick() }, label);
}

/** Run `task` with `btn` disabled and a busy label. */
export async function busy<T>(btn: HTMLButtonElement, label: string, task: () => Promise<T>): Promise<T> {
  const old = btn.textContent;
  btn.disabled = true;
  btn.textContent = label;
  btn.classList.add("is-busy");
  try {
    return await task();
  } finally {
    btn.disabled = false;
    btn.textContent = old;
    btn.classList.remove("is-busy");
  }
}

export function fmtTime(unix: number | null | undefined): string {
  if (unix === null || unix === undefined) return "Never";
  return new Date(unix * 1000).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export function fmtSize(bytes: number): string {
  const units = ["bytes", "KB", "MB", "GB", "TB"];
  let n = bytes;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return i === 0 ? `${n} ${units[0]}` : `${n.toFixed(1)} ${units[i]}`;
}

export function baseName(path: string): string {
  const parts = path.split(/[\\/]/).filter(Boolean);
  return parts[parts.length - 1] ?? path;
}

export function revealLabel(): string {
  const ua = navigator.userAgent;
  if (ua.includes("Mac")) return "Show in Finder";
  if (ua.includes("Windows")) return "Show in Explorer";
  return "Show in folder";
}

/** Small inline status icon. */
export function icon(kind: "ok" | "warn" | "stop" | "info" | "spin" | "dot"): HTMLElement {
  const glyph = { ok: "✓", warn: "!", stop: "✕", info: "i", spin: "", dot: "" }[kind];
  return h("span", { class: `icon icon-${kind}`, "aria-hidden": "true" }, glyph);
}
