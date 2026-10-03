// App shell: sidebar navigation, routing, incoming files (double-click,
// second launch, drag-drop), and the badge for approval requests.

import "./style.css";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { type AppState, type SetupForm, api } from "./api";
import { errorPanel } from "./components";
import { clear, h } from "./dom";
import { setPersonalWording } from "./messages";
import { adminScreen } from "./screens/admin";
import { fileScreen } from "./screens/file";
import { historyScreen } from "./screens/history";
import { openScreen } from "./screens/open";
import { personalSendScreen } from "./screens/psend";
import { requestsScreen } from "./screens/requests";
import { sendScreen } from "./screens/send";
import { settingsScreen } from "./screens/settings";
import { setupScreen } from "./screens/setup";
import { welcomeScreen } from "./screens/welcome";

export type Route =
  | "welcome"
  | "open"
  | "send"
  | "history"
  | "file"
  | "requests"
  | "admin"
  | "settings"
  | "setup";

export interface Ctx {
  state: AppState;
  refreshState(): Promise<void>;
  go(route: Route, arg?: unknown): void;
  /** Show any .svx files the OS handed to the app. */
  pickUpPending(): Promise<void>;
  /** Files dropped on the window, for the current screen. */
  onFiles: ((paths: string[]) => void) | null;
  /** Re-count requests waiting for my approval (personal accounts). */
  refreshRequests(): Promise<void>;
}

const app = document.getElementById("app")!;
let route: Route = "open";
let pendingRequests = 0;

const ctx: Ctx = {
  state: null as unknown as AppState,
  async refreshState() {
    ctx.state = await api.state();
    setPersonalWording(ctx.state.personal);
  },
  go(r, arg) {
    // Leaving Open stops waiting for a sender's approval (nothing is
    // decrypted in the background).
    if (route === "open" && r !== "open") void api.cancelOpen().catch(() => {});
    route = r;
    render(arg);
  },
  pickUpPending: () => pickUpPending(),
  onFiles: null,
  refreshRequests: () => refreshRequests(),
};

const PERSONAL_NAV: [Route, string][] = [
  ["send", "Send"],
  ["open", "Open"],
  ["history", "History"],
  ["requests", "Requests"],
  ["settings", "Settings"],
];

const COMPANY_NAV: [Route, string][] = [
  ["open", "Open"],
  ["send", "Protect & send"],
  ["admin", "Admin"],
  ["settings", "Settings"],
];

function navItem(r: Route, label: string): HTMLElement {
  const current = r === route || (r === "history" && route === "file");
  return h("button", {
    type: "button",
    class: `nav-item${current ? " is-current" : ""}`,
    "aria-current": current ? "page" : undefined,
    "data-route": r,
    onclick: () => ctx.go(r),
  }, h("span", {}, label),
  r === "requests" && pendingRequests > 0
    ? h("span", { class: "nav-badge", "aria-label": `${pendingRequests} waiting` }, String(pendingRequests))
    : null);
}

function render(arg?: unknown) {
  clear(app);
  ctx.onFiles = null;
  const s = ctx.state;
  if (!s.configured && route !== "setup" && route !== "welcome") route = "welcome";

  const main = h("main", { class: "main" });
  if (!s.configured) {
    app.append(h("div", { class: "shell shell-bare" }, main));
  } else {
    const items = (s.personal ? PERSONAL_NAV : COMPANY_NAV).map(([r, label]) => navItem(r, label));
    const side = h("aside", { class: "sidebar" },
      h("div", { class: "brand" }, h("span", { class: "brand-mark", "aria-hidden": "true" }), "Secure Verified Exchange"),
      h("nav", { class: "nav", "aria-label": "Main" }, ...items),
      h("div", { class: "who" },
        h("span", { class: "who-name" }, s.personal ? (s.email ?? "") : (s.org_id ?? "")),
        s.dev ? h("span", { class: "badge badge-warn" }, "dev") : null),
    );
    app.append(h("div", { class: "shell" }, side, main));
  }

  if (s.config_error && route === "setup") {
    main.appendChild(errorPanel({
      kind: "config",
      message: `The existing configuration (${s.config_path}) couldn't be loaded: ${s.config_error}`,
      deny_reason: null, exit_code: 2, path: null,
    }));
  }
  switch (route) {
    case "welcome":
      welcomeScreen(ctx, main);
      break;
    case "setup": {
      const a = (arg ?? {}) as { replace?: boolean; form?: SetupForm };
      setupScreen(ctx, main, a.replace ?? s.config_error !== null, a.form);
      break;
    }
    case "open":
      openScreen(ctx, main, typeof arg === "string" ? arg : null);
      break;
    case "send":
      if (s.personal) personalSendScreen(ctx, main, (arg ?? null) as { to?: string[] } | null);
      else sendScreen(ctx, main);
      break;
    case "history":
      historyScreen(ctx, main, arg === "received" ? "received" : "sent");
      break;
    case "file":
      fileScreen(ctx, main, String(arg ?? ""));
      break;
    case "requests":
      requestsScreen(ctx, main);
      break;
    case "admin":
      adminScreen(ctx, main);
      break;
    case "settings":
      settingsScreen(ctx, main);
      break;
  }
}

/** .svx files handed to the app by the OS always go to the Open screen. */
async function pickUpPending() {
  // Leave files queued until setup is done.
  if (!ctx.state.configured) return;
  const paths = await api.takePending().catch(() => [] as string[]);
  if (paths.length) ctx.go("open", paths[paths.length - 1]);
}

/** Update the Requests badge without re-rendering the screen. */
async function refreshRequests() {
  if (!ctx.state.configured || !ctx.state.personal) return;
  const n = await api.requests().then((r) => r.length).catch(() => pendingRequests);
  if (n === pendingRequests) return;
  pendingRequests = n;
  const btn = app.querySelector<HTMLElement>('.nav-item[data-route="requests"]');
  if (btn) btn.replaceWith(navItem("requests", "Requests"));
}

async function start() {
  await ctx.refreshState();
  route = ctx.state.configured ? (ctx.state.personal ? "send" : "open") : "welcome";
  render();
  await listen("open-file", () => void pickUpPending());
  await pickUpPending();
  void refreshRequests();
  window.setInterval(() => void refreshRequests(), 20_000);
  await getCurrentWebview().onDragDropEvent((ev) => {
    if (ev.payload.type !== "drop" || !ctx.state.configured) return;
    const paths = ev.payload.paths;
    if (route === "send" && ctx.onFiles) {
      ctx.onFiles(paths);
    } else {
      const svx = paths.filter((p) => p.toLowerCase().endsWith(".svx"));
      if (svx.length) ctx.go("open", svx[0]);
      else if (ctx.onFiles && route !== "open") ctx.onFiles(paths);
    }
  });
}

void start();
