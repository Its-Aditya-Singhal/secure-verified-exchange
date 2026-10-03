// App shell: navigation, routing, incoming files (double-click, second
// launch, drag-drop).

import "./style.css";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { type AppState, type SetupForm, api } from "./api";
import { errorPanel } from "./components";
import { clear, h } from "./dom";
import { adminScreen } from "./screens/admin";
import { openScreen } from "./screens/open";
import { sendScreen } from "./screens/send";
import { settingsScreen } from "./screens/settings";
import { setupScreen } from "./screens/setup";

export type Route = "open" | "send" | "admin" | "settings" | "setup";

export interface Ctx {
  state: AppState;
  refreshState(): Promise<void>;
  go(route: Route, arg?: unknown): void;
  /** Show any .svx files the OS handed to the app. */
  pickUpPending(): Promise<void>;
  /** Files dropped on the window, for the current screen. */
  onFiles: ((paths: string[]) => void) | null;
}

const app = document.getElementById("app")!;
let route: Route = "open";

const ctx: Ctx = {
  state: null as unknown as AppState,
  async refreshState() {
    ctx.state = await api.state();
  },
  go(r, arg) {
    route = r;
    render(arg);
  },
  pickUpPending: () => pickUpPending(),
  onFiles: null,
};

const NAV: [Route, string][] = [
  ["open", "Open"],
  ["send", "Protect & send"],
  ["admin", "Admin"],
  ["settings", "Settings"],
];

function render(arg?: unknown) {
  clear(app);
  ctx.onFiles = null;
  const s = ctx.state;
  if (!s.configured && route !== "setup") route = "setup";

  const nav = s.configured
    ? h("nav", { class: "nav", "aria-label": "Main" },
        ...NAV.map(([r, label]) =>
          h("button", {
            type: "button",
            class: `nav-item${r === route ? " is-current" : ""}`,
            "aria-current": r === route ? "page" : undefined,
            onclick: () => ctx.go(r),
          }, label)))
    : null;
  const header = h("header", { class: "topbar" },
    h("div", { class: "brand" }, h("span", { class: "brand-mark", "aria-hidden": "true" }), "Secure Verified Exchange"),
    nav,
    s.configured ? h("div", { class: "org" }, s.org_id ?? "", s.dev ? h("span", { class: "badge badge-warn" }, "dev") : null) : null,
  );
  const main = h("main", { class: "main" });
  app.append(header, main);

  if (s.config_error && route === "setup") {
    main.appendChild(errorPanel({
      kind: "config",
      message: `The existing configuration (${s.config_path}) couldn't be loaded: ${s.config_error}`,
      deny_reason: null, exit_code: 2, path: null,
    }));
  }
  switch (route) {
    case "setup": {
      const a = (arg ?? {}) as { replace?: boolean; form?: SetupForm };
      setupScreen(ctx, main, a.replace ?? s.config_error !== null, a.form);
      break;
    }
    case "open":
      openScreen(ctx, main, typeof arg === "string" ? arg : null);
      break;
    case "send":
      sendScreen(ctx, main);
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

async function start() {
  await ctx.refreshState();
  render();
  await listen("open-file", () => void pickUpPending());
  await pickUpPending();
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
