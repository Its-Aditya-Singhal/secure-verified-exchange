// App shell: sidebar navigation, routing, incoming files (double-click,
// second launch, drag-drop), and the badge for approval requests.

import "./style.css";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { type AppState, type AvailableUpdate, type SetupForm, api, asAppError } from "./api";
import { brandLockup } from "./brand";
import { errorPanel } from "./components";
import { busy, button, clear, h, icon } from "./dom";
import { setPersonalWording } from "./messages";
import { adminScreen } from "./screens/admin";
import { fileScreen } from "./screens/file";
import { historyScreen } from "./screens/history";
import { nameScreen } from "./screens/name";
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
  /** Look for an app update now (throws when `show` and it fails). */
  checkForUpdate(show?: boolean): Promise<AvailableUpdate | null>;
}

const app = document.getElementById("app")!;
let route: Route = "open";
let pendingRequests = 0;
let update: AvailableUpdate | null = null;
/** "Later" hides the banner; the sidebar keeps an Update button. */
let updateHidden = false;
let lastUpdateCheck = 0;
/** The service said this account is suspended: the whole app is locked. */
let suspended = false;
/** Whether the account has a name: "missing" (a new Google account) shows
 *  only the name screen until it's given. */
let named: "unknown" | "yes" | "missing" = "unknown";

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
  checkForUpdate: (show) => checkForUpdate(show),
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
  if (suspended && s.configured) {
    renderSuspended();
    return;
  }
  if (s.configured && s.personal && named === "missing") {
    const main = h("main", { class: "main" });
    app.append(h("div", { class: "shell shell-bare" }, main));
    nameScreen(main, s.email ?? "", () => {
      named = "yes";
      route = "send";
      render();
    });
    return;
  }
  if (s.configured && s.personal && named === "unknown") void checkName();
  if (!s.configured) named = "unknown";
  if (!s.configured && route !== "setup" && route !== "welcome") route = "welcome";

  const main = h("main", { class: "main" });
  if (!s.configured) {
    app.append(h("div", { class: "shell shell-bare" }, main));
  } else {
    const items = (s.personal ? PERSONAL_NAV : COMPANY_NAV).map(([r, label]) => navItem(r, label));
    const side = h("aside", { class: "sidebar" },
      h("div", { class: "brand" }, brandLockup(), h("span", { class: "brand-name" }, "Secure Verified Exchange")),
      h("nav", { class: "nav", "aria-label": "Main" }, ...items),
      update && updateHidden
        ? h("button", {
          type: "button", class: "nav-update",
          onclick: () => { updateHidden = false; render(arg); },
        }, icon("info"), h("span", {}, `Update to ${update.version}`))
        : null,
      h("div", { class: "who" },
        h("span", { class: "who-name" }, s.personal ? (s.email ?? "") : (s.org_id ?? "")),
        s.dev ? h("span", { class: "badge badge-warn" }, "dev") : null),
    );
    app.append(h("div", { class: "shell" }, side, main));
  }

  if (update && !updateHidden) main.appendChild(updateBanner(update));
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

/** The locked app of a suspended account. The service refuses everything
 *  the account asks for anyway; this says so instead of a usable-looking app. */
function renderSuspended() {
  const main = h("main", { class: "main" });
  app.append(h("div", { class: "shell shell-bare" }, main));
  if (update) main.appendChild(updateBanner(update));
  const status = h("p", { class: "muted small" });
  const again = button("Check again", () => void busy(again, "Checking…", async () => {
    await checkAccount();
    if (suspended) status.textContent = "Still suspended.";
  }));
  main.append(
    h("div", { class: "brand center-brand" }, brandLockup()),
    errorPanel(
      { kind: "suspended", message: "", deny_reason: null, exit_code: 1, path: null },
      [again],
    ),
    status,
    h("p", { class: "muted small" }, `Signed in as ${ctx.state.email ?? ""}.`),
  );
}

/** Ask the service whether this account may be used; lock or unlock the app.
 *  Being offline changes nothing. */
async function checkAccount() {
  if (!ctx.state.configured || !ctx.state.personal) return;
  let now = false;
  try {
    await api.account();
  } catch (e) {
    if (asAppError(e).kind !== "suspended") return;
    now = true;
  }
  if (now !== suspended) {
    suspended = now;
    if (!suspended) route = "send";
    render();
  }
}

/** Ask once whether the account has a name; a missing one takes over the
 *  window until it's given. Being offline changes nothing. */
let checkingName = false;
async function checkName() {
  if (checkingName || named !== "unknown") return;
  checkingName = true;
  try {
    const n = await api.accountName();
    named = n.first_name || n.last_name ? "yes" : "missing";
    if (named === "missing") render();
  } catch {
    // Try again on the next render.
  } finally {
    checkingName = false;
  }
}

/** A newer, verified release: install and restart. */
function updateBanner(u: AvailableUpdate): HTMLElement {
  const out = h("div", {});
  const install = button(`Install ${u.version} and restart`, () => void busy(install, "Installing…", async () => {
    try {
      await api.installUpdate();
    } catch (e) {
      out.replaceChildren(errorPanel(asAppError(e)));
    }
  }), "primary");
  return h("div", { class: "panel panel-info update-banner", role: "status" },
    h("div", { class: "panel-head" }, icon("info"), h("h3", {}, `Version ${u.version} is available`)),
    u.notes ? h("p", {}, u.notes) : null,
    h("p", { class: "muted small" }, "Signed by the SVX release key built into this app; the download is checked before it's installed."),
    h("div", { class: "actions" }, install, button("Later", () => { updateHidden = true; render(); })),
    out);
}

/** Look for a verified update now and then; errors are ignored (offline). */
async function checkForUpdate(show = false): Promise<AvailableUpdate | null> {
  if (!ctx.state.updates_available) return null;
  lastUpdateCheck = Date.now();
  try {
    const u = await api.checkUpdate();
    if (u && (!update || update.version !== u.version || (show && updateHidden))) {
      update = u;
      updateHidden = false;
      if (!show) render();
    }
    return u;
  } catch (e) {
    if (show) throw e;
    return null;
  }
}

/** .svx files handed to the app by the OS always go to the Open screen. */
async function pickUpPending() {
  // Leave files queued until setup is done (or the suspension is lifted).
  if (!ctx.state.configured || suspended) return;
  const paths = await api.takePending().catch(() => [] as string[]);
  if (paths.length) ctx.go("open", paths[paths.length - 1]);
}

/** Update the Requests badge without re-rendering the screen. */
async function refreshRequests() {
  if (!ctx.state.configured || !ctx.state.personal) return;
  const n = await api.requests().then((r) => r.length).catch((e) => {
    if (asAppError(e).kind === "suspended") void checkAccount();
    return pendingRequests;
  });
  if (n === pendingRequests) return;
  pendingRequests = n;
  const btn = app.querySelector<HTMLElement>('.nav-item[data-route="requests"]');
  if (btn) btn.replaceWith(navItem("requests", "Requests"));
}

async function start() {
  await ctx.refreshState();
  route = ctx.state.configured ? (ctx.state.personal ? "send" : "open") : "welcome";
  render();
  await checkAccount();
  window.setInterval(() => void checkAccount(), 60_000);
  // At most every 30 s: a system dialog (Touch ID, keychain) takes the
  // focus away and gives it back, which mustn't start another check.
  let lastAccountCheck = Date.now();
  window.addEventListener("focus", () => {
    if (Date.now() - lastAccountCheck < 30_000) return;
    lastAccountCheck = Date.now();
    void checkAccount();
  });
  await listen("open-file", () => void pickUpPending());
  // Windows Hello opens its prompt behind the app: say where to find it.
  if (navigator.userAgent.includes("Windows")) {
    const hint = h("div", { class: "presence-hint", role: "status", hidden: true },
      icon("info"),
      h("span", {}, "Windows Hello is waiting for you. If you don't see it, click ",
        h("strong", {}, "Windows Security"), " in the taskbar."));
    document.body.appendChild(hint);
    await listen<boolean>("presence", (e) => {
      hint.hidden = !e.payload;
    });
  }
  await pickUpPending();
  void refreshRequests();
  window.setInterval(() => void refreshRequests(), 20_000);
  // Updates: at start, every 3 hours, and when the window comes to the
  // front if the last look was over an hour ago.
  void checkForUpdate();
  window.setInterval(() => void checkForUpdate(), 3 * 3600_000);
  window.addEventListener("focus", () => {
    if (Date.now() - lastUpdateCheck > 3600_000) void checkForUpdate();
  });
  await getCurrentWebview().onDragDropEvent((ev) => {
    if (ev.payload.type !== "drop" || !ctx.state.configured || suspended) return;
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
