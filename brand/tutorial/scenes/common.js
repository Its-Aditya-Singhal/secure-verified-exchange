// Shared pieces for the tutorial scenes: example people (fictional), app
// fixtures, file icons and system prompts.
import { $, ease, env, prog, symbol } from "../engine.js";

export const NOW = 1791500000; // a fixed "now" so dates in the app never change between frames

export const ALICE = { first: "Alice", last: "Example", email: "alice@example.com", account: "u.a11ce0000000a11c" };
export const BOB = { first: "Bob", last: "Example", email: "bob@example.com", account: "u.b0b0000000000b0b" };

export const EVE = { first: "Eve", last: "Example", email: "eve@example.com", account: "u.e0e00000000000e0" };

export function appState(who, extra = {}) {
  return {
    configured: true, config_path: "", config_error: null, org_id: who.account,
    service_url: "https://api.getsvx.me:8443", idp_issuer: "svx:email", dev: false,
    output_dir: who === BOB ? "/Users/bob/Documents/SVX" : who === EVE ? "/Users/eve/Documents/SVX" : "/Users/alice/Documents/SVX",
    prefs: { recent_recipients: [], signing_key: null, last_policy: null, pending_org: null, pending_encryption_key: null, ask_presence: null, check_updates: false },
    personal: true, email: who.email, presence_available: true, presence_active: true,
    updates_available: false, view_supported: true, ...extra,
  };
}

/** Fixtures every signed-in personal account needs. */
export function signedIn(who, more = {}) {
  return {
    state: appState(who),
    account: { account: who.account, email: who.email, provider: "Email", issuer: "svx:email", created_at: NOW - 86400 * 3, signing_key_id: "a1", kem_key_id: "b2", kem_public: "" },
    account_name: { first_name: who.first, last_name: who.last },
    requests: [],
    ...more,
  };
}

export const contact = (who) => ({ account: who.account, email: who.email });

const PDF = `<div class="doc"><em>PDF</em></div>`;
const SVX = `<div class="doc svx"><div class="lockmark">${symbol(64)}</div></div>`;
export function fileIcon(name, kind = "pdf") {
  return $(`<div class="fileicon">${kind === "pdf" ? PDF : SVX}<div class="nm">${name}</div></div>`);
}

const ICONS = {
  chat: `<svg viewBox="0 0 64 64" fill="none" stroke="#4cc584" stroke-width="4" stroke-linejoin="round"><path d="M10 14h44v28H30l-12 10v-10h-8z"/><path d="M20 26h24M20 33h14" stroke-linecap="round"/></svg>`,
  mail: `<svg viewBox="0 0 64 64" fill="none" stroke="#9db5c9" stroke-width="4" stroke-linejoin="round"><rect x="8" y="14" width="48" height="36" rx="5"/><path d="M10 18l22 17 22-17"/></svg>`,
  usb: `<svg viewBox="0 0 64 64" fill="none" stroke="#f0b456" stroke-width="4" stroke-linejoin="round"><rect x="20" y="22" width="24" height="36" rx="5"/><path d="M24 22V8h16v14M29 13h1M35 13h1" stroke-linecap="round"/></svg>`,
};
export function destination(kind, label) {
  return $(`<div class="dest">${ICONS[kind]}<span>${label}</span></div>`);
}

/** The "confirm it's you" prompts, recreated (no OS logos). */
export function macTouchId(reason) {
  return $(`<div class="sysdlg mac"><div class="fp">${fingerprint()}</div><h4>Touch ID</h4><div>“Secure Verified Exchange” is trying to ${reason}.</div><div class="btns"><span>Use Password…</span><span>Cancel</span></div></div>`);
}
export function winHello() {
  return $(`<div class="sysdlg win" style="text-align:left;border-radius:10px;background:rgba(32,33,38,.98)"><div style="font:500 16px 'IBM Plex Sans';color:#bbb">Windows Security</div><h4 style="margin-top:18px">Making sure it’s you</h4><div style="color:#ccc">Confirm with your PIN, fingerprint, or Windows password.</div><div class="pin" style="margin-top:22px;height:48px;border-bottom:2px solid #0a84ff;background:#2b2c31;border-radius:4px 4px 0 0;display:flex;align-items:center;gap:12px;padding:0 16px"></div><div class="btns" style="justify-content:flex-end"><span class="pri" style="border-radius:4px">OK</span><span style="border-radius:4px">Cancel</span></div></div>`);
}
function fingerprint() {
  const arcs = [10, 16, 22, 28, 34].map((r, i) => `<path d="M${40 - r} ${44 + (i % 2) * 3} a${r} ${r} 0 0 1 ${2 * r} 0" />`).join("");
  return `<svg viewBox="0 0 80 80" width="84" height="84" fill="none" stroke="#ff6a3d" stroke-width="3.2" stroke-linecap="round">${arcs}<path d="M40 44v18"/></svg>`;
}

/** A floating badge like "Alice's computer" pinned to a world position. */
export function badge(E, t0, t1, x, y, html) {
  return E.add(`<div class="badge" style="position:absolute;left:${x}px;top:${y}px">${html}</div>`, (t, el) => {
    const a = env(t, t0, t1, 0.5, 0.4);
    el.style.display = a > 0 ? "" : "none";
    el.style.opacity = a;
    el.style.transform = `translate(-50%,-50%) translateY(${(1 - ease.outExpo(prog(t, t0, t0 + 0.6))) * 18}px)`;
  });
}

export const avatar = (who, color) => `<span class="av" style="width:36px;height:36px;font-size:16px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;background:${color};color:#16171b;font-family:Unbounded">${who.first[0]}</span>`;

/** The check result for the file Alice sent to Bob (what the Open screen shows first). */
export const statusFor = (forWho, over = {}) => ({
  artifact_id: "5a1f", sender_org: ALICE.account, sender_name: "Alice Example <alice@example.com>",
  recipient_org: BOB.account, recipients: [BOB.account], my_org: forWho.account, for_you: forWho === BOB,
  expired: false, created_at: NOW - 3600, expires_at: NOW + 7 * 86400, policy: "personal", service_id: "svx",
  protection: "Maximum (SVX-2, post-quantum)", post_quantum: true, suite_id: 4, view_only: false, ...over,
});

/** A file on the desktop that gets double-clicked; returns a selection highlight updater. */
export function desktopFile(E, name, kind, x, y, t0) {
  const el = E.add(fileIcon(name, kind), null);
  el.style.left = `${x}px`; el.style.top = `${y}px`;
  E.every((t) => {
    const show = ease.outBack(prog(t, t0, t0 + 0.6));
    el.style.opacity = Math.min(1, show * 1.4);
    el.style.transform = `scale(${show})`;
  });
  return el;
}

/** The protected viewer window (a separate OS window in the real app): the page, and the viewer's name and time burned into it. */
export function viewerWindow(E, x, y, who, w = 1100, h = 760) {
  const wm = Array.from({ length: 60 }, () => `<span>${who.email} · Oct 9, 2026, 3:23 PM</span>`).join("");
  return E.add(`<div class="appwin mac" style="left:${x - w / 2}px;top:${y - h / 2}px;width:${w}px;height:${h}px"><div class="tb tb-mac"><i></i><i></i><i></i><span>Project-plan.pdf</span></div><div class="vbody"><div class="vpage"><h1>Project plan</h1><div class="sub">Q4 · Example Corp</div><h2>1. Goals</h2><ul><li>Launch the new brochure site</li><li>Move design files to one shared place</li><li>Review the budget with Carol</li></ul><h2>2. Timeline</h2><div class="bar" style="width:92%"></div><div class="bar" style="width:78%"></div><div class="bar" style="width:86%"></div><div class="bar" style="width:55%"></div><h2>3. Budget</h2><div class="bar" style="width:88%"></div><div class="bar" style="width:70%"></div><div class="vwm">${wm}</div></div><div class="vtag">View only</div></div></div>`, null);
}
