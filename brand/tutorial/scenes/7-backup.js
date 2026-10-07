// Chapter 7: Keep your keys safe. Why a backup matters, how to save one, how to restore it.
import { ease, env, prog, symbol } from "../engine.js";
import { ALICE, NOW, avatar, badge, destination, fileIcon, signedIn } from "./common.js";

const LAPTOP = `<svg viewBox="0 0 240 170" width="360" fill="none" stroke="#a8a59e" stroke-width="5" stroke-linejoin="round"><rect x="40" y="14" width="160" height="104" rx="9"/><path d="M14 142h212l-14 14H28z"/><g stroke="#ff6a3d"><circle cx="104" cy="62" r="14"/><path d="M118 62h46M150 62v14M164 62v10"/></g></svg>`;

export default async function scene(E) {
  const L = (i, d) => E.at(i, d), End = (i, d) => E.end(i, d);
  const AX = 1010, NX = 3010, Y = 560;

  let restored = false;
  const info = { account: ALICE.account, email: ALICE.email, provider: "Email", issuer: "svx:email", created_at: NOW - 86400 * 3, signing_key_id: "a1", kem_key_id: "b2", kem_public: "" };
  const alice = await E.appWindow({
    id: "alice", x: AX, y: Y, os: "mac", now: NOW,
    fixtures: signedIn(ALICE, { account: info, save_backup: "/Users/alice/Documents/Alice-keys.svxbackup", password_strength: { score: 0, ok: false, feedback: [] } }),
  });
  const fresh = await E.appWindow({
    id: "fresh", x: NX, y: Y, os: "win", now: NOW,
    fixtures: {
      state: () => (restored ? { ...signedIn(ALICE).state } : { ...signedIn(ALICE).state, configured: false, org_id: null, personal: false, email: null }),
      providers: { service_url: "https://api.getsvx.me:8443", dev: false, providers: [{ name: "Google", issuer: "https://accounts.google.com" }] },
      sign_up: async () => { throw { kind: "account_exists", message: "", deny_reason: null, exit_code: 2, path: null }; },
      restore: async () => { await E.gate("restore"); restored = true; return info; },
      account: info,
    },
  });
  const byText = (text, within) => (d) => [...d.querySelectorAll(within)].find((e) => e.textContent.trim() === text);
  const card = (i) => (d) => d.querySelectorAll("section.card")[i];
  const nav = (r) => `.nav-item[data-route="${r}"]`;
  const aliceEl = E.frames.get("alice").el;

  E.every((t) => { E.world.style.opacity = ease.out(prog(t, L(3, -0.55), L(3, 0.2))) * (1 - ease.in(prog(t, L(9, -0.3), L(9, 0.4)))); });
  E.titleCard(0.05, L(1, -0.1), 7, "Keep your keys safe");

  // ---------------------------------------------------------------- 1-2. why a backup matters (graphics)
  const laptop = E.add(`<div style="position:absolute;left:960px;top:400px;transform:translate(-50%,-50%);text-align:center">${LAPTOP}<div class="lt" style="margin-top:8px;font:600 34px 'IBM Plex Sans'">Your keys are only here</div></div>`, null, E.hud);
  const bad = E.add(`<div style="position:absolute;left:960px;top:400px;transform:translate(-50%,-50%);font:700 190px Unbounded;color:#e5484d;text-shadow:0 10px 40px rgba(0,0,0,.6)">✕</div>`, null, E.hud);
  const locked = E.add(fileIcon("Project-plan.svx", "svx"), null, E.hud);
  const stat = E.add(`<div style="position:absolute;left:960px;top:690px;transform:translateX(-50%);font:600 34px 'IBM Plex Sans';white-space:nowrap;padding:12px 24px;border-radius:14px;background:rgba(29,31,36,.95);border:1px solid #e5484d;color:#fff"><span class="s">✕ Can’t be opened</span></div>`, null, E.hud);
  const bkFile = E.add(fileIcon("Alice-keys.svxbackup", "svx"), null, E.hud);
  const T_LOST = L(2, 0.2), T_FILE = L(2, 1.2), T_BACKUP = L(2, 3.0);
  E.every((t) => {
    // 1: the laptop with the keys
    const a1 = env(t, L(1, -0.1), T_LOST + 0.9, 0.5, 0.5);
    const p1 = ease.outBack(prog(t, L(1, -0.1), L(1, 0.6)));
    const lost = ease.in(prog(t, T_LOST, T_LOST + 0.9));
    laptop.style.display = a1 > 0 ? "" : "none";
    laptop.style.opacity = a1 * (1 - lost * 0.7);
    laptop.style.filter = lost > 0 ? `grayscale(${lost})` : "";
    laptop.style.transform = `translate(-50%,-50%) scale(${0.8 + 0.2 * p1}) translateY(${lost * 80}px) rotate(${lost * 14}deg)`;
    const bp = ease.outBack(prog(t, T_LOST + 0.1, T_LOST + 0.6));
    bad.style.display = bp > 0 && t < T_FILE + 0.4 ? "" : "none";
    bad.style.opacity = Math.min(1, bp) * (1 - ease.in(prog(t, T_FILE - 0.2, T_FILE + 0.4)));
    bad.style.transform = `translate(-50%,-50%) scale(${0.5 + 0.5 * bp})`;
    // 2: a locked file nobody can open, until the backup brings the keys back
    const fa = env(t, T_FILE, End(2, 0.5), 0.5, 0.5);
    const fp = ease.outBack(prog(t, T_FILE, T_FILE + 0.6));
    locked.style.display = fa > 0 ? "" : "none";
    locked.style.left = "885px"; locked.style.top = "300px";
    locked.style.opacity = fa;
    locked.style.transform = `scale(${1.7 * (0.7 + 0.3 * fp)})`;
    const ok = t >= T_BACKUP + 0.9;
    stat.style.display = fa > 0 ? "" : "none";
    stat.style.opacity = fa;
    stat.style.borderColor = ok ? "#4cc584" : "#e5484d";
    stat.firstElementChild.textContent = ok ? "✓ Opens again" : "✕ Can’t be opened";
    const ba = env(t, T_BACKUP, End(2, 0.5), 0.4, 0.5);
    const bq = ease.outBack(prog(t, T_BACKUP, T_BACKUP + 0.6));
    bkFile.style.display = ba > 0 ? "" : "none";
    bkFile.style.left = `${520 + 260 * ease.inOutExpo(prog(t, T_BACKUP + 0.5, T_BACKUP + 1.1))}px`;
    bkFile.style.top = "300px";
    bkFile.style.opacity = ba;
    bkFile.style.transform = `scale(${1.4 * (0.6 + 0.4 * bq)})`;
  });
  E.sfx(L(1, 0.0), "pop", 0.6); E.sfx(T_LOST, "lock", 0.8); E.sfx(T_FILE, "pop", 0.6); E.sfx(T_BACKUP, "pop", 0.7); E.sfx(T_BACKUP + 0.9, "success", 0.7);
  E.caption(L(1, 0.3), End(1, 0.2), "Your keys live [[only on your computer]]");
  E.caption(L(2, 0.5), End(2, 0.3), "Lose it, and files sent to you [[stay locked]]");

  // ---------------------------------------------------------------- 3. Settings > Backup
  badge(E, L(3, 0.1), End(6, -0.3), AX - 450, 120, `${avatar(ALICE, "#ff6a3d")}<span>Alice’s computer</span>`);
  E.cam(0, AX, Y, 0.95);
  const C = E.cursor;
  C.place([1500, 900]); C.show(L(3, 0.2));
  C.move(L(3, 0.2), L(3, 0.9), () => alice.center(nav("settings")));
  alice.click(L(3, 1.0), nav("settings"));
  alice.scrollTo(L(3, 1.3), L(3, 2.0), card(2), 14);
  E.camOn(L(3, 1.6), L(3, 2.4), () => alice.rectFinal(card(2)), 1.3, { dy: 40 });
  E.spot(L(3, 1.9), End(3, 0.3), () => alice.rect(card(2)), "Backup", { side: "left", pad: 10 });
  E.caption(L(3, 0.4), End(3, 0.3), "Settings, then [[Backup]]");

  // ---------------------------------------------------------------- 4. recovery password
  const pwi = (n) => (d) => d.querySelectorAll('input[autocomplete="new-password"]')[n];
  C.move(L(4, -0.1), L(4, 0.4), () => alice.center(pwi(0)));
  alice.click(L(4, 0.45), pwi(0));
  alice.type(L(4, 0.5), L(4, 1.4), pwi(0), "maple-tiger-orbit-77");
  alice.type(L(4, 1.5), L(4, 2.1), pwi(1), "maple-tiger-orbit-77");
  C.move(L(4, 2.1), L(4, 2.6), () => alice.center(byText("Save backup…", "button")));
  alice.click(L(4, 2.7), byText("Save backup…", "button"));
  E.caption(L(4, 0.3), End(4, 0.3), "A [[recovery password]], then save");
  const safe = E.add(destination("usb", "A safe place"), null, E.hud);
  const file = E.add(fileIcon("Alice-keys.svxbackup", "svx"), null, E.hud);
  const S0 = L(4, 3.0);
  E.every((t) => {
    const a = env(t, S0 - 0.1, L(5, 0.8), 0.3, 0.5);
    const p = ease.outBack(prog(t, S0 - 0.1, S0 + 0.5));
    const fl = ease.inOutExpo(prog(t, S0 + 0.3, S0 + 0.9));
    safe.style.display = a > 0 ? "" : "none";
    safe.style.left = "1330px"; safe.style.top = "240px";
    safe.style.opacity = a;
    safe.style.transform = `scale(${0.7 + 0.3 * p})`;
    file.style.display = a > 0 ? "" : "none";
    file.style.left = `${460 + (1405 - 460) * fl}px`; file.style.top = `${300 - 0 * fl}px`;
    file.style.opacity = a * (1 - 0.4 * fl);
    file.style.transform = `scale(${1.1 * (1 - 0.35 * fl)})`;
  });
  E.sfx(S0 + 0.3, "swoosh", 0.6); E.sfx(S0 + 0.9, "pop", 0.6);

  // ---------------------------------------------------------------- 5. nobody can recover the password
  E.spot(L(5, 0.0), End(5, 0.2), () => alice.rect(byText("There's no way to recover this password.", "p")), null, { pad: 10 });
  E.caption(L(5, 0.2), End(5, 0.3), "Nobody can recover it. [[Not even us.]]");

  // ---------------------------------------------------------------- 6-7. a new computer
  E.camTo(L(5, 2.5), L(6, 0.5), NX, Y, 0.95, ease.inOutExpo);
  badge(E, L(6, 0.4), End(8, 0.3), NX - 450, 120, `${avatar(ALICE, "#ff6a3d")}<span>A new computer</span>`);
  E.camOn(L(6, 1.6), L(6, 2.4), () => fresh.rect(".provider-buttons"), 1.4, { dy: 50 });
  C.move(L(6, 0.2), L(6, 1.0), () => [NX + 100, Y + 160]);
  C.move(L(6, 1.1), L(6, 1.6), () => fresh.center(".btn-google"));
  fresh.click(L(6, 1.7), ".btn-google");
  fresh.scrollTo(L(6, 2.0), L(6, 2.7), card(1), 24);
  E.camOn(L(6, 2.1), L(6, 3.0), () => fresh.rectFinal(card(1)), 1.2, { dy: 50 });
  E.spot(L(6, 2.4), End(6, 0.2), () => fresh.rect(card(1)), "Restore from your backup", { side: "right", pad: 10 });
  E.caption(L(6, 0.5), End(6, 0.4), "On a new computer, [[restore it]]");
  const rpw = (d) => d.querySelector('input[autocomplete="current-password"]');
  C.move(L(7, -0.4), L(7, 0.1), () => fresh.center(rpw));
  fresh.click(L(7, 0.15), rpw);
  fresh.type(L(7, 0.2), L(7, 0.75), rpw, "maple-tiger-orbit-77");
  C.move(L(7, 0.8), L(7, 1.0), () => fresh.center(byText("Choose backup file…", "button")));
  fresh.click(L(7, 1.05), byText("Choose backup file…", "button"));
  E.release(L(7, 1.6), "restore");
  E.sfx(L(7, 1.7), "success", 0.7);
  C.show(L(8, 0.0), false);

  // ---------------------------------------------------------------- 8. everything opens again
  E.camOn(L(8, -0.3), L(8, 0.6), () => fresh.rect(".panel-ok"), 1.35, { dy: 40 });
  E.spot(L(8, 0.4), End(8, 0.0), () => fresh.rect(".panel-ok"), "Your keys are back", { side: "right", pad: 12 });
  E.caption(L(8, 0.3), End(8, 0.3), "Everything opens [[again]]");

  // ---------------------------------------------------------------- 9-11. outro
  const mark = E.add(`<div style="position:absolute;left:960px;top:330px;transform:translate(-50%,-50%)">${symbol(230)}</div>`, null, E.hud);
  const word = E.add(`<div style="position:absolute;left:960px;top:520px;transform:translate(-50%,-50%);font:700 96px Unbounded;letter-spacing:.04em">SVX</div>`, null, E.hud);
  const site = E.add(`<div style="position:absolute;left:960px;top:920px;transform:translate(-50%,-50%);font:400 34px 'IBM Plex Mono';letter-spacing:.1em;color:#a8a59e">getsvx.me</div>`, null, E.hud);
  E.every((t) => {
    const a = ease.inOut(prog(t, L(9, -0.2), L(9, 0.5)));
    const p = ease.outExpo(prog(t, L(9, -0.1), L(9, 0.9)));
    const w = ease.outExpo(prog(t, L(9, 0.3), L(9, 1.2)));
    const s = ease.out(prog(t, L(11, 0.4), L(11, 1.0)));
    mark.style.display = a > 0 ? "" : "none";
    mark.style.opacity = a;
    mark.style.transform = `translate(-50%,-50%) scale(${0.6 + 0.4 * p}) rotate(${(1 - p) * -25}deg)`;
    word.style.opacity = w * a;
    word.style.transform = `translate(-50%,-50%) translateY(${(1 - w) * 30}px)`;
    site.style.opacity = s;
  });
  E.sfx(L(9, 0.0), "whoosh", 0.7); E.sfx(L(11, 0.0), "success", 0.8);
  E.caption(L(10, 0.0), End(10, 0.3), "Send it. [[Stay in control.]]", { y: 700, size: 56 });
  E.caption(L(11, 0.0), End(11, 0.9), "Welcome to [[SVX]]", { y: 700, size: 56 });

  E.every((t) => { E.root.style.opacity = 1 - ease.in(prog(t, E.duration - 0.8, E.duration)); });
}
