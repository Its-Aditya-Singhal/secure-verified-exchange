// Chapter 4: Open a file you received. Bob double-clicks Project-plan.svx.
import { ease, env, prog } from "../engine.js";
import { ALICE, BOB, EVE, NOW, avatar, badge, desktopFile, signedIn, statusFor, winHello } from "./common.js";

const PATH = "/Users/bob/Downloads/Project-plan.svx";

export default async function scene(E) {
  const L = (i, d) => E.at(i, d), End = (i, d) => E.end(i, d);

  const WX = 1010, WY = 560, EX = 3010;
  let pending = [];
  const takePending = () => { const p = pending; pending = []; return p; };
  const app = await E.appWindow({
    id: "bob", x: WX, y: WY, os: "win",
    fixtures: signedIn(BOB, {
      take_pending: takePending,
      status: statusFor(BOB),
      open: async () => {
        await E.gate("open");
        return { path: "/Users/bob/Documents/SVX/Project-plan.pdf", name: "Project-plan.pdf", is_folder: false, size: 482113, sender_org: ALICE.account, artifact_id: "5a1f", classification: null, description: null, can_open: true };
      },
    }),
  });
  let eveP = [];
  const eve = await E.appWindow({
    id: "eve", x: EX, y: WY, os: "mac",
    fixtures: signedIn(EVE, { take_pending: () => { const p = eveP; eveP = []; return p; }, status: statusFor(EVE) }),
  });
  const win = E.frames.get("bob").el;
  const ui = (sel) => () => app.rect(sel);
  const byText = (text, within) => (d) => [...d.querySelectorAll(within)].find((e) => e.textContent.trim() === text);
  const openBtn = byText("Open securely", "button");
  /** dt + dd of a row in the app's key/value list, as one rectangle. */
  const row = (scope, which) => () => {
    const f = app.q((d) => d.querySelector(`${scope} dl.facts`));
    if (!f) return null;
    const kids = [...f.children];
    const i = which < 0 ? kids.length - 2 : which * 2;
    const a = app.rect(() => kids[i]), b = app.rect(() => kids[i + 1]);
    return a && b ? { x: a.x, y: a.y, w: b.x + b.w - a.x, h: Math.max(a.h, b.h) } : null;
  };

  E.every((t) => { E.world.style.opacity = ease.out(prog(t, L(1, -0.55), L(1, 0.25))); });
  E.titleCard(0.05, L(1, -0.1), 4, "Open a file you received");

  // ---------------------------------------------------------------- Bob's desktop
  badge(E, L(1, 0.1), End(7), 330, 120, `${avatar(BOB, "#9db5c9")}<span>Bob’s computer</span>`);
  const icon = desktopFile(E, "Project-plan.svx", "svx", 160, 430, L(1, 0.3));
  const FILE = [235, 505];
  const POP = L(1, 2.45);
  E.every((t) => {
    const sel = prog(t, L(1, 2.0), L(1, 2.1));
    icon.style.background = `rgba(255,255,255,${0.12 * sel})`;
    icon.style.borderRadius = "14px";
    icon.style.padding = "8px 0 6px";
    icon.style.marginLeft = "-0px";
    // Bob's window opens when the file is double-clicked.
    const p = ease.outExpo(prog(t, POP, POP + 0.7));
    win.style.opacity = Math.min(1, p * 1.5);
    win.style.transform = `scale(${0.9 + 0.1 * p}) translateY(${(1 - p) * 40}px)`;
  });
  E.sfx(POP, "whoosh", 0.5);

  // ---------------------------------------------------------------- cursor
  const C = E.cursor;
  C.place([760, 880]);
  C.show(L(1, 0.7));
  C.move(L(1, 0.8), L(1, 1.8), [FILE[0] + 8, FILE[1] - 6]);
  C.press(L(1, 2.0)); C.press(L(1, 2.2));
  E.sfx(L(1, 2.0), "click", 0.8); E.sfx(L(1, 2.2), "click", 0.8);
  app.emit(POP - 0.05, "open-file", null);
  E.do(POP - 0.1, () => { pending = [PATH]; });

  // ---------------------------------------------------------------- camera
  E.cam(0, 760, 560, 0.9);
  E.cam(L(1, 0.1), 700, 540, 1.0);
  E.camTo(L(1, 2.3), L(2, -0.2), WX, WY, 0.95);
  E.camOn(L(2, 0.0), L(2, 1.0), () => app.rectFinal("section.card"), 1.35, { dy: 50 });
  E.camOn(L(3, 0.0), L(3, 0.9), row("section.card", 0), 1.9, { dy: 90 });
  E.camOn(End(3, 0.15), L(4, 0.2), () => app.rectFinal(openBtn), 1.6, { dy: -20, dx: -80 });
  E.camTo(L(4, 0.55), L(4, 1.3), WX, WY, 0.95);          // pull back for the confirm prompt
  E.camOn(L(5, 1.1), L(5, 2.0), ui("ol.timeline"), 1.3, { dy: 30 });
  E.camOn(L(6, 0.9), L(7, 0.3), ui(".panel-ok"), 1.25, { dy: 30 });
  E.camTo(L(8, -0.5), L(8, 0.9), EX, WY, 0.92, ease.inOutExpo);   // over to Eve

  // ---------------------------------------------------------------- 1. the check
  E.spot(L(3, 0.2), End(3, 0.0), row("section.card", 0), "Signature verified", { side: "below" });
  E.caption(L(2, 0.4), End(2, 0.2), "SVX [[checks the file]] first");
  E.caption(L(3, 0.4), End(3, 0.0), "Really from [[Alice]] and unchanged");

  // ---------------------------------------------------------------- 2. Bob confirms
  C.move(End(3, 0.0), L(4, 0.3), () => app.center(openBtn));
  app.click(L(4, 0.35), openBtn);
  const wh = E.add(winHello(), null, E.hud);
  const tag = E.add(`<div class="badge" style="position:absolute">Windows Hello, or your password</div>`, null, E.hud);
  const pinBox = wh.querySelector(".pin");
  const T0 = L(4, 0.7), T1 = L(5, 0.9);
  E.sfx(T0 + 0.1, "pop", 0.7);
  E.every((t) => {
    const a = env(t, T0, T1, 0.5, 0.45);
    for (const [el, x, y, d] of [[wh, 960, 560, 0], [tag, 960, 320, 0.15]]) {
      el.style.display = a > 0 ? "" : "none";
      const p = ease.outBack(prog(t, T0 + d, T0 + 0.65 + d));
      el.style.left = `${x}px`; el.style.top = `${y}px`;
      el.style.opacity = a;
      el.style.transform = `translate(-50%,-50%) scale(${0.88 + 0.12 * p}) translateY(${(1 - p) * 30}px)`;
    }
    const n = Math.floor(prog(t, T0 + 0.5, T1 - 0.5) * 6);
    if (pinBox.childElementCount !== n) pinBox.innerHTML = "<i style='width:12px;height:12px;border-radius:50%;background:#fff;display:block'></i>".repeat(n);
  });
  for (let i = 0; i < 6; i++) E.sfx(T0 + 0.5 + i * ((T1 - T0 - 1.0) / 6), "key", 0.35);
  E.sfx(T1 - 0.2, "success", 0.6);
  E.caption(L(4, 0.5), L(5, 0.8), "Bob confirms it’s [[him]]");

  // ---------------------------------------------------------------- 3. the live steps
  const step = (t, name, sender = null) => app.emit(t, "open-progress", { step: name, index: 0, sender });
  step(L(4, 0.45), "verifying");
  step(L(4, 0.55), "signature_valid", "Alice Example");
  step(L(5, 1.0), "connecting");
  step(L(5, 2.0), "checking_authorization");
  step(End(5, -0.5), "access_approved");
  step(L(6, 0.3), "decrypting");
  E.sfx(L(5, 1.0), "tick", 0.5); E.sfx(L(5, 2.0), "tick", 0.5); E.sfx(End(5, -0.5), "tick", 0.5); E.sfx(L(6, 0.3), "tick", 0.5);
  E.spot(L(5, 2.1), End(5, 0.2), ui('li.step[data-step="checking_authorization"]'), "Alice’s rules", { side: "right", pad: 10 });
  E.caption(L(5, 0.9), End(5, 0.1), "Then [[Alice’s rules]] are checked");
  E.release(L(6, 1.3), "open");
  E.sfx(L(6, 1.35), "success", 0.7);

  // ---------------------------------------------------------------- 4. unlocked and saved
  E.caption(L(6, 1.0), End(6, 0.2), "Unlocked [[on this computer]]");
  E.spot(L(7, -0.1), End(7, 0.4), row(".panel-ok", -1), "Only Bob can read it", { side: "below" });
  E.caption(L(7, 0.1), End(7, 0.4), "Saved where [[only Bob]] can read it");
  C.show(L(7, 1.0), false);

  // ---------------------------------------------------------------- 5. someone else
  const eveBadge = badge(E, L(8, 0.0), End(8, 0.4), EX - 520, 150, `${avatar(EVE, "#c9a3e8")}<span>Eve’s computer</span>`);
  eveBadge.style.left = `${EX - 450}px`;
  const stray = E.add(`<div class="fileicon" style="width:150px"><div class="doc svx"><div class="lockmark" style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center"></div></div><div class="nm">Project-plan.svx</div></div>`, null);
  E.every((t) => {
    const f = ease.inOutExpo(prog(t, L(8, -0.4), L(8, 0.8)));
    const a = env(t, L(8, -0.5), L(8, 1.1), 0.25, 0.3);
    stray.style.display = a > 0 ? "" : "none";
    stray.style.left = `${1700 + (EX - 160 - 1700) * f}px`; stray.style.top = "430px";
    stray.style.opacity = a;
    stray.style.transform = `scale(${1 + 0.15 * Math.sin(Math.PI * f)})`;
  });
  E.sfx(L(8, -0.4), "whoosh", 0.5);
  E.do(L(8, 1.2), () => { eveP = [PATH]; eve.win.svxEmit("open-file", null); });
  E.sfx(L(8, 1.6), "lock", 0.6);
  E.spot(L(8, 1.9), End(8, 0.3), () => eve.rect(".panel"), "Won’t open for Eve", { side: "below", pad: 10 });
  E.caption(L(8, 0.6), End(8, 0.4), "A copy for the wrong person [[won’t open]]");

  E.every((t) => { E.root.style.opacity = 1 - ease.in(prog(t, E.duration - 0.6, E.duration)); });
}
