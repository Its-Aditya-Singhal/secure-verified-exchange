// Chapter 6: View-only files. Alice ticks "View only"; Bob reads it in the protected viewer.
import { ease, env, prog } from "../engine.js";
import { ALICE, BOB, NOW, avatar, badge, signedIn, viewerWindow } from "./common.js";

const SAVE = `<svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linejoin="round"><path d="M5 3h11l3 3v15H5z"/><path d="M8 3v6h8V3M8 21v-7h8v7"/></svg>`;
const COPY = `<svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linejoin="round"><rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V4H5v13h3"/></svg>`;
const PRINT = `<svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linejoin="round"><path d="M7 9V3h10v6M7 17H4V9h16v8h-3"/><rect x="7" y="14" width="10" height="7"/></svg>`;
const CAMERA = `<svg viewBox="0 0 64 64" fill="none" stroke="#f0b456" stroke-width="4" stroke-linejoin="round"><rect x="6" y="18" width="52" height="34" rx="6"/><path d="M22 18l4-8h12l4 8"/><circle cx="32" cy="35" r="10"/></svg>`;

export default async function scene(E) {
  const L = (i, d) => E.at(i, d), End = (i, d) => E.end(i, d);
  const X = 1010, Y = 560;

  const alice = await E.appWindow({
    id: "alice", x: X, y: Y, os: "mac", now: NOW,
    fixtures: signedIn(ALICE, { view_check: { ok: true, office: false, reason: null } }),
  });
  const aliceEl = E.frames.get("alice").el;
  const viewer = viewerWindow(E, X, Y, BOB);
  const card = (i) => (d) => d.querySelectorAll("section.card")[i];
  const viewToggle = (d) => [...d.querySelectorAll("label.toggle")].find((l) => l.querySelector("strong")?.textContent.trim() === "View only");

  E.every((t) => { E.world.style.opacity = ease.out(prog(t, L(1, -0.55), L(1, 0.25))); });
  E.titleCard(0.05, L(1, -0.1), 6, "View-only files");

  // While the title plays: Alice drops her file in and scrolls to her controls.
  alice.drop(0.3, ["/Users/alice/Documents/Project-plan.pdf"]);
  alice.scrollTo(1.0, 1.6, card(2), 18);
  badge(E, L(1, 0.1), End(1, 0.1), X - 450, 120, `${avatar(ALICE, "#ff6a3d")}<span>Alice’s computer</span>`);
  badge(E, L(2, 0.3), End(4), X - 450, 120, `${avatar(BOB, "#9db5c9")}<span>Bob’s computer</span>`);

  // ---------------------------------------------------------------- camera
  E.cam(0, X, Y, 0.9);
  E.camOn(L(1, -0.3), L(1, 0.6), () => alice.rectFinal(viewToggle), 1.6, { dy: 70 });
  E.camTo(L(2, -0.2), L(2, 0.8), X, Y, 0.95);
  E.camTo(L(3, 0.0), L(3, 1.0), X, Y - 30, 1.0);
  E.camTo(L(4, -0.1), L(4, 0.9), X, Y, 0.92);

  // ---------------------------------------------------------------- 1. tick "View only"
  const C = E.cursor;
  C.place([1500, 900]); C.show(L(1, -0.2));
  C.move(L(1, -0.1), L(1, 1.0), () => alice.center((d) => viewToggle(d).querySelector("input")));
  alice.click(L(1, 1.2), (d) => viewToggle(d).querySelector("input"), "tick");
  E.spot(L(1, 0.9), End(1, 0.1), () => alice.rect(viewToggle), "Tick View only", { side: "below", pad: 10 });
  E.caption(L(1, 0.3), End(1, 0.1), "Tick [[View only]] before sending");
  C.show(End(1, 0.3), false);

  // ---------------------------------------------------------------- 2. Bob reads it in the viewer
  E.every((t) => {
    const out = ease.inOut(prog(t, L(2, -0.5), L(2, 0.0)));
    aliceEl.style.opacity = 1 - out;
    const p = ease.outExpo(prog(t, L(2, -0.15), L(2, 0.7)));
    viewer.style.display = p > 0 ? "" : "none";
    viewer.style.opacity = Math.min(1, p * 1.6);
    viewer.style.transform = `scale(${0.93 + 0.07 * p}) translateY(${(1 - p) * 40}px)`;
  });
  E.sfx(L(2, -0.15), "whoosh", 0.6);
  E.caption(L(2, 0.3), End(2, 0.2), "Bob reads it [[inside SVX]]");
  E.spot(L(2, 1.0), End(2, 0.1), () => ({ x: X - 280, y: Y - 330, w: 560, h: 700 }), null, { pad: 6 });

  // ---------------------------------------------------------------- 3. no save, copy or print
  const chips = [[SAVE, "Save", -380, 0.0], [COPY, "Copy", 0, 0.7], [PRINT, "Print", 380, 1.4]].map(([svg, label, dx, d]) => {
    const el = E.add(`<div class="chip-x" style="left:${960 + dx - 120}px;top:740px">${svg}<span>${label}</span><span class="x" style="color:#e5484d;font-size:34px;margin-left:6px">✕</span></div>`, null, E.hud);
    return { el, d };
  });
  E.every((t) => {
    for (const { el, d } of chips) {
      const a = env(t, L(3, d - 0.2), End(3, 0.1), 0.4, 0.4);
      const p = ease.outBack(prog(t, L(3, d - 0.2), L(3, d + 0.35)));
      el.style.display = a > 0 ? "" : "none";
      el.style.opacity = a;
      el.style.transform = `translateY(${(1 - p) * 40}px) scale(${0.9 + 0.1 * p})`;
      const x = el.querySelector(".x");
      x.style.transform = `scale(${ease.outBack(prog(t, L(3, d + 0.25), L(3, d + 0.6)))})`;
      x.style.display = t >= L(3, d + 0.25) ? "inline-block" : "none";
    }
  });
  for (const [, , , d] of [[0, 0, 0, 0.25], [0, 0, 0, 0.95], [0, 0, 0, 1.65]]) E.sfx(L(3, d), "tick", 0.7);
  E.caption(L(3, 0.2), End(3, 0.2), "No saving, copying or [[printing]]", { y: 968 });

  // ---------------------------------------------------------------- 4. a screenshot comes out black
  const keys = E.add(`<div style="position:absolute;left:960px;top:200px;transform:translateX(-50%);display:flex;gap:70px;align-items:center;font:500 24px 'IBM Plex Sans';color:#a8a59e"><div style="text-align:center"><div style="display:flex;gap:10px"><span class="key">⌘</span><span class="key">⇧</span><span class="key">4</span></div><div style="margin-top:12px">Mac</div></div><div style="text-align:center"><div style="display:flex;gap:10px"><span class="key">⊞</span><span class="key">⇧</span><span class="key">S</span></div><div style="margin-top:12px">Windows</div></div></div>`, null, E.hud);
  const flash = E.add(`<div style="position:absolute;inset:0;background:#fff;opacity:0;z-index:70"></div>`, null, E.hud);
  const shot = E.add(`<div style="position:absolute;right:60px;bottom:230px;width:380px;border-radius:14px;overflow:hidden;background:#17181c;border:1px solid #444;box-shadow:0 30px 70px rgba(0,0,0,.6)"><div style="height:230px;background:#000"></div><div style="padding:10px 14px;font:500 16px 'IBM Plex Sans';color:#a8a59e">Screenshot · Oct 9, 3:24 PM</div></div>`, null, E.hud);
  const T4 = L(4, 0.5);
  E.every((t) => {
    const a = env(t, L(4, 0.0), End(4, -0.2), 0.4, 0.4);
    keys.style.display = a > 0 ? "flex" : "none";
    keys.style.opacity = a;
    keys.style.transform = `translateX(-50%) translateY(${(1 - ease.outExpo(prog(t, L(4, 0.0), L(4, 0.6)))) * -40}px)`;
    const f = t >= T4 && t < T4 + 0.35 ? 1 - prog(t, T4, T4 + 0.35) : 0;
    flash.style.display = f > 0 ? "" : "none";
    flash.style.opacity = f * 0.55;
    const p = ease.outBack(prog(t, T4 + 0.5, T4 + 1.1));
    const o = env(t, T4 + 0.5, End(4, 0.3), 0.3, 0.4);
    shot.style.display = o > 0 ? "" : "none";
    shot.style.opacity = o;
    shot.style.transform = `translateX(${(1 - p) * 120}px)`;
  });
  E.sfx(T4, "swoosh", 0.7); E.sfx(T4 + 0.5, "pop", 0.8);
  E.caption(L(4, 1.4), End(4, 0.3), "The screenshot is [[black]]");

  // ---------------------------------------------------------------- 5. what it works for
  const TYPES = [["PDF", "PDF", "#d9534f", 0.15], ["IMG", "Images", "#2f9e8f", 1.0], ["DOC", "Word", "#3a76d8", 1.9], ["XLS", "Excel", "#2e9b5a", 2.8], ["PPT", "PowerPoint", "#e0793a", 3.6]];
  const tiles = TYPES.map(([g, label, color, d], i) => ({ el: E.add(`<div class="ftile" style="left:${960 + (i - 2) * 250 - 105}px;top:400px;background:${color}">${g}<small>${label}</small></div>`, null, E.hud), d }));
  E.every((t) => {
    const dim = ease.inOut(prog(t, L(5, -0.3), L(5, 0.3)));
    viewer.style.filter = dim > 0 ? `blur(${dim * 8}px) brightness(${1 - dim * 0.6})` : "";
    for (const { el, d } of tiles) {
      const p = ease.outBack(prog(t, L(5, d), L(5, d + 0.55)));
      const o = Math.min(1, p * 1.4) * (1 - ease.in(prog(t, End(5, 0.0), End(5, 0.4))));
      el.style.display = o > 0.01 ? "" : "none";
      el.style.opacity = o;
      el.style.transform = `scale(${0.6 + 0.4 * p}) translateY(${(1 - p) * 50}px)`;
    }
  });
  for (const [, , , d] of TYPES) E.sfx(L(5, d + 0.05), "pop", 0.6);
  E.caption(L(5, 0.3), End(5, 0.2), "PDFs, images, [[Word]], [[Excel]], [[PowerPoint]]", { y: 780, size: 40 });

  // ---------------------------------------------------------------- 6. the honest note
  E.caption(L(6, 0.0), End(6, 0.6), "One honest [[note]]", { y: 470, size: 84 });

  // ---------------------------------------------------------------- 7. a phone photo
  const scene7 = E.add(`<div style="position:absolute;inset:0"><div class="m7" style="position:absolute;left:520px;top:250px;width:640px;height:420px;border-radius:20px;background:#1d1f24;border:10px solid #3d4048;overflow:hidden"><div style="margin:30px auto;width:250px;height:360px;background:#f7f5f0;border-radius:4px;padding:26px 24px;font:700 20px 'Unbounded';color:#16171b">Project plan<div style="height:9px;background:#dcd8ce;border-radius:5px;margin-top:20px;width:90%"></div><div style="height:9px;background:#dcd8ce;border-radius:5px;margin-top:12px;width:70%"></div><div style="height:9px;background:#dcd8ce;border-radius:5px;margin-top:12px;width:82%"></div></div></div><div class="ph" style="position:absolute;left:1180px;top:340px;width:150px;height:290px;border-radius:26px;background:#2c2e35;border:5px solid #5b5e69;display:flex;align-items:flex-start;justify-content:center;padding-top:30px"><div style="width:62px;height:62px;border-radius:50%;background:#101114;border:5px solid #4a4d57"></div></div><div class="fl" style="position:absolute;inset:0;background:#fff;opacity:0"></div><div class="cm" style="position:absolute;left:1030px;top:230px;width:84px;height:84px">${CAMERA}</div></div>`, null, E.hud);
  const ph = scene7.querySelector(".ph"), fl = scene7.querySelector(".fl"), cm = scene7.querySelector(".cm"), mon = scene7.querySelector(".m7");
  const T7 = L(7, 1.7);
  E.every((t) => {
    const a = env(t, L(7, -0.2), End(7, 0.2), 0.5, 0.4);
    scene7.style.display = a > 0 ? "" : "none";
    scene7.style.opacity = a;
    const p = ease.outBack(prog(t, L(7, -0.1), L(7, 0.8)));
    ph.style.transform = `translateX(${(1 - p) * 260}px) rotate(${-10 + 10 * p}deg)`;
    mon.style.transform = `translateY(${(1 - ease.outExpo(prog(t, L(7, -0.2), L(7, 0.6)))) * 40}px)`;
    const f = t >= T7 && t < T7 + 0.35 ? 1 - prog(t, T7, T7 + 0.35) : 0;
    fl.style.opacity = f * 0.5;
    const c = ease.outBack(prog(t, T7 + 0.3, T7 + 0.9));
    cm.style.opacity = c;
    cm.style.transform = `scale(${c}) rotate(${(1 - c) * -20}deg)`;
  });
  E.sfx(L(7, 0.0), "whoosh", 0.5); E.sfx(T7, "click", 0.9);
  E.caption(L(7, 0.2), End(7, 0.3), "A phone photo [[can’t be stopped]]", { y: 810 });

  // ---------------------------------------------------------------- 8. so only send it to people you trust
  const trust = E.add(`<div style="position:absolute;left:960px;top:380px;transform:translate(-50%,-50%);text-align:center"><div style="width:190px;height:190px;border-radius:50%;margin:0 auto;background:#9db5c9;color:#16171b;font:700 90px/190px Unbounded;box-shadow:0 0 0 8px rgba(76,197,132,.9),0 30px 70px rgba(0,0,0,.5)">B</div><div style="margin-top:26px;font:600 38px 'IBM Plex Sans'">Someone you trust</div></div>`, null, E.hud);
  E.every((t) => {
    const a = env(t, L(8, -0.2), End(8, 0.3), 0.5, 0.5);
    const p = ease.outBack(prog(t, L(8, -0.1), L(8, 0.7)));
    trust.style.display = a > 0 ? "" : "none";
    trust.style.opacity = a;
    trust.style.transform = `translate(-50%,-50%) scale(${0.7 + 0.3 * p})`;
  });
  E.sfx(L(8, 0.0), "success", 0.5);
  E.caption(L(8, 0.3), End(8, 0.4), "View-only is for people you [[trust]]");

  E.every((t) => { E.root.style.opacity = 1 - ease.in(prog(t, E.duration - 0.6, E.duration)); });
}
