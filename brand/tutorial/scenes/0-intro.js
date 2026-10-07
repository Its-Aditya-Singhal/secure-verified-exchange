// Chapter 0: What SVX is. Pure motion graphics, no app window.
import { ease, env, prog, symbol } from "../engine.js";
import { avatar, destination, fileIcon } from "./common.js";

const LAPTOP = `<svg viewBox="0 0 240 170" width="380" fill="none" stroke="#a8a59e" stroke-width="5" stroke-linejoin="round"><rect x="40" y="14" width="160" height="104" rx="9" fill="#1d1f24"/><path d="M14 142h212l-14 14H28z"/></svg>`;
const CLOUD = `<svg viewBox="0 0 220 140" width="300" fill="#1d1f24" stroke="#4a4d57" stroke-width="5" stroke-linejoin="round"><path d="M58 112a34 34 0 0 1-4-67 46 46 0 0 1 88-8 38 38 0 0 1 22 75z"/></svg>`;
const KEY = `<svg viewBox="0 0 320 120" width="380" fill="#ff6a3d"><path fill-rule="evenodd" d="M62 14a46 46 0 1 0 0 92a46 46 0 1 0 0-92zm0 30a16 16 0 1 1 0 32a16 16 0 1 1 0-32z"/><rect x="100" y="52" width="210" height="16" rx="4"/><rect x="230" y="68" width="16" height="30" rx="3"/><rect x="268" y="68" width="16" height="22" rx="3"/></svg>`;
const LOCK = `<svg viewBox="0 0 64 64" width="44" fill="none" stroke="#4cc584" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"><rect x="14" y="28" width="36" height="28" rx="6" fill="#16171b"/><path d="M22 28V20a10 10 0 0 1 20 0v8"/></svg>`;
const clipL = "polygon(0 0,52% 0,58% 25%,50% 50%,58% 75%,52% 100%,0 100%)";
const clipR = "polygon(52% 0,100% 0,100% 100%,52% 100%,58% 75%,50% 50%,58% 25%)";

export default async function scene(E) {
  const L = (i, d) => E.at(i, d), End = (i, d) => E.end(i, d);
  const pos = (html, x, y) => E.add(`<div style="position:absolute;left:${x}px;top:${y}px;will-change:transform">${html}</div>`, null);
  const stat = (el) => { el.style.position = "static"; return el.outerHTML; };
  const show = (el, a, tf) => { el.style.display = a > 0.002 ? "" : "none"; el.style.opacity = a; if (tf) el.style.transform = `translate(-50%,-50%) ${tf}`; };

  // ---------------------------------------------------------------- cast
  const logo = pos(`${symbol(250)}<div style="margin-top:18px;font:700 110px Unbounded;letter-spacing:.05em;text-align:center">SVX</div>`, 960, 470);
  const laptop = pos(`${LAPTOP}<div style="text-align:center;margin-top:10px;font:600 30px 'IBM Plex Sans'">Alice’s computer</div>`, 420, 560);
  const file = pos(stat(fileIcon("Project-plan.pdf")), 420, 520);
  const lockedFile = pos(`<div class="fileicon" style="position:static"><div class="doc svx"><div class="lockmark">${symbol(64)}</div></div><div class="nm">Project-plan.svx</div></div>`, 420, 520);
  const bob = pos(`<div style="width:140px;height:140px;border-radius:50%;background:#9db5c9;color:#16171b;font:700 66px/140px Unbounded;text-align:center;box-shadow:0 0 0 7px #4cc584">B</div><div style="text-align:center;margin-top:14px;font:600 30px 'IBM Plex Sans'">Bob ✓</div>`, 1500, 520);
  const eve = pos(`<div style="width:120px;height:120px;border-radius:50%;background:#c9a3e8;color:#16171b;font:700 56px/120px Unbounded;text-align:center;opacity:.55">E</div><div style="text-align:center;margin-top:12px;font:600 26px 'IBM Plex Sans';color:#a8a59e">Someone else</div>`, 1500, 830);
  const stop = pos(`<div style="font:700 120px Unbounded;color:#e5484d;text-shadow:0 10px 40px rgba(0,0,0,.6)">✕</div>`, 1250, 830);
  const cloud = pos(`${CLOUD}<div style="position:absolute;left:0;right:0;top:56px;text-align:center;font:600 30px 'IBM Plex Sans'">SVX service</div>`, 960, 230);
  const nofile = pos(`<div style="font:700 90px Unbounded;color:#e5484d;text-shadow:0 10px 40px rgba(0,0,0,.6)">✕</div>`, 700, 290);
  const keyL = pos(`<div style="clip-path:${clipL}">${KEY}</div>`, 960, 560);
  const keyR = pos(`<div style="clip-path:${clipR}">${KEY}</div>`, 960, 560);
  const keyCap = pos(`<div style="font:600 30px 'IBM Plex Sans';white-space:nowrap;text-align:center">One key</div>`, 960, 660);
  const halfSvc = pos(`<div style="font:600 28px 'IBM Plex Sans';color:#ff6a3d;white-space:nowrap">holds half</div>`, 960, 330);
  const halfBob = pos(`<div style="font:600 28px 'IBM Plex Sans';color:#ff6a3d;white-space:nowrap;text-align:center">the other half</div>`, 1500, 800);
  const dests = [["chat", "WhatsApp", 540], ["mail", "Email", 960], ["usb", "USB stick", 1380]].map(([k, label, x]) => ({
    x, card: pos(stat(destination(k, label)), x, 850), copy: pos(stat(fileIcon("", "svx")), 420, 520), lock: pos(LOCK, x + 100, 770),
  }));
  const free = pos(`<div style="padding:26px 70px;border-radius:999px;background:#ff6a3d;color:#16171b;font:700 130px Unbounded;box-shadow:0 30px 90px rgba(255,106,61,.4)">Free</div>`, 960, 470);

  // ---------------------------------------------------------------- camera
  E.cam(0, 960, 540, 1.0);
  E.camTo(0.3, L(1, -0.2), 960, 520, 1.12);
  E.camTo(L(1, -0.1), L(1, 1.0), 960, 640, 0.95);
  E.camTo(L(2, -0.2), L(2, 0.8), 470, 560, 1.55);
  E.camTo(End(2, -0.5), L(3, 0.4), 840, 420, 1.0);
  E.camTo(L(4, -0.1), L(4, 0.9), 960, 520, 1.25);
  E.camTo(L(5, -0.2), L(5, 0.8), 1000, 440, 0.95);
  E.camTo(L(6, -0.2), L(6, 0.8), 960, 640, 0.92);
  E.camTo(L(9, -0.2), L(9, 0.8), 960, 540, 1.0);

  // ---------------------------------------------------------------- 0. This is SVX
  E.every((t) => {
    const a = ease.outExpo(prog(t, 0.1, 1.0)) * (1 - ease.inOut(prog(t, L(1, -0.3), L(1, 0.2))));
    const p = ease.outExpo(prog(t, 0.0, 1.1));
    show(logo, a, `scale(${0.7 + 0.3 * p}) rotate(${(1 - p) * -12}deg)`);
  });
  E.sfx(0.1, "whoosh", 0.8); E.sfx(L(0, 0.5), "success", 0.5);

  // ---------------------------------------------------------------- 1. only the person you choose
  E.every((t) => {
    const a = ease.outBack(prog(t, L(1, -0.1), L(1, 0.7)));
    show(laptop, Math.min(1, a * 1.5), `scale(${0.8 + 0.2 * a})`);
    show(bob, ease.outBack(prog(t, L(1, 0.3), L(1, 1.0))) * (1 - ease.in(prog(t, L(5, 2.5), L(6, 0.0)))), `scale(${0.7 + 0.3 * ease.outBack(prog(t, L(1, 0.3), L(1, 1.0)))})`);
    show(eve, ease.outBack(prog(t, L(1, 0.6), L(1, 1.3))) * (1 - ease.in(prog(t, L(2, 0), L(2, 0.6)))), "");
    // The file goes to Bob along an arc, and is stopped on the way to Someone else.
    const f = ease.inOutExpo(prog(t, L(1, 1.2), L(1, 2.4)));
    const fa = env(t, L(1, 0.9), L(2, 0.7), 0.3, 0.5);
    const x = 420 + (1380 - 420) * f, y = 520 - 120 * Math.sin(Math.PI * f);
    file.style.display = fa > 0 ? "" : "none";
    file.style.opacity = fa;
    file.style.transform = `translate(-50%,-50%) translate(${x - 420}px,${y - 520}px) scale(${1 - 0.25 * f})`;
    const sp = ease.outBack(prog(t, L(1, 2.0), L(1, 2.5)));
    show(stop, sp * (1 - ease.in(prog(t, L(2, 0), L(2, 0.5)))), `scale(${0.5 + 0.5 * sp})`);
  });
  E.sfx(L(1, 0.35), "pop", 0.6); E.sfx(L(1, 1.2), "whoosh", 0.5); E.sfx(L(1, 2.0), "lock", 0.7);
  E.caption(L(1, 0.4), End(1, 0.2), "Only [[the person you choose]] can open it");

  // ---------------------------------------------------------------- 2. locked right here
  E.every((t) => {
    const m = ease.inOutExpo(prog(t, L(2, 1.0), L(2, 1.7)));
    show(lockedFile, m, `scale(${0.62 + 0.1 * m}) rotateY(${(1 - m) * 80}deg)`);
  });
  E.sfx(L(2, 1.0), "lock", 0.8);
  E.caption(L(2, 0.6), End(2, 0.3), "Locked [[on your computer]]");

  // ---------------------------------------------------------------- 3. we never receive it
  const arrow = E.add(`<svg style="position:absolute;left:0;top:0" width="1920" height="1080"><path d="M560 470 C700 420 760 330 830 290" stroke="#ff6a3d" stroke-width="6" fill="none" stroke-dasharray="14 12" stroke-linecap="round"/></svg>`, null);
  E.every((t) => {
    const ca = ease.outBack(prog(t, L(3, -0.1), L(3, 0.5))) * (1 - ease.in(prog(t, L(6, -0.3), L(6, 0.3))));
    show(cloud, ca, `scale(${0.8 + 0.2 * ca})`);
    const aa = env(t, L(3, 0.1), L(3, 1.1), 0.25, 0.4);
    arrow.style.display = aa > 0 ? "" : "none"; arrow.style.opacity = aa;
    const na = ease.outBack(prog(t, L(3, 0.4), L(3, 0.8))) * (1 - ease.in(prog(t, L(4, -0.2), L(4, 0.3))));
    show(nofile, na, `scale(${0.5 + 0.5 * na})`);
  });
  E.sfx(L(3, 0.1), "pop", 0.6); E.sfx(L(3, 0.45), "lock", 0.6);
  E.caption(L(3, 0.1), End(3, 0.4), "We [[never receive]] it");

  // ---------------------------------------------------------------- 4. the key splits
  E.every((t) => {
    const a = ease.outBack(prog(t, L(4, -0.2), L(4, 0.5))) * (1 - ease.in(prog(t, L(5, 2.3), L(6, -0.1))));
    const s = ease.inOutExpo(prog(t, L(4, 0.9), L(4, 1.7)));
    const toL = ease.inOutExpo(prog(t, L(5, 0.3), L(5, 1.3)));
    show(keyL, a, `translate(${-80 * s - 40 * toL}px,${-290 * toL}px) rotate(${-10 * s}deg) scale(${1 - 0.15 * toL})`);
    show(keyR, a, `translate(${80 * s + 460 * toL}px,${170 * toL}px) rotate(${10 * s}deg) scale(${1 - 0.15 * toL})`);
    show(keyCap, ease.out(prog(t, L(4, 0.2), L(4, 0.7))) * (1 - ease.in(prog(t, L(4, 1.0), L(4, 1.4)))), "");
    show(halfSvc, ease.out(prog(t, L(5, 1.2), L(5, 1.7))) * (1 - ease.in(prog(t, L(5, 2.5), L(6, -0.1)))), "");
    show(halfBob, ease.out(prog(t, L(5, 1.5), L(5, 2.0))) * (1 - ease.in(prog(t, L(5, 2.4), L(6, -0.2)))), "");
  });
  E.sfx(L(4, 0.9), "swoosh", 0.6); E.sfx(L(5, 0.5), "whoosh", 0.5); E.sfx(L(5, 1.3), "lock", 0.6);
  E.caption(L(4, 0.2), End(4, 0.3), "The key is [[split in two]]");
  E.caption(L(5, 0.4), End(5, 0.3), "We hold [[only half]]");

  // ---------------------------------------------------------------- 5. any way you like
  E.every((t) => {
    for (const [i, d] of dests.map((dd, i) => [i, [0.1, 0.85, 1.4][i]])) {
      const { card, copy, lock } = dests[i];
      const cp = ease.outBack(prog(t, L(7, d - 0.2), L(7, d + 0.4)));
      const out = 1 - ease.in(prog(t, L(9, -0.3), L(9, 0.3)));
      show(card, Math.min(1, cp) * out, `translateY(${(1 - cp) * 60}px)`);
      const ft = L(7, d);
      const f = ease.inOutExpo(prog(t, ft, ft + 0.8));
      const ca = t >= ft ? (1 - prog(t, ft + 0.8, ft + 1.1)) : 0;
      show(copy, ca * out, `translate(${(dests[i].x - 420) * f}px,${(850 - 520) * f}px) scale(${0.9 - 0.45 * f})`);
      const la = ease.outBack(prog(t, L(8, 0.2 + i * 0.25), L(8, 0.7 + i * 0.25))) * out;
      show(lock, la, `scale(${la})`);
    }
    if (t >= L(6, -0.3)) {
      const back = 1 - ease.in(prog(t, L(9, -0.2), L(9, 0.3)));
      show(laptop, back, "");
      show(lockedFile, back, "scale(0.7)");
    }
  });
  E.sfx(L(7, 0.1), "pop", 0.6); E.sfx(L(7, 0.85), "pop", 0.6); E.sfx(L(7, 1.4), "pop", 0.6);
  E.sfx(L(8, 0.2), "tick", 0.5); E.sfx(L(8, 0.45), "tick", 0.5); E.sfx(L(8, 0.7), "tick", 0.5);
  E.caption(L(6, 0.2), End(8, 0.3), "Send it [[any way]] you like. Every copy stays [[locked]].", { y: 968, size: 38 });

  // ---------------------------------------------------------------- 6. free
  E.every((t) => {
    const p = ease.spring(prog(t, L(9, 0.0), L(9, 1.0)));
    const a = Math.min(1, prog(t, L(9, 0.0), L(9, 0.3))) * (1 - ease.in(prog(t, L(10, 0.2), L(10, 1.0))));
    show(free, a, `scale(${0.4 + 0.6 * p}) rotate(${(1 - p) * -8}deg)`);
  });
  E.sfx(L(9, 0.0), "success", 0.9); E.sfx(L(9, 0.0), "pop", 0.7);
  E.caption(L(10, 0.0), End(10, 0.5), "Let’s see [[how it works]]", { y: 760, size: 56 });

  E.every((t) => { E.root.style.opacity = 1 - ease.in(prog(t, E.duration - 0.8, E.duration)); });
}
