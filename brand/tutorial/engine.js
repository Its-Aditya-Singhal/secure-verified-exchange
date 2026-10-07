// Motion engine for the "Learn how to use SVX" videos.
//
// Everything is a pure function of time: window.renderAt(t) draws the frame
// at t seconds, so frames can be rendered one by one at any rate. One-shot
// actions (clicks, typing into the real app, releasing a mock answer) run once,
// in order, as time passes them. Rendering only moves forward.
//
// The app windows are the real desktop UI (out/app, built with mock-tauri.ts)
// in iframes; the engine answers its commands from the scene's fixtures.

export const W = 1920, H = 1080;

// ---------------------------------------------------------------- easing
export const ease = {
  linear: (p) => p,
  inOut: (p) => (p < 0.5 ? 4 * p * p * p : 1 - Math.pow(-2 * p + 2, 3) / 2), // AE "easy ease"
  out: (p) => 1 - Math.pow(1 - p, 3),
  in: (p) => p * p * p,
  outExpo: (p) => (p >= 1 ? 1 : 1 - Math.pow(2, -10 * p)),
  inOutExpo: (p) => (p <= 0 ? 0 : p >= 1 ? 1 : p < 0.5 ? Math.pow(2, 20 * p - 10) / 2 : (2 - Math.pow(2, -20 * p + 10)) / 2),
  outBack: (p) => { const c1 = 1.55, c3 = c1 + 1; return 1 + c3 * Math.pow(p - 1, 3) + c1 * Math.pow(p - 1, 2); },
  outQuint: (p) => 1 - Math.pow(1 - p, 5),
  spring: (p) => (p >= 1 ? 1 : 1 - Math.exp(-6.5 * p) * Math.cos(10.5 * p)),
};
export const clamp = (x, a = 0, b = 1) => Math.min(b, Math.max(a, x));
export const prog = (t, a, b) => clamp((t - a) / (b - a));
const lerp = (a, b, p) => a + (b - a) * p;
const mix = (a, b, p) =>
  typeof a === "number" ? lerp(a, b, p)
    : Array.isArray(a) ? a.map((x, i) => lerp(x, b[i], p))
    : Object.fromEntries(Object.keys(a).map((k) => [k, lerp(a[k], b[k] ?? a[k], p)]));

/** Keyframes [[t, value, easeIntoThisKey?], …]; values are numbers, arrays or flat objects. */
export function kf(t, keys, def = ease.inOut) {
  if (t <= keys[0][0]) return keys[0][1];
  for (let i = 1; i < keys.length; i++) {
    const [b, vb, e] = keys[i];
    if (t <= b) {
      const [a, va] = keys[i - 1];
      return mix(va, vb, (e || def)(b === a ? 1 : (t - a) / (b - a)));
    }
  }
  return keys[keys.length - 1][1];
}

/** 0 → 1 → 0 envelope: in over [a, a+fi], out over [b-fo, b]. */
export function env(t, a, b, fi = 0.4, fo = 0.4, e = ease.inOut) {
  if (t < a || t > b) return 0;
  return Math.min(e(prog(t, a, a + fi)), e(1 - prog(t, b - fo, b)));
}

// ---------------------------------------------------------------- DOM helpers
export const $ = (html) => { const d = document.createElement("div"); d.innerHTML = html.trim(); return d.firstElementChild; };
const css = (el, o) => Object.assign(el.style, o);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const SYM = `<svg viewBox="0 0 64 64" aria-hidden="true"><path fill="var(--bone)" d="M7 4H19L32 17L45 4H57L32 29Z"/><path fill="var(--sig)" d="M7 60H19L32 47L45 60H57L32 35Z"/></svg>`;
/** "Words with [[a highlight]]" -> word spans that can rise one by one. */
export function words(text) {
  const out = [];
  let hl = false;
  for (const raw of text.split(" ")) {
    let w = raw;
    if (w.startsWith("[[")) { hl = true; w = w.slice(2); }
    const close = w.includes("]]");
    if (close) w = w.replace("]]", "");
    out.push(`<span class="w${hl ? " hl" : ""}"><span>${w}</span></span>`);
    if (close) hl = false;
  }
  return out.join(" ");
}
export const symbol = (size) => `<span class="sym" style="width:${size}px;height:${size}px">${SYM}</span>`;

// ---------------------------------------------------------------- the engine
export class Engine {
  constructor(timing, chapter) {
    this.timing = timing;
    this.chapter = chapter;
    this.L = timing.lines.map(([start, end, text]) => ({ start, end, text }));
    this.duration = timing.duration;
    this.updaters = [];          // (t) => void, every frame
    this.actions = [];           // [t, fn], once
    this.done = 0;               // index of the next action
    this.cues = [];              // [t, sound] for the soundtrack
    this.gates = new Map();
    this.frames = new Map();     // iframe id -> {el, fixtures}
    this.camKeys = [[0, { x: W / 2, y: H / 2, z: 1 }]];
    this.lastT = -1;

    this.root = document.getElementById("stage");
    this.world = $(`<div id="world"></div>`);
    this.hud = $(`<div id="hud"></div>`);
    this.root.append(this.world, this.hud);
    this.bg = document.getElementById("bg");
    this.grid = document.getElementById("grid");
    this.grain = document.getElementById("grain");
    this.cursor = new Cursor(this);
    window.svxMock = (cmd, args, frame) => this.mock(cmd, args, frame);
  }

  // ---- time helpers: the voice drives everything
  /** Start of spoken line i (plus an offset in seconds). */
  at(i, d = 0) { return this.L[i].start + d; }
  /** End of spoken line i. */
  end(i, d = 0) { return this.L[i].end + d; }
  /** A point a fraction p of the way through line i. */
  mid(i, p = 0.5) { return lerp(this.L[i].start, this.L[i].end, p); }

  every(fn) { this.updaters.push(fn); }
  do(t, fn) { this.actions.push([t, fn]); }
  sfx(t, name, gain = 1) { this.cues.push([+t.toFixed(3), name, gain]); }

  // ---- camera (world point x,y centered on screen at zoom z)
  cam(t, x, y, z, e = ease.inOut) { this.camKeys.push([t, { x, y, z }, e]); }
  /** Move the camera from where it is at t0 to (x,y,z) by t1. */
  camTo(t0, t1, x, y, z, e = ease.inOut) {
    this.camKeys.push([t0, null]);
    this.camKeys.push([t1, { x, y, z }, e]);
  }

  // ---- mocks for the real app
  gate(name) {
    let g = this.gates.get(name);
    if (!g) {
      let resolve; const p = new Promise((r) => (resolve = r));
      g = { p, resolve }; this.gates.set(name, g);
    }
    return g.p;
  }
  release(t, name, value) { this.do(t, () => { this.gate(name); this.gates.get(name).resolve(value); }); }
  async mock(cmd, args, frame) {
    const f = this.frames.get(frame)?.fixtures ?? {};
    let v = f[cmd];
    if (typeof v === "function") v = v(args);
    if (v === undefined) {
      const quiet = { take_pending: [], check_update: null, requests: [], cancel_open: null };
      if (cmd in quiet) return quiet[cmd];
      console.log("unmocked", frame, cmd, JSON.stringify(args ?? {}));
      return null;
    }
    return await v;
  }

  /** A real-app window: the desktop UI in an iframe, with a Mac or Windows frame. */
  async appWindow({ id, x, y, w = 1240, h = 780, os = "mac", title = "Secure Verified Exchange", fixtures = {}, layer = this.world, now = null }) {
    const bar = os === "mac"
      ? `<div class="tb tb-mac"><i></i><i></i><i></i><span>${title}</span></div>`
      : `<div class="tb tb-win"><span class="wico">${symbol(16)}</span><span>${title}</span><b>&#x2013;</b><b>&#x25A1;</b><b>&#x2715;</b></div>`;
    const el = $(`<div class="appwin ${os}" style="left:${x - w / 2}px;top:${y - h / 2}px;width:${w}px;height:${h}px">${bar}<iframe src="out/app/index.html?frame=${id}" style="height:${h - 38}px"></iframe></div>`);
    layer.appendChild(el);
    const frame = el.querySelector("iframe");
    this.frames.set(id, { el, frame, fixtures, x: x - w / 2, y: y - h / 2 + 38 });
    await new Promise((r) => frame.addEventListener("load", r, { once: true }));
    // The video sets every motion itself: no app transitions or spinners on wall-clock time.
    const st = frame.contentDocument.createElement("style");
    st.textContent = "*,*::before,*::after{transition:none!important;animation:none!important;caret-color:transparent!important}";
    frame.contentDocument.head.appendChild(st);
    // The app's own smooth scrolling runs on wall-clock time: the video scrolls it by hand.
    frame.contentWindow.Element.prototype.scrollIntoView = function () {};
    // Focusing a field in a window that sits off screen would scroll the whole stage to it.
    const realFocus = frame.contentWindow.HTMLElement.prototype.focus;
    frame.contentWindow.HTMLElement.prototype.focus = function (o) { return realFocus.call(this, { ...(o || {}), preventScroll: true }); };
    if (now) frame.contentWindow.Date.now = () => now * 1000; // the app's clock is part of the story
    await this.settle(frame.contentWindow, 120);
    return new AppWin(this, id);
  }

  async settle(win = window, ms = 25) {
    for (let i = 0; i < 4; i++) await sleep(0);
    await sleep(ms);
  }

  // ---- big kinetic text
  /** Chapter card: number + title rising word by word, then wiping away. */
  titleCard(t0, t1, num, title) {
    const el = $(`<div class="titlecard"><div class="tc-num">${String(num).padStart(2, "0")}</div><div class="tc-title">${words(title)}</div><div class="tc-line"></div></div>`);
    this.hud.appendChild(el);
    const ws = [...el.querySelectorAll(".w>span")];
    const num_ = el.querySelector(".tc-num"), line = el.querySelector(".tc-line");
    this.sfx(t0, "whoosh", 0.8);
    this.sfx(t1 - 0.45, "swoosh", 0.6);
    this.every((t) => {
      const on = t >= t0 - 0.1 && t <= t1 + 0.1;
      el.style.display = on ? "" : "none";
      if (!on) return;
      const out = ease.inOutExpo(prog(t, t1 - 0.55, t1));
      css(num_, { opacity: ease.out(prog(t, t0, t0 + 0.5)) * (1 - out), transform: `translateY(${(1 - ease.outExpo(prog(t, t0, t0 + 0.8))) * 60 - out * 80}px)` });
      ws.forEach((w, i) => {
        const p = ease.outExpo(prog(t, t0 + 0.15 + i * 0.09, t0 + 0.95 + i * 0.09));
        css(w, { transform: `translateY(${(1 - p) * 110 - out * 110}%)` });
      });
      css(line, { transform: `scaleX(${ease.inOutExpo(prog(t, t0 + 0.3, t0 + 1.2)) * (1 - out)})` });
    });
  }

  /** Lower-third key phrase (the voice says more; this is the takeaway). */
  caption(t0, t1, text, { y = 968, size = 42 } = {}) {
    const el = $(`<div class="cap" style="top:${y}px;font-size:${size}px">${words(text)}</div>`);
    const band = $(`<div class="capband ${y < H / 2 ? "top" : ""}"></div>`);
    this.hud.append(band, el);
    this.every((t) => { band.style.opacity = env(t, t0 - 0.1, t1 + 0.1, 0.45, 0.45); });
    const ws = [...el.querySelectorAll(".w>span")];
    this.every((t) => {
      const on = t >= t0 && t <= t1;
      el.style.display = on ? "" : "none";
      if (!on) return;
      const o = 1 - ease.in(prog(t, t1 - 0.35, t1));
      el.style.opacity = o;
      ws.forEach((w, i) => {
        const p = ease.outQuint(prog(t, t0 + i * 0.05, t0 + 0.6 + i * 0.05));
        css(w, { transform: `translateY(${(1 - p) * 100}%)`, opacity: p });
      });
    });
  }

  /** A full-screen chevron wipe at t (covers the cut between two set-ups). */
  wipe(t, dur = 0.9) {
    const el = $(`<div class="wipe"><div class="wipe-a"></div><div class="wipe-b"></div></div>`);
    this.hud.appendChild(el);
    const a = el.firstElementChild, b = el.lastElementChild;
    this.sfx(t - 0.05, "swoosh", 0.7);
    this.every((tt) => {
      const p = prog(tt, t - dur / 2, t + dur / 2);
      el.style.display = p > 0 && p < 1 ? "" : "none";
      css(a, { transform: `translateX(${lerp(-130, 130, ease.inOutExpo(p))}%) skewX(-18deg)` });
      css(b, { transform: `translateX(${lerp(-150, 110, ease.inOutExpo(clamp(p * 1.08 - 0.04)))}%) skewX(-18deg)` });
    });
  }

  // ---- generic animated element in the world
  /** Add HTML to the world (or hud) and animate it with an update function. */
  add(html, update, layer = this.world) {
    const el = typeof html === "string" ? $(html) : html;
    layer.appendChild(el);
    if (update) this.every((t) => update(t, el));
    return el;
  }

  /** Spotlight: dim everything but a box (world coords from rectFn), with a label. */
  spot(t0, t1, rectFn, label, { pad = 14, side = "right", r = 14 } = {}) {
    const el = $(`<div class="spot"><div class="spot-hole"></div>${label ? `<div class="spot-label"><i></i><span>${label}</span></div>` : ""}</div>`);
    this.world.appendChild(el);
    const hole = el.querySelector(".spot-hole"), lab = el.querySelector(".spot-label");
    this.sfx(t0, "pop", 0.5);
    this.every((t) => {
      const a = env(t, t0, t1, 0.45, 0.4);
      el.style.display = a > 0 ? "" : "none";
      if (a <= 0) return;
      const rc = rectFn();
      if (!rc) return;
      const grow = 1 - ease.outBack(prog(t, t0, t0 + 0.6));
      const g = 26 * grow;
      css(hole, {
        left: `${rc.x - pad - g}px`, top: `${rc.y - pad - g}px`,
        width: `${rc.w + 2 * (pad + g)}px`, height: `${rc.h + 2 * (pad + g)}px`, borderRadius: `${r}px`,
        boxShadow: `0 0 0 4000px rgba(8,9,12,${0.55 * a}), 0 0 0 2px rgba(255,106,61,${0.9 * a}), 0 0 40px 6px rgba(255,106,61,${0.28 * a})`,
      });
      if (lab) {
        const lp = ease.outExpo(prog(t, t0 + 0.2, t0 + 0.9));
        const lx = side === "right" ? rc.x + rc.w + pad + 28 : side === "left" ? rc.x - pad - 28 : rc.x + rc.w / 2;
        const ly = side === "below" ? rc.y + rc.h + pad + 26 : side === "above" ? rc.y - pad - 26 : rc.y + rc.h / 2;
        css(lab, { left: `${lx}px`, top: `${ly}px`, opacity: a * lp, transform: `translate(${side === "left" ? "-100%" : side === "right" ? "0" : "-50%"},${side === "above" ? "-100%" : side === "below" ? "0" : "-50%"}) translate(${side === "right" ? (1 - lp) * -24 : side === "left" ? (1 - lp) * 24 : 0}px,${side === "below" ? (1 - lp) * -16 : side === "above" ? (1 - lp) * 16 : 0}px)` });
        lab.className = `spot-label ${side}`;
      }
    });
  }

  // ---- the frame
  async renderAt(t) {
    // One-shot actions up to t, in time order (each may change the real app).
    if (!this._sorted) { this.actions.sort((a, b) => a[0] - b[0]); this._sorted = true; } // stable
    if (t > this.lastT) {
      let ran = false;
      while (this.done < this.actions.length && this.actions[this.done][0] <= t) {
        await this.actions[this.done][1]();
        this.done++; ran = true;
        await this.settle(window, 10); // the app must finish each step before the next one acts on it
      }
      if (ran) await this.settle();
      this.lastT = t;
    }
    // Camera. (Nothing may scroll the stage itself.)
    for (const el of [this.root, this.world, document.documentElement, document.body]) { el.scrollLeft = 0; el.scrollTop = 0; }
    const c = this.cameraAt(t);
    css(this.world, { transform: `translate(${W / 2}px,${H / 2}px) scale(${c.z}) translate(${-c.x}px,${-c.y}px)` });
    // Background parallax: the grid drifts a third as much as the world.
    css(this.grid, { transform: `translate(${(W / 2 - c.x) * 0.3}px,${(H / 2 - c.y) * 0.3}px) scale(${1 + (c.z - 1) * 0.25})` });
    this.cursor.update(t, c.z);
    for (const u of this.updaters) u(t);
    drawGrain(this.grain, Math.round(t * 60));
  }

  cameraAt(t) {
    // Keys are resolved lazily, when their segment starts: "from where it is"
    // keys (null) hold the previous value; element keys (functions) measure
    // the element then, after any scroll that has started.
    if (!this._cam) this._cam = this.camKeys.slice().sort((a, b) => a[0] - b[0]).map(([kt, v, e]) => ({ t: kt, v, e, r: null }));
    const K = this._cam;
    for (let i = 0; i < K.length; i++) {
      const k = K[i];
      if (k.r) continue;
      if (i > 0 && t < K[i - 1].t) break;
      if (k.v === null) k.r = i > 0 ? { ...K[i - 1].r } : { x: W / 2, y: H / 2, z: 1 };
      else if (typeof k.v === "function") k.r = k.v() ?? (i > 0 ? { ...K[i - 1].r } : { x: W / 2, y: H / 2, z: 1 });
      else k.r = k.v;
    }
    return kfObj(t, K.filter((k) => k.r).map((k) => [k.t, k.r, k.e]));
  }

  /** Move the camera onto an element (rectFn -> world rect) at zoom z, by t1.
   *  dy shifts the framing (positive = element higher on screen, room for captions). */
  camOn(t0, t1, rectFn, z, { dy = 70, dx = 0, e = ease.inOut } = {}) {
    this.camKeys.push([t0, null]);
    this.camKeys.push([t1, () => { const r = rectFn(); return r ? { x: r.x + r.w / 2 + dx / z, y: r.y + r.h / 2 + dy / z, z } : null; }, e]);
  }

  /** World-space rect of an element inside an app window. */
  rect(id, sel) {
    const f = this.frames.get(id);
    const el = typeof sel === "string" ? f.frame.contentDocument.querySelector(sel) : sel(f.frame.contentDocument);
    if (!el) return null;
    const r = el.getBoundingClientRect();
    // The iframe's origin in world px (the window is positioned in world px).
    return { x: f.x + r.left, y: f.y + r.top, w: r.width, h: r.height };
  }
}

function kfObj(t, keys) {
  if (keys.length === 0) return { x: W / 2, y: H / 2, z: 1 };
  if (t <= keys[0][0]) return keys[0][1];
  for (let i = 1; i < keys.length; i++) {
    if (t <= keys[i][0]) {
      const [a, va] = keys[i - 1], [b, vb, e] = keys[i];
      const p = (e || ease.inOut)(b === a ? 1 : (t - a) / (b - a));
      // Zoom moves in log space so push-ins feel even.
      return { x: lerp(va.x, vb.x, p), y: lerp(va.y, vb.y, p), z: Math.exp(lerp(Math.log(va.z), Math.log(vb.z), p)) };
    }
  }
  return keys[keys.length - 1][1];
}

// ---------------------------------------------------------------- app window handle
class AppWin {
  constructor(E, id) { this.E = E; this.id = id; this.f = E.frames.get(id); }
  get doc() { return this.f.frame.contentDocument; }
  get win() { return this.f.frame.contentWindow; }
  q(sel) { return typeof sel === "string" ? this.doc.querySelector(sel) : sel(this.doc); }
  /** Element by its visible text (exact, trimmed), optionally limited to a selector. */
  byText(text, within = "button, a, h1, h2, h3, label, strong, span, p, div") {
    return [...this.doc.querySelectorAll(within)].find((e) => e.textContent.trim() === text) ?? null;
  }
  rect(sel) { return this.E.rect(this.id, sel); }
  /** Where an element will be once the scroll in progress has finished. */
  rectFinal(sel) {
    const r = this.rect(sel);
    if (!r) return null;
    const goal = this.scrollGoal ? this.scrollGoal() : null;
    if (goal === null || goal === undefined) return r;
    return { ...r, y: r.y - (goal - this.doc.scrollingElement.scrollTop) };
  }
  center(sel) { const r = this.rect(sel); return r ? [r.x + r.w / 2, r.y + r.h / 2] : null; }
  click(t, sel, sound = "click") {
    this.E.sfx(t, sound);
    this.E.cursor.press(t);
    this.E.do(t, () => { const el = this.q(sel); if (el) el.click(); else console.log("click: not found", sel); });
  }
  /** Type text into an input, one character at a time, from t0 to t1. */
  type(t0, t1, sel, text, { enter = false } = {}) {
    const n = text.length;
    for (let i = 1; i <= n; i++) {
      const tt = lerp(t0, t1, i / n);
      if (i % 2 === 1) this.E.sfx(tt, "key", 0.5);
      this.E.do(tt, () => {
        const el = this.q(sel);
        const set = Object.getOwnPropertyDescriptor(this.win.HTMLInputElement.prototype, "value").set;
        set.call(el, text.slice(0, i));
        el.dispatchEvent(new this.win.Event("input", { bubbles: true }));
      });
    }
    if (enter) {
      this.E.sfx(t1 + 0.15, "key", 0.8);
      this.E.do(t1 + 0.15, () => {
        const el = this.q(sel);
        el.dispatchEvent(new this.win.KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
      });
    }
  }
  drop(t, paths) { this.E.do(t, () => this.win.svxDrop(paths)); }
  emit(t, name, payload) { this.E.do(t, () => this.win.svxEmit(name, payload)); }
  /** Smoothly scroll the app's main area to show selector at the top (with margin). */
  scrollTo(t0, t1, sel, margin = 24) {
    let from = null, to = null;
    const main = () => this.doc.scrollingElement;
    this.E.do(t0, () => {
      const m = main(); from = m.scrollTop;
      this.scrollGoal = () => to;
      const el = this.q(sel);
      to = el ? from + el.getBoundingClientRect().top - margin : from;
      to = Math.max(0, Math.min(to, m.scrollHeight - m.clientHeight));
    });
    let landed = false;
    this.E.every((t) => {
      if (from === null || t < t0 || landed) return;
      main().scrollTop = lerp(from, to, ease.inOut(prog(t, t0, t1)));
      if (t >= t1) { landed = true; this.scrollGoal = null; } // done: later scrolls take over from here
    });
  }
  /** Go to an app screen by clicking its sidebar item. */
  nav(t, route) { this.click(t, `.nav-item[data-route="${route}"]`); }
}

// ---------------------------------------------------------------- cursor
class Cursor {
  constructor(E) {
    this.E = E;
    this.el = $(`<div class="cursor"><svg viewBox="0 0 28 34" width="28" height="34"><path d="M3 2 L3 26 L9.5 20 L14 31 L18.5 29 L14 18.5 L23 18.5 Z" fill="#fff" stroke="#111" stroke-width="1.6" stroke-linejoin="round"/></svg></div>`);
    this.ring = $(`<div class="click-ring"></div>`);
    E.world.append(this.ring, this.el);
    this.moves = [];   // {t0,t1,to:()=>[x,y]|[x,y], from, bend}
    this.presses = [];
    this.vis = [];     // [t, opacity]
    this.pos = [W / 2 + 300, H / 2 + 200];
  }
  show(t, on = true) { this.vis.push([t, on ? 1 : 0]); }
  /** Glide to a point or an app element's center between t0 and t1 (curved, eased). */
  move(t0, t1, to, { bend = 0.18 } = {}) { this.moves.push({ t0, t1, to, bend, from: null, end: null }); this.moves.sort((a, b) => a.t0 - b.t0); }
  press(t) { this.presses.push(t); }
  place(xy) { this.pos = xy; }
  update(t, z) {
    let [x, y] = this.pos;
    for (const m of this.moves) {
      if (t < m.t0) break;
      if (m.from === null) m.from = [x, y];
      if (m.end === null) m.end = typeof m.to === "function" ? (m.to() ?? m.from) : m.to;
      const p = ease.inOut(prog(t, m.t0, m.t1));
      const [ax, ay] = m.from, [bx, by] = m.end;
      // A gentle arc, like a hand moving a mouse.
      const nx = -(by - ay), ny = bx - ax;
      const arc = Math.sin(Math.PI * p) * m.bend;
      x = lerp(ax, bx, p) + nx * arc; y = lerp(ay, by, p) + ny * arc;
    }
    let o = 0;
    for (const [tt, v] of this.vis) if (t >= tt) o = v;
    const fade = this.vis.reduce((acc, [tt, v]) => (t >= tt && t < tt + 0.3 ? (v ? prog(t, tt, tt + 0.3) : 1 - prog(t, tt, tt + 0.3)) : acc), o);
    let s = 1;
    let ringP = -1;
    for (const p of this.presses) {
      if (t >= p - 0.12 && t < p + 0.18) s = 1 - 0.16 * Math.sin(Math.PI * prog(t, p - 0.12, p + 0.18));
      if (t >= p && t < p + 0.55) ringP = prog(t, p, p + 0.55);
    }
    const inv = 1 / Math.sqrt(z); // stays a sensible size when the camera zooms
    this.cur = [x, y];
    css(this.el, { transform: `translate(${x}px,${y}px) scale(${inv * s})`, opacity: fade });
    css(this.ring, { display: ringP >= 0 ? "" : "none", transform: `translate(${x}px,${y}px) translate(-50%,-50%) scale(${0.3 + ease.out(ringP) * 1.4 * inv})`, opacity: (1 - ringP) * fade });
  }
}

// ---------------------------------------------------------------- film grain
let grainCtx = null, grainBuf = null;
function drawGrain(canvas, frame) {
  if (!grainCtx) { grainCtx = canvas.getContext("2d"); grainBuf = grainCtx.createImageData(canvas.width, canvas.height); }
  let s = (frame * 2654435761) >>> 0;
  const d = grainBuf.data;
  for (let i = 0; i < d.length; i += 4) {
    s ^= s << 13; s ^= s >>> 17; s ^= s << 5;
    const v = (s >>> 24);
    d[i] = d[i + 1] = d[i + 2] = v; d[i + 3] = 255;
  }
  grainCtx.putImageData(grainBuf, 0, 0);
}
