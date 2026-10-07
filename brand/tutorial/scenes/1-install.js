// Chapter 1: Install SVX. The website, the Windows warning, the Mac warning, then self-updating.
// Four "sets" side by side in the world; the camera pans between them.
import { ease, env, kf, prog, symbol } from "../engine.js";
import { ALICE, NOW, appState, signedIn } from "./common.js";

const lerp = (a, b, p) => a + (b - a) * p;
const SHIELD = `<svg viewBox="0 0 64 64" width="64" fill="none" stroke="#f0b456" stroke-width="4" stroke-linejoin="round"><path d="M32 6l20 8v16c0 14-9 24-20 28C21 54 12 44 12 30V14z"/><path d="M32 22v14M32 42v2" stroke-linecap="round"/></svg>`;
const FOLDER = `<svg viewBox="0 0 120 100" width="150"><path d="M8 20a8 8 0 0 1 8-8h28l10 12h50a8 8 0 0 1 8 8v52a8 8 0 0 1-8 8H16a8 8 0 0 1-8-8z" fill="#4aa3f0"/><path d="M8 34h104v46a8 8 0 0 1-8 8H16a8 8 0 0 1-8-8z" fill="#74bdfa"/></svg>`;
const EXE = `<svg viewBox="0 0 64 64" width="96"><rect x="8" y="6" width="48" height="52" rx="6" fill="#2d3340" stroke="#5b6475" stroke-width="3"/><rect x="18" y="16" width="28" height="22" rx="3" fill="#ff6a3d"/><rect x="18" y="44" width="28" height="5" rx="2.5" fill="#8a93a6"/></svg>`;

export default async function scene(E) {
  const L = (i, d) => E.at(i, d), End = (i, d) => E.end(i, d);
  const A = 960, B = 3260, C = 5560, D = 7860, Y = 540;

  const el = (html, x, y, w, h) => E.add(`<div style="position:absolute;left:${x}px;top:${y}px;${w ? `width:${w}px;` : ""}${h ? `height:${h}px;` : ""}">${html}</div>`, null);
  const vis = (e, a, tf = "") => { e.style.display = a > 0.002 ? "" : "none"; e.style.opacity = a; if (tf) e.style.transform = tf; };

  // ---------------------------------------------------------------- set D: the real app, with an update waiting
  const upd = { version: "0.1.9", notes: "Smaller fixes and a smoother first start.", released_at: NOW, platform: "x86_64", package: { url: "", size: 0, sha512: "", signature: "" } };
  const app = await E.appWindow({
    id: "app", x: D, y: Y + 20, os: "mac", now: NOW,
    fixtures: signedIn(ALICE, { state: { ...appState(ALICE), updates_available: true }, check_update: upd }),
  });
  // (the app's own state says "updates available" so it looks for one at start)
  // The window is already open; the banner shows from the start.

  // ---------------------------------------------------------------- set A: getsvx.me
  const BX = A - 760, BY = 150, BW = 1520, BH = 800;
  const url = "getsvx.me/download";
  const browser = el(`<div style="width:${BW}px;height:${BH}px;border-radius:16px;background:#16171b;box-shadow:0 0 0 1px rgba(255,255,255,.08),0 50px 120px rgba(0,0,0,.6);overflow:hidden;position:relative">
    <div style="height:64px;background:#1f2127;border-bottom:1px solid #2b2d33;display:flex;align-items:center;gap:10px;padding:0 20px"><i style="width:13px;height:13px;border-radius:50%;background:#ff5f57"></i><i style="width:13px;height:13px;border-radius:50%;background:#febc2e"></i><i style="width:13px;height:13px;border-radius:50%;background:#28c840"></i>
      <div class="urlbar" style="margin-left:30px;flex:1;max-width:620px;height:38px;border-radius:19px;background:#121317;border:1px solid #33363e;display:flex;align-items:center;padding:0 18px;font:500 20px 'IBM Plex Sans';color:#e8e6e1"><span class="urltext"></span><span class="caret" style="width:2px;height:22px;background:#ff6a3d;margin-left:2px"></span></div>
      <div class="dlpill" style="margin-left:auto;display:none;align-items:center;gap:10px;padding:8px 16px;border-radius:12px;background:#2a2d35;font:500 18px 'IBM Plex Sans';color:#e8e6e1">⬇ SVX-beta-Windows.exe</div></div>
    <div class="page" style="position:absolute;left:0;right:0;top:64px;bottom:0;padding:56px 70px;background:radial-gradient(ellipse at 50% 0,#252832,#16171b 60%)">
      <div style="font:700 56px/1.1 Unbounded;margin-bottom:12px">Get SVX for your<br>desktop.</div>
      <div style="font:400 22px 'IBM Plex Sans';color:#a8a59e;margin-bottom:46px">Free beta. Windows and Mac.</div>
      <div style="display:flex;gap:36px">
        <div class="cardm" style="width:560px;height:290px;border-radius:22px;background:#1d1f24;border:1px solid #3d4048;padding:34px"><div style="font:700 34px Unbounded;margin-bottom:8px">macOS</div><div style="font:400 20px 'IBM Plex Sans';color:#a8a59e;margin-bottom:34px">SVX-beta-macOS.dmg · Apple chip</div><div style="display:inline-block;padding:18px 34px;border-radius:14px;background:#f3f1ec;color:#16171b;font:600 24px 'IBM Plex Sans'">Download for macOS</div></div>
        <div class="cardw" style="width:560px;height:290px;border-radius:22px;background:#1d1f24;border:1px solid #3d4048;padding:34px"><div style="font:700 34px Unbounded;margin-bottom:8px">Windows</div><div style="font:400 20px 'IBM Plex Sans';color:#a8a59e;margin-bottom:34px">SVX-beta-Windows.exe · Windows 10 and 11</div><div style="display:inline-block;padding:18px 34px;border-radius:14px;background:#f3f1ec;color:#16171b;font:600 24px 'IBM Plex Sans'">Download for Windows</div></div>
      </div></div></div>`, BX, BY);
  const urlText = browser.querySelector(".urltext"), caret = browser.querySelector(".caret"), pill = browser.querySelector(".dlpill"), page = browser.querySelector(".page");
  const macCard = { x: BX + 70, y: BY + 64 + 56 + 190, w: 560, h: 290 };
  const winCard = { x: BX + 70 + 560 + 36, y: BY + 64 + 56 + 190, w: 560, h: 290 };
  const winBtn = [winCard.x + 34 + 150, winCard.y + 34 + 38 + 20 + 34 + 24 + 20 + 30];

  // ---------------------------------------------------------------- set B: Windows
  const wd = el(`<div style="width:1500px;height:860px;border-radius:18px;background:linear-gradient(135deg,#102a52,#1b4a8a 55%,#0f2f5e);box-shadow:0 50px 120px rgba(0,0,0,.6);overflow:hidden;position:relative">
    <div class="fold" style="position:absolute;left:180px;top:130px;width:760px;height:380px;border-radius:12px;background:#202125;border:1px solid #3a3c43;overflow:hidden"><div style="height:44px;background:#2a2b30;display:flex;align-items:center;padding:0 18px;font:500 18px 'IBM Plex Sans';color:#cfcdc7">Downloads</div>
      <div class="exe" style="position:absolute;left:60px;top:90px;width:170px;text-align:center;border-radius:8px;padding:10px 0;font:400 17px 'IBM Plex Sans';color:#e8e6e1">${EXE}<div style="margin-top:8px">SVX-beta-<br>Windows.exe</div></div></div>
    <div style="position:absolute;left:0;right:0;bottom:0;height:64px;background:rgba(20,22,28,.9);display:flex;align-items:center;justify-content:center;gap:22px"><i style="width:30px;height:30px;background:#4aa3f0;border-radius:6px"></i><i style="width:30px;height:30px;background:#555b69;border-radius:8px"></i><i style="width:30px;height:30px;background:#555b69;border-radius:8px"></i></div></div>`, B - 750, Y - 430);
  const exeIcon = wd.querySelector(".exe");
  const EXE_C = [B - 750 + 180 + 60 + 85, Y - 430 + 130 + 90 + 70];
  const DX = B - 330, DY = Y - 200;
  const smart = el(`<div style="width:660px;height:400px;background:#1b2a49;color:#fff;box-shadow:0 40px 100px rgba(0,0,0,.65);border:1px solid #3a5a96;position:relative;font-family:'IBM Plex Sans'">
    <div style="position:absolute;left:36px;top:34px;font:600 32px 'IBM Plex Sans'">Windows protected your PC</div>
    <div class="sp" style="position:absolute;left:36px;top:96px;width:588px;font:400 21px/1.45 'IBM Plex Sans'">Microsoft Defender SmartScreen prevented an unrecognized app from starting. Running this app might put your PC at risk.</div>
    <div class="more" style="position:absolute;left:36px;top:206px;font:400 21px 'IBM Plex Sans';text-decoration:underline">More info</div>
    <div class="info" style="position:absolute;left:36px;top:196px;font:400 21px/1.6 'IBM Plex Sans';opacity:0"><div>App: <b style="font-weight:600">SVX-beta-Windows.exe</b></div><div>Publisher: <b style="font-weight:600">Unknown publisher</b></div></div>
    <div class="runany" style="position:absolute;left:330px;top:320px;width:150px;height:46px;background:#2c3f66;border:1px solid #5b78b3;text-align:center;font:500 20px/46px 'IBM Plex Sans';opacity:0">Run anyway</div>
    <div style="position:absolute;left:494px;top:320px;width:136px;height:46px;background:#5a8fe0;text-align:center;font:500 20px/46px 'IBM Plex Sans'">Don’t run</div></div>`, DX, DY);
  const moreC = [DX + 36 + 50, DY + 206 + 14], runC = [DX + 330 + 75, DY + 320 + 23];
  const smartMore = smart.querySelector(".more"), smartInfo = smart.querySelector(".info"), smartRun = smart.querySelector(".runany");
  const inst = el(`<div style="width:560px;padding:30px 34px;border-radius:14px;background:#f2f2f2;color:#222;box-shadow:0 40px 100px rgba(0,0,0,.6);font:500 24px 'IBM Plex Sans'">Installing SVX…<div style="margin-top:22px;height:14px;border-radius:7px;background:#d6d6d6;overflow:hidden"><div class="bar" style="height:100%;width:0;background:#0b7a3e"></div></div></div>`, B - 280, Y - 70);
  const bar = inst.querySelector(".bar");

  // ---------------------------------------------------------------- set C: Mac
  const MX = C - 410, MY = Y - 260;
  const dmg = el(`<div style="width:820px;height:470px;border-radius:14px;background:#26282d;box-shadow:0 0 0 1px rgba(255,255,255,.1),0 50px 120px rgba(0,0,0,.6);overflow:hidden;position:relative"><div class="tb tb-mac"><i></i><i></i><i></i><span>SVX</span></div>
    <div style="position:absolute;left:0;right:0;top:38px;bottom:0;background:linear-gradient(#34373e,#26282d)"></div>
    <div style="position:absolute;left:500px;top:150px;text-align:center;font:500 22px 'IBM Plex Sans';color:#e8e6e1">${FOLDER}<div style="margin-top:6px">Applications</div></div>
    <svg style="position:absolute;left:300px;top:190px" width="220" height="40"><path d="M6 20h190M178 6l20 14-20 14" fill="none" stroke="#8a93a6" stroke-width="5" stroke-linecap="round" stroke-linejoin="round" stroke-dasharray="2 14"/></svg></div>`, MX, MY);
  const appIcon = el(`<div style="width:150px;text-align:center;font:500 22px 'IBM Plex Sans';color:#e8e6e1"><div style="width:130px;height:130px;margin:0 auto 6px;border-radius:30px;background:#16171b;border:2px solid #3d4048;display:flex;align-items:center;justify-content:center;box-shadow:0 18px 40px rgba(0,0,0,.5)">${symbol(78)}</div>SVX</div>`, 0, 0);
  const ICON0 = [MX + 140 + 75, MY + 190 + 65], ICON1 = [MX + 500 + 75 - 10, MY + 190 + 40];
  const gate = el(`<div style="width:540px;padding:34px;border-radius:20px;background:rgba(44,46,52,.98);border:1px solid rgba(255,255,255,.12);box-shadow:0 40px 100px rgba(0,0,0,.65);text-align:center;font:400 20px/1.45 'IBM Plex Sans';color:#e0ded8"><div style="display:flex;justify-content:center;margin-bottom:14px">${SHIELD}</div><div style="font:600 25px 'IBM Plex Sans';color:#fff;margin-bottom:8px">“SVX” Not Opened</div>Apple could not verify “SVX” is free of malware that may harm your Mac or compromise your privacy.<div style="display:flex;gap:14px;justify-content:center;margin-top:24px"><span style="padding:9px 26px;border-radius:9px;background:#0a84ff;color:#fff;font-weight:500">Done</span><span style="padding:9px 26px;border-radius:9px;background:#43454d">Move to Bin</span></div></div>`, C - 270, Y - 190);
  const SX = C - 500, SY = Y - 310;
  const sett = el(`<div style="width:1000px;height:620px;border-radius:14px;background:#2b2d33;box-shadow:0 0 0 1px rgba(255,255,255,.1),0 50px 120px rgba(0,0,0,.65);overflow:hidden;position:relative;font-family:'IBM Plex Sans'"><div class="tb tb-mac"><i></i><i></i><i></i><span>System Settings</span></div>
    <div style="position:absolute;left:0;top:38px;bottom:0;width:260px;background:#23252a;padding:20px 14px;font:400 19px/2.1 'IBM Plex Sans';color:#c9c7c1"><div>Wi-Fi</div><div>Network</div><div>Notifications</div><div>Appearance</div><div style="background:#0a84ff;color:#fff;border-radius:8px;padding-left:10px;margin:0 -4px">Privacy &amp; Security</div><div>Desktop &amp; Dock</div></div>
    <div style="position:absolute;left:290px;top:68px;right:30px;color:#e8e6e1"><div style="font:600 34px 'IBM Plex Sans';margin-bottom:26px">Privacy &amp; Security</div><div style="font:600 18px 'IBM Plex Sans';color:#9a9892;margin-bottom:10px">Security</div>
      <div style="border-radius:12px;background:#33353c;padding:22px 26px;font:400 20px/1.45 'IBM Plex Sans'">“SVX” was blocked to protect your Mac.<div class="oa" style="position:absolute;right:20px;top:99px;padding:10px 22px;border-radius:9px;background:#43454d;font:500 19px 'IBM Plex Sans';color:#fff">Open Anyway</div></div></div></div>`, SX, SY);
  const openAnyC = [SX + 1000 - 30 - 20 - 62, SY + 68 + 99 + 56 + 10 + 30 - 10];
  const tickC = el(`<div style="width:130px;height:130px;border-radius:50%;background:#4cc584;color:#16171b;font:700 80px/130px Unbounded;text-align:center;box-shadow:0 20px 60px rgba(76,197,132,.35)">✓</div>`, C - 65, Y - 40);
  const once = el(`<div style="font:700 130px Unbounded;white-space:nowrap">Once</div>`, C - 190, Y - 280);

  // ---------------------------------------------------------------- camera
  E.cam(0, A, Y, 1.0);
  E.camTo(L(1, -0.3), L(1, 0.7), A, Y + 30, 1.06);
  E.camTo(L(3, 1.4), L(4, -0.2), A, Y, 0.95);
  E.camTo(L(4, -0.15), L(4, 0.75), B, Y, 1.0, ease.inOutExpo);
  E.camTo(L(5, 0.4), L(5, 1.3), B, Y + 40, 1.35);
  E.camTo(L(6, 1.0), L(7, -0.1), B, Y, 1.0);
  E.camTo(L(7, -0.1), L(7, 0.8), C, Y, 1.0, ease.inOutExpo);
  E.camTo(L(8, 0.3), L(8, 1.0), C, Y, 1.2);
  E.camTo(L(8, 2.2), L(8, 3.0), C, Y + 20, 0.95);
  E.camTo(L(8, 3.6), L(9, 0.6), C + 60, Y + 100, 1.4);
  E.camTo(L(10, 0.2), L(10, 1.0), C, Y, 1.0);
  E.camTo(L(11, -0.5), L(11, 0.5), D, Y + 20, 1.0, ease.inOutExpo);
  E.camOn(L(11, 0.8), L(11, 1.6), () => app.rect(".update-banner"), 1.2, { dy: 40 });

  // ---------------------------------------------------------------- 0-3. the website
  E.every((t) => {
    const n = Math.floor(prog(t, 0.45, 2.0) * url.length);
    urlText.textContent = url.slice(0, n);
    caret.style.display = t < L(2, 0.0) ? "" : "none";
    const p = ease.outExpo(prog(t, 2.0, 3.0));
    page.style.opacity = p; page.style.transform = `translateY(${(1 - p) * 30}px)`;
    const b = ease.outExpo(prog(t, 0.0, 0.9));
    browser.style.opacity = b; browser.style.transform = `scale(${0.94 + 0.06 * b})`;
    pill.style.display = t >= L(3, 2.3) ? "flex" : "none";
  });
  for (let i = 0; i < url.length; i += 2) E.sfx(0.45 + (i / url.length) * 1.55, "key", 0.4);
  E.sfx(2.0, "whoosh", 0.4);
  E.caption(L(0, 0.2), End(0, 0.1), "[[getsvx.me]]");
  E.spot(L(1, 0.2), L(1, 1.5), () => macCard, "Mac, Apple chip", { side: "below", pad: 8, r: 22 });
  E.spot(L(1, 1.5), End(1, 0.2), () => winCard, "Windows 10 and 11", { side: "below", pad: 8, r: 22 });
  E.caption(L(1, 0.4), End(1, 0.2), "Windows, or a Mac with an [[Apple chip]]");
  const apple = el(`<div class="badge" style="font-size:26px;padding:12px 22px">${SHIELD.replace('width="64"', 'width="30"')}<span>Not signed by Apple</span></div>`, A + 120, Y - 255);
  const ms = el(`<div class="badge" style="font-size:26px;padding:12px 22px">${SHIELD.replace('width="64"', 'width="30"')}<span>Not signed by Microsoft</span></div>`, A + 120, Y - 190);
  E.every((t) => {
    vis(apple, env(t, L(2, 1.4), End(3, 0.6), 0.5, 0.5), `translateY(${(1 - ease.outExpo(prog(t, L(2, 1.4), L(2, 2.1)))) * 24}px)`);
    vis(ms, env(t, L(2, 2.3), End(3, 0.6), 0.5, 0.5), `translateY(${(1 - ease.outExpo(prog(t, L(2, 2.3), L(2, 3.0)))) * 24}px)`);
  });
  E.sfx(L(2, 1.4), "pop", 0.5); E.sfx(L(2, 2.3), "pop", 0.5);
  E.caption(L(2, 0.4), End(2, 0.2), "A free beta: [[not signed yet]]");
  E.caption(L(3, 0.4), End(3, 0.2), "Your computer asks you to [[confirm once]]");

  const C0 = E.cursor;
  C0.place([A + 600, Y + 300]); C0.show(L(1, 1.8));
  C0.move(L(3, 0.2), L(3, 1.6), () => winBtn);
  C0.press(L(3, 2.2)); E.sfx(L(3, 2.2), "click", 0.8);
  C0.show(L(4, -0.3), false);

  // ---------------------------------------------------------------- 4-6. Windows
  E.sfx(L(4, 0.2), "pop", 0.4);
  E.every((t) => {
    const sel = prog(t, L(4, 1.1), L(4, 1.15));
    exeIcon.style.background = `rgba(120,170,255,${0.28 * sel})`;
    vis(smart, ease.outBack(prog(t, L(4, 1.8), L(4, 2.3))) * (1 - ease.in(prog(t, L(6, 1.0), L(6, 1.3)))), `scale(${0.92 + 0.08 * ease.outExpo(prog(t, L(4, 1.8), L(4, 2.4)))})`);
    const m = ease.inOut(prog(t, L(5, 2.7), L(5, 3.0)));
    smartMore.style.opacity = 1 - m; smartInfo.style.opacity = m; smartRun.style.opacity = m;
    vis(inst, ease.out(prog(t, L(6, 1.2), L(6, 1.6))) * (1 - ease.in(prog(t, L(7, -0.5), L(7, 0.1)))));
    bar.style.width = `${ease.inOut(prog(t, L(6, 1.4), L(7, -0.3))) * 100}%`;
  });
  const C1 = E.cursor;
  C1.place([B + 400, Y + 300]); C1.show(L(4, 0.2));
  C1.move(L(4, 0.25), L(4, 1.0), () => EXE_C);
  C1.press(L(4, 1.1)); C1.press(L(4, 1.3)); E.sfx(L(4, 1.1), "click", 0.8); E.sfx(L(4, 1.3), "click", 0.8);
  E.sfx(L(4, 1.9), "pop", 0.7);
  E.spot(L(5, 0.3), L(5, 1.9), () => ({ x: DX + 28, y: DY + 26, w: 600, h: 54 }), null, { pad: 8 });
  E.caption(L(5, 0.2), L(5, 2.4), "“Windows protected your PC”");
  C1.move(L(5, 1.9), L(5, 2.5), () => moreC);
  C1.press(L(5, 2.7)); E.sfx(L(5, 2.7), "click", 0.8);
  E.spot(L(5, 2.9), End(5, 0.3), () => ({ x: DX + 22, y: DY + 190, w: 400, h: 96 }), null, { pad: 6 });
  E.caption(L(5, 2.7), End(6, 0.4), "[[More info]], then [[Run anyway]]");
  C1.move(L(6, 0.0), L(6, 0.7), () => runC);
  C1.press(L(6, 0.9)); E.sfx(L(6, 0.9), "click", 0.8);
  E.sfx(L(6, 1.3), "success", 0.5);
  C1.show(L(6, 1.5), false);

  // ---------------------------------------------------------------- 7. Mac: drag into Applications
  const DRAG0 = L(7, 1.0), DRAG1 = L(7, 2.6);
  E.every((t) => {
    const a = ease.outBack(prog(t, L(7, 0.0), L(7, 0.6)));
    dmg.style.opacity = Math.min(1, a * 1.5); dmg.style.transform = `scale(${0.92 + 0.08 * a})`;
    const f = ease.inOut(prog(t, DRAG0, DRAG1));
    const x = lerp(ICON0[0], ICON1[0], f) - 75, y = lerp(ICON0[1], ICON1[1], f) - 70;
    const sink = ease.in(prog(t, DRAG1, DRAG1 + 0.35));
    appIcon.style.left = `${x}px`; appIcon.style.top = `${y}px`;
    appIcon.style.opacity = Math.min(1, a * 1.5) * (1 - sink);
    appIcon.style.transform = `scale(${(1 + 0.08 * Math.sin(Math.PI * Math.min(1, f * 1.2))) * (1 - 0.3 * sink)})`;
  });
  const C2 = E.cursor;
  C2.place([C + 450, Y + 320]); C2.show(L(7, 0.4));
  C2.move(L(7, 0.5), L(7, 1.0), () => ICON0);
  C2.press(L(7, 1.0)); E.sfx(L(7, 1.0), "click", 0.7);
  C2.move(DRAG0, DRAG1, () => ICON1, { bend: 0 });
  C2.press(DRAG1); E.sfx(DRAG1, "drop", 0.8);
  C2.show(L(7, 3.4), false);
  E.caption(L(7, 0.4), End(7, 0.2), "Drag SVX into [[Applications]]");

  // ---------------------------------------------------------------- 8-9. Mac: Gatekeeper, then Open Anyway
  E.every((t) => {
    const dm = ease.in(prog(t, L(8, 0.2), L(8, 0.7)));
    dmg.style.opacity = (1 - dm) * Math.min(1, ease.outBack(prog(t, L(7, 0.0), L(7, 0.6))) * 1.5);
    vis(gate, env(t, L(8, 0.6), L(8, 2.6), 0.4, 0.3), `scale(${0.94 + 0.06 * ease.outExpo(prog(t, L(8, 0.6), L(8, 1.1)))})`);
    vis(sett, ease.outBack(prog(t, L(8, 2.4), L(8, 3.0))) * (1 - ease.in(prog(t, L(10, 0.0), L(10, 0.4)))), `scale(${0.94 + 0.06 * ease.outExpo(prog(t, L(8, 2.4), L(8, 3.1)))})`);
    const oa = sett.querySelector(".oa");
    const hit = prog(t, L(9, 0.85), L(9, 0.95));
    oa.style.background = hit > 0 ? "#0a84ff" : "#43454d";
    const tk = ease.outBack(prog(t, L(10, 0.0), L(10, 0.6)));
    vis(tickC, Math.min(1, tk) * (1 - ease.in(prog(t, End(10, 0.1), End(10, 0.6)))), `scale(${tk})`);
    const on = ease.outExpo(prog(t, L(10, 0.0), L(10, 0.9)));
    vis(once, on * (1 - ease.in(prog(t, End(10, 0.1), End(10, 0.6)))), `translateY(${(1 - on) * 60}px)`);
  });
  E.sfx(L(8, 0.6), "pop", 0.6); E.sfx(L(8, 2.4), "whoosh", 0.5); E.sfx(L(9, 0.9), "click", 0.8); E.sfx(L(10, 0.1), "success", 0.8);
  E.caption(L(8, 0.7), L(8, 2.4), "A warning: [[not verified]]");
  E.caption(L(8, 2.6), End(9, 0.4), "Privacy and Security, then [[Open Anyway]]");
  const C3 = E.cursor;
  C3.place([C + 300, Y + 280]); C3.show(L(8, 3.2));
  C3.move(L(8, 3.3), L(9, 0.7), () => openAnyC);
  C3.press(L(9, 0.9));
  C3.show(L(9, 1.4), false);
  E.caption(L(10, 0.9), End(10, 0.3), "You only do this [[once]]", { y: 780 });

  // ---------------------------------------------------------------- 11. it updates itself
  E.spot(L(11, 1.2), End(11, 0.2), () => app.rect(".update-banner"), "Updates itself", { side: "below", pad: 10 });
  E.caption(L(11, 0.4), End(11, 0.6), "After that, SVX [[updates itself]]");
  E.sfx(L(11, 0.5), "pop", 0.5);

  E.every((t) => { E.root.style.opacity = 1 - ease.in(prog(t, E.duration - 0.8, E.duration)); });
}
