// Chapter 3: Send a file. Alice sends Project-plan.pdf to Bob.
import { ease, env, kf, prog, symbol } from "../engine.js";
import { ALICE, BOB, NOW, avatar, badge, contact, destination, fileIcon, macTouchId, signedIn, winHello } from "./common.js";

export default async function scene(E) {
  const L = (i, d) => E.at(i, d), End = (i, d) => E.end(i, d);

  // ---------------------------------------------------------------- set-up
  const WX = 1110, WY = 560;
  const app = await E.appWindow({
    id: "alice", x: WX, y: WY, os: "mac",
    fixtures: signedIn(ALICE, {
      lookup: async () => { await E.gate("lookup"); return contact(BOB); },
      view_check: { ok: true, office: false, reason: null },
      send_personal: async () => {
        await E.gate("send");
        return {
          path: "/Users/alice/Documents/Project-plan.svx", artifact_id: "5a1f",
          recipients: [contact(BOB)],
          rules: { require_approval: true, one_time: true, expires_at: NOW + 7 * 86400, view_only: false, allow_share_requests: false },
          expires_at: NOW + 7 * 86400, protection: "Maximum (SVX-2, post-quantum)",
        };
      },
    }),
  });
  const win = E.frames.get("alice").el;
  const ui = (sel) => () => app.rect(sel);
  const byText = (text, within) => (d) => [...d.querySelectorAll(within)].find((e) => e.textContent.trim() === text);
  const toggle = (title) => (d) => [...d.querySelectorAll("label.toggle")].find((l) => l.querySelector("strong")?.textContent.trim() === title);

  // The whole picture fades up after the title card.
  E.every((t) => {
    const a = ease.out(prog(t, L(1, -0.55), L(1, 0.25)));
    E.world.style.opacity = a;
  });

  // Title.
  E.titleCard(0.05, L(1, -0.15), 3, "Send a file");

  // Alice's computer: the window, and her file on the desktop.
  badge(E, L(1, 0.1), End(4), WX - 520, WY - 430, `${avatar(ALICE, "#ff6a3d")}<span>Alice’s computer</span>`);
  const file = E.add(fileIcon("Project-plan.pdf"), null);
  file.style.left = "160px"; file.style.top = "430px";
  const FILE0 = [235, 505];
  let grabbed = null;
  E.every((t) => {
    // Appears, is picked up, follows the cursor, drops into the window.
    const show = ease.outBack(prog(t, L(1, 0.4), L(1, 1.0)));
    let [x, y] = FILE0, s = show, o = Math.min(1, show * 1.4);
    const pick = L(2, 0.05), drop = L(2, 1.55);
    if (t >= pick && t < drop + 0.5) {
      if (!grabbed) grabbed = [...E.cursor.cur];
      const [cx, cy] = E.cursor.cur;
      x = cx - (grabbed[0] - FILE0[0]); y = cy - (grabbed[1] - FILE0[1]);
      s = 1 + 0.08 * ease.out(prog(t, pick, pick + 0.25));
    }
    if (t >= drop) {
      const p = ease.inOutExpo(prog(t, drop, drop + 0.45));
      s *= 1 - 0.7 * p; o = 1 - p;
    }
    file.style.transform = `translate(${x - FILE0[0]}px,${y - FILE0[1]}px) scale(${s}) rotate(${t >= pick && t < drop ? -4 : 0}deg)`;
    file.style.opacity = o;
    file.style.display = o > 0.01 ? "" : "none";
  });

  // ---------------------------------------------------------------- camera
  E.cam(0, 960, 560, 0.86);
  E.cam(L(1), 960, 560, 0.86);
  E.cam(End(1), 930, 545, 0.95);
  E.camTo(L(2, -0.1), L(2, 1.2), 820, 470, 1.18);                 // follow the drag toward the drop zone
  const card = (i) => (d) => d.querySelectorAll("section.card")[i];
  const goBtn = byText("Encrypt and send", "button");
  E.camOn(End(2, 0.2), L(3, 0.5), () => app.rectFinal(card(1)), 1.45);                     // "Who can open it?"
  E.camOn(L(4, 0.2), L(4, 0.9), () => app.rectFinal(".chip-email"), 2.1, { dx: 260 });   // close on the verified chip
  E.camOn(End(4, 0.15), L(5, 0.7), () => app.rectFinal(card(2)), 1.5, { dy: 60 });       // controls
  E.camOn(L(8, -0.2), L(8, 0.6), () => app.rectFinal("select"), 1.6, { dy: 10 });       // expiry
  E.camOn(End(8, 0.2), L(9, 0.5), () => app.rectFinal(goBtn), 1.7, { dx: -120 });        // the button
  E.camTo(L(10, -0.1), L(10, 0.8), 960, 540, 0.9);                                        // pull back for the prompts
  E.camOn(L(11, -0.2), L(11, 0.6), () => app.rectFinal(".panel-ok"), 1.25, { dy: 40 });  // the result
  E.camTo(L(12, -0.2), L(12, 0.7), 960, 540, 1.0, ease.inOutExpo);

  // ---------------------------------------------------------------- cursor
  const C = E.cursor;
  C.place([420, 980]);
  C.show(L(1, 1.2));
  C.move(L(1, 1.3), L(2, 0.0), [FILE0[0] + 10, FILE0[1] - 10]);
  C.press(L(2, 0.05));
  E.sfx(L(2, 0.05), "click", 0.7);
  C.move(L(2, 0.2), L(2, 1.5), () => app.center(".dropzone"), { bend: -0.12 });
  C.press(L(2, 1.55));
  app.drop(L(2, 1.6), ["/Users/alice/Documents/Project-plan.pdf"]);
  E.sfx(L(2, 1.6), "drop");

  // 2. Bob's email.
  app.scrollTo(End(2, 0.15), L(3, 0.4), (d) => d.querySelectorAll("section.card")[1]);
  C.move(End(2, 0.3), L(3, 0.35), () => app.center(".email-input input"));
  app.click(L(3, 0.4), ".email-input input");
  app.type(L(3, 0.55), End(3, -0.05), ".email-input input", BOB.email, { enter: true });
  E.release(End(3, 0.55), "lookup");
  E.sfx(End(3, 0.6), "success", 0.6);
  E.spot(L(4, 0.35), End(4, 0.1), ui(".chip-email"), "Verified account", { side: "below" });
  E.caption(L(4, 0.4), End(4), "Green tick = [[Bob’s real account]]");

  // 3. Controls.
  app.scrollTo(End(4, 0.1), L(5, 0.7), (d) => d.querySelectorAll("section.card")[2], 18);
  C.move(End(4, 0.2), L(5, 0.6), [1500, 360]);
  E.spot(L(6, 0.1), End(6, 0.15), () => app.rect(toggle("Ask me before each open")), "Bob waits for Alice’s OK", { side: "below" });
  E.spot(L(7, 0.05), End(7, 0.15), () => app.rect(toggle("One-time")), "Opens once", { side: "below" });
  E.spot(L(8, 0.0), End(8, 0.5), () => app.rect("select"), "Stops opening after…", { side: "above" });
  C.move(L(8, 0.0), L(8, 0.7), () => app.center("select"));
  app.click(L(8, 0.8), "select");
  E.do(L(8, 1.3), () => { const s = app.q("select"); s.value = "2"; s.dispatchEvent(new app.win.Event("change", { bubbles: true })); });
  E.sfx(L(8, 1.3), "tick", 0.6);

  // 4. Encrypt and send.
  app.scrollTo(End(8, 0.2), L(9, 0.3), goBtn, 420);
  C.move(L(9, -0.1), L(9, 0.9), () => app.center(byText("Encrypt and send", "button")));
  app.click(L(9, 1.0), byText("Encrypt and send", "button"));
  E.caption(L(9, 0.2), End(9, 0.3), "Encrypt and send");

  // Confirm it's you: Touch ID on a Mac, Windows Hello (or the password) on Windows.
  const mac = E.add(macTouchId("send a file securely"), null, E.hud);
  const wh = E.add(winHello(), null, E.hud);
  const macTag = E.add(`<div class="badge" style="position:absolute">Mac</div>`, null, E.hud);
  const winTag = E.add(`<div class="badge" style="position:absolute">Windows</div>`, null, E.hud);
  const pinBox = wh.querySelector(".pin");
  const fp = mac.querySelector(".fp svg");
  E.sfx(L(10, 0.25), "pop", 0.7);
  E.every((t) => {
    const a = env(t, L(10, 0.2), End(10, -0.15), 0.6, 0.45);
    for (const [el, x, y, d] of [[mac, 690, 540, 0], [wh, 1250, 540, 0.12], [macTag, 690, 300, 0.2], [winTag, 1250, 300, 0.3]]) {
      el.style.display = a > 0 ? "" : "none";
      const p = ease.outBack(prog(t, L(10, 0.2 + d), L(10, 0.85 + d)));
      el.style.left = `${x}px`; el.style.top = `${y}px`;
      el.style.opacity = a;
      el.style.transform = `translate(-50%,-50%) scale(${0.85 + 0.15 * p}) translateY(${(1 - p) * 30}px)`;
    }
    // The fingerprint fills in; PIN dots appear one by one.
    const f = prog(t, L(10, 1.6), L(10, 3.4));
    fp.style.opacity = 0.35 + 0.65 * f;
    fp.style.filter = `drop-shadow(0 0 ${f * 14}px rgba(255,106,61,${f}))`;
    const n = Math.floor(prog(t, L(10, 1.4), L(10, 3.6)) * 6);
    if (pinBox.childElementCount !== n) pinBox.innerHTML = "<i style='width:12px;height:12px;border-radius:50%;background:#fff;display:block'></i>".repeat(n);
  });
  for (let i = 0; i < 6; i++) E.sfx(L(10, 1.4 + i * 0.36), "key", 0.35);
  E.sfx(L(10, 3.5), "success", 0.7);
  E.caption(L(10, 0.6), End(10, -0.2), "Confirm it’s you");
  E.release(End(10, -0.3), "send");

  // 5. Locked: the result, then the file turns into its .svx.
  E.spot(L(11, 0.1), L(11, 2.0), ui(".panel-ok .panel-head"), null, { pad: 18 });
  E.sfx(L(11, 0.0), "lock");
  const pdf = E.add(fileIcon("Project-plan.pdf"), null, E.hud);
  const svx = E.add(fileIcon("Project-plan.svx", "svx"), null, E.hud);
  const MORPH = L(11, 2.3);
  E.every((t) => {
    const a = env(t, L(11, 1.9), End(13, 0.6), 0.5, 0.5);
    const morph = ease.inOutExpo(prog(t, MORPH, MORPH + 0.7));
    const lift = ease.outExpo(prog(t, L(12, 0.0), L(12, 0.8)));
    for (const [el, show] of [[pdf, 1 - morph], [svx, morph]]) {
      el.style.display = a > 0 ? "" : "none";
      el.style.left = "885px"; el.style.top = `${330 - lift * 20}px`;
      el.style.opacity = a * show;
      el.style.transform = `scale(${1.5 * (el === svx ? 0.85 + 0.15 * ease.outBack(prog(t, MORPH, MORPH + 0.8)) : 1 - 0.2 * morph)}) rotateY(${(el === svx ? 1 - morph : -morph) * 90}deg)`;
    }
  });
  E.sfx(MORPH, "whoosh", 0.6);
  E.caption(L(11, 0.4), End(11, 0.2), "Locked in a [[.svx]] file");

  // 6. Send it any way: chat, email, USB.
  const dests = [["chat", "WhatsApp", 560, 0.0], ["mail", "Email", 960, 0.9], ["usb", "USB stick", 1360, 1.5]].map(([k, label, x, d]) => {
    const el = E.add(destination(k, label), null, E.hud);
    const copy = E.add(fileIcon("", "svx"), null, E.hud);
    return { el, copy, x, d };
  });
  E.every((t) => {
    const out = 1 - ease.in(prog(t, End(13, 0.3), End(13, 0.95)));
    for (const { el, copy, x, d } of dests) {
      const p = ease.outBack(prog(t, L(12, 0.5 + d * 0.25), L(12, 1.1 + d * 0.25)));
      el.style.display = p > 0 ? "" : "none";
      el.style.left = `${x - 150}px`; el.style.top = "640px";
      el.style.opacity = Math.min(1, p) * out;
      el.style.transform = `translateY(${(1 - p) * 60}px)`;
      // A copy flies from the big file into each, as its name is spoken.
      const ft = L(13, d);
      const f = ease.inOutExpo(prog(t, ft, ft + 0.75));
      copy.style.display = t >= ft ? "" : "none";
      copy.style.left = `${885 + (x - 960) * f}px`; copy.style.top = `${300 + 300 * f}px`;
      copy.style.transform = `scale(${1.2 - 0.75 * f})`;
      copy.style.opacity = (f < 1 ? 0.95 : 1 - prog(t, ft + 0.75, ft + 1.0)) * out;
      const glow = env(t, ft + 0.7, ft + 1.6, 0.15, 0.6);
      el.style.borderColor = glow > 0 ? `rgba(255,106,61,${0.4 + 0.6 * glow})` : "";
      el.style.boxShadow = `0 30px 70px rgba(0,0,0,.5), 0 0 ${40 * glow}px rgba(255,106,61,${0.45 * glow})`;
    }
  });
  for (const [, , , d] of [["", "", 0, 0], ["", "", 0, 0.9], ["", "", 0, 1.5]]) E.sfx(L(13, d + 0.65), "pop", 0.6);
  E.caption(L(12, 0.3), End(13, 0.2), "Every copy stays [[locked]]", { y: 210 });

  C.show(L(11, 1.9), false);

  // Fade the app away when the file leaves it.
  E.every((t) => {
    const dim = ease.inOut(prog(t, L(11, 1.7), L(11, 2.2)));
    const gone = ease.inOut(prog(t, L(12, -0.1), L(12, 0.6)));
    win.style.opacity = (1 - 0.82 * dim) * (1 - gone);
    win.style.filter = dim > 0 ? `blur(${dim * 6}px)` : "";
  });
  E.every((t) => {
    E.root.style.opacity = 1 - ease.in(prog(t, E.duration - 0.6, E.duration));
  });
}
