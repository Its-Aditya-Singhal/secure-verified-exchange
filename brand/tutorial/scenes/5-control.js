// Chapter 5: Stay in control. Bob waits, Alice approves, then History, expiry, revoke.
import { ease, env, prog } from "../engine.js";
import { ALICE, BOB, NOW, avatar, badge, signedIn, statusFor } from "./common.js";

const PATH = "/Users/bob/Downloads/Project-plan.svx";
const MAIL = `<svg viewBox="0 0 64 64" fill="none" stroke="#9db5c9" stroke-width="4" stroke-linejoin="round"><rect x="8" y="14" width="48" height="36" rx="5"/><path d="M10 18l22 17 22-17"/></svg>`;

export default async function scene(E) {
  const L = (i, d) => E.at(i, d), End = (i, d) => E.end(i, d);
  const AX = 1010, BX = -1010, Y = 560;

  // ---------------------------------------------------------------- what the services "know"
  let reqList = [];
  const person = { state: "not_opened", requested_at: null, opened_at: null };
  const file = {
    artifact_id: "5a1f", sender: ALICE.account, sender_email: ALICE.email, created_at: NOW - 3600 * 5,
    signed_expires_at: NOW + 14 * 86400,
    rules: { require_approval: true, one_time: true, expires_at: NOW + 7 * 86400, view_only: false, allow_share_requests: false },
    signed_view_only: false, revoked_at: null, file_name: "Project-plan.pdf",
    get recipients() { return [{ account: BOB.account, email: BOB.email, ...person }]; },
  };
  const snap = () => JSON.parse(JSON.stringify({ ...file, recipients: file.recipients }));
  let pending = [];

  const alice = await E.appWindow({
    id: "alice", x: AX, y: Y, os: "mac", now: NOW,
    fixtures: signedIn(ALICE, {
      requests: () => reqList.slice(),
      approve: () => { reqList = []; person.state = "approved"; return null; },
      history: () => ({ sent: [snap()], received: [] }),
      file: () => snap(),
      update_file: ({ update }) => {
        if (update.expires_at != null) file.rules.expires_at = update.expires_at;
        if (update.revoke) { file.revoked_at = NOW; person.state = "revoked"; }
        return snap();
      },
    }),
  });
  const bob = await E.appWindow({
    id: "bob", x: BX, y: Y, os: "win", now: NOW,
    fixtures: signedIn(BOB, {
      take_pending: () => { const p = pending; pending = []; return p; },
      status: statusFor(BOB),
      open: async () => {
        await E.gate("open");
        return { path: "/Users/bob/Documents/SVX/Project-plan.pdf", name: "Project-plan.pdf", is_folder: false, size: 482113, sender_org: ALICE.account, artifact_id: "5a1f", classification: null, description: null, can_open: true };
      },
    }),
  });

  const byText = (text, within) => (d) => [...d.querySelectorAll(within)].find((e) => e.textContent.trim() === text);
  const card = (i) => (d) => d.querySelectorAll("section.card")[i];
  const lastCard = (d) => [...d.querySelectorAll("section.card")].pop();
  const approveBtn = byText("Approve", "button");
  const checkbox = (d) => d.querySelector("label.check input");
  const nav = (r) => `.nav-item[data-route="${r}"]`;

  E.every((t) => { E.world.style.opacity = ease.out(prog(t, L(1, -0.55), L(1, 0.25))); });
  E.titleCard(0.05, L(1, -0.1), 5, "Stay in control");
  badge(E, L(1, 0.1), End(10), BX - 450, 120, `${avatar(BOB, "#9db5c9")}<span>Bob’s computer</span>`);
  badge(E, L(1, 0.1), End(10), AX - 450, 120, `${avatar(ALICE, "#ff6a3d")}<span>Alice’s computer</span>`);

  // ---------------------------------------------------------------- set-up while the title plays
  E.do(0.05, () => { pending = [PATH]; bob.win.svxEmit("open-file", null); });
  E.do(0.5, () => bob.q(byText("Open securely", "button"))?.click());
  const step = (t, name, sender = null) => bob.emit(t, "open-progress", { step: name, index: 0, sender });
  step(0.7, "verifying"); step(0.75, "signature_valid", "Alice Example"); step(0.8, "connecting");
  step(0.85, "checking_authorization"); step(0.9, "awaiting_approval", "Alice Example");
  E.do(1.0, () => { person.state = "requested"; person.requested_at = NOW - 60; });

  // ---------------------------------------------------------------- camera
  E.cam(0, BX, Y, 0.95);
  E.camOn(L(1, 0.0), L(1, 0.9), () => bob.rect("ol.timeline"), 1.2, { dy: 30 });
  E.camTo(L(1, 1.5), L(1, 2.5), AX, Y, 0.95, ease.inOutExpo);
  E.camOn(L(2, 1.1), L(2, 2.0), () => alice.rectFinal("section.card"), 1.3, { dy: 50 });
  E.camOn(L(3, -0.2), L(3, 0.6), () => alice.rectFinal(approveBtn), 1.3, { dy: -10, dx: 0 });
  E.camTo(L(3, 1.2), L(4, 0.45), BX, Y, 0.95, ease.inOutExpo);
  E.camOn(L(4, 0.6), L(4, 1.2), () => bob.rect(".panel-ok"), 1.2, { dy: 30 });
  E.camTo(L(5, -0.3), L(5, 0.8), AX, Y, 0.95, ease.inOutExpo);
  E.camOn(L(5, 1.5), L(5, 2.2), () => alice.rectFinal("ul.list"), 1.5, { dy: 40 });
  E.camOn(L(6, 0.4), L(6, 1.1), () => alice.rectFinal(card(0)), 1.4, { dy: 40 });
  E.camOn(L(7, 0.15), L(7, 0.9), () => alice.rectFinal(".row"), 1.5, { dy: 50 });
  E.camOn(L(8, 0.0), L(8, 0.8), () => alice.rectFinal(lastCard), 1.4, { dy: 30, dx: -250 });
  E.camOn(End(8, 1.3), L(9, 0.8), () => alice.rectFinal(".panel-info, .note"), 1.3, { dy: 40 });
  E.camTo(L(10, -0.3), L(10, 0.8), BX, Y, 0.95, ease.inOutExpo);
  E.camOn(L(10, 0.9), L(10, 1.6), () => bob.rect(".panel-ok"), 1.2, { dy: 30 });

  // ---------------------------------------------------------------- 1. Bob waits; Alice is told
  E.spot(L(1, 0.2), L(1, 1.5), () => bob.rect('li.step[data-step="checking_authorization"]'), "Bob waits for Alice", { side: "right", pad: 10 });
  const toast = E.add(`<div class="mailtoast" style="left:1350px;top:150px"><div class="mt-h">${MAIL}<span>Mail · now</span></div><b>Bob Example wants to open a file you sent</b>Open SVX to approve or decline.</div>`, null);
  const T = L(1, 2.3);
  E.every((t) => {
    const a = env(t, T, End(2, -0.6), 0.5, 0.5);
    const p = ease.outBack(prog(t, T, T + 0.6));
    toast.style.display = a > 0 ? "" : "none";
    toast.style.opacity = a;
    toast.style.transform = `translateX(${(1 - p) * 120}px)`;
  });
  E.sfx(T, "pop", 0.8);
  E.do(T + 0.1, () => {
    reqList = [{ kind: "open", request_id: "r1", artifact_id: "5a1f", requester: BOB.account, requester_email: BOB.email, requested_at: NOW - 120, expires_at: NOW + 86400, file_name: "Project-plan.pdf" }];
    const n = alice.q(nav("requests"));
    if (n && !n.querySelector(".nav-badge")) { const b = alice.doc.createElement("span"); b.className = "nav-badge"; b.textContent = "1"; n.appendChild(b); }
  });
  E.caption(L(1, 2.0), End(1, 0.1), "Alice gets an [[email]] and a [[request]]");

  // ---------------------------------------------------------------- 2. Alice checks and approves
  const C = E.cursor;
  C.place([1500, 900]);
  C.show(L(2, -0.3));
  C.move(L(2, -0.2), L(2, 0.8), () => alice.center(nav("requests")));
  alice.click(L(2, 0.9), nav("requests"));
  E.spot(L(2, 1.9), End(2, 0.1), () => alice.rect("label.check"), "Ask Bob yourself", { side: "below", pad: 10 });
  C.move(L(2, 2.0), L(2, 2.7), () => alice.center("label.check input"));
  alice.click(L(2, 2.8), checkbox, "tick");
  E.caption(L(2, 1.1), End(2, 0.1), "She makes sure it’s [[really Bob]]");
  C.move(L(3, -0.1), L(3, 0.5), () => alice.center(approveBtn));
  alice.click(L(3, 0.7), approveBtn);
  E.caption(L(3, 0.2), End(3, 0.2), "[[Approve]]");

  // ---------------------------------------------------------------- 3. Bob's file opens
  step(L(3, 1.5), "access_approved"); step(L(3, 1.9), "decrypting");
  E.release(L(4, 0.2), "open");
  E.sfx(L(3, 1.6), "success", 0.7);
  E.do(L(4, 0.2), () => { person.state = "opened"; person.opened_at = NOW + 300; });
  E.caption(L(4, 0.5), End(4, 0.2), "Bob’s file [[opens]]");
  C.show(End(4, 0.2), false);

  // ---------------------------------------------------------------- 4. History
  C.show(L(5, 0.4));
  C.move(L(5, 0.3), L(5, 1.0), () => alice.center(nav("history")));
  alice.click(L(5, 1.1), nav("history"));
  E.spot(L(5, 2.0), End(5, 0.2), () => alice.rect("ul.list li"), "Every file she sent", { side: "below", pad: 8 });
  E.caption(L(5, 0.9), End(5, 0.3), "[[History]]: everything she sent");
  C.move(L(6, -0.3), L(6, 0.3), () => alice.center("ul.list li .list-row"));
  alice.click(L(6, 0.4), "ul.list li .list-row");
  E.spot(L(6, 0.8), End(6, 0.3), () => alice.rect("ul.list .list-row"), "Bob opened it", { side: "below", pad: 8 });
  E.caption(L(6, 0.4), End(6, 0.3), "Who opened it, and [[when]]");

  // ---------------------------------------------------------------- 5. Stop sooner
  alice.scrollTo(L(7, -0.2), L(7, 0.6), card(1), 14);
  C.move(L(7, 0.5), L(7, 1.0), () => alice.center("select"));
  alice.click(L(7, 1.1), "select");
  E.do(L(7, 1.35), () => { const s = alice.q("select"); s.value = String(86400); s.dispatchEvent(new alice.win.Event("change", { bubbles: true })); });
  E.sfx(L(7, 1.35), "tick", 0.6);
  C.move(L(7, 1.4), L(7, 1.8), () => alice.center(byText("Set", "button")));
  alice.click(L(7, 1.9), byText("Set", "button"));
  E.spot(L(7, 0.5), End(7, 0.1), () => alice.rect(".row"), "Stop opening sooner", { side: "below", pad: 10 });
  E.caption(L(7, 0.2), End(7, 0.2), "Make it stop opening [[sooner]]");

  // ---------------------------------------------------------------- 6. Revoke
  alice.scrollTo(L(8, -0.2), L(8, 0.7), lastCard, 14);
  C.move(L(8, 0.6), L(8, 1.1), () => alice.center((d) => lastCard(d).querySelector("input")));
  alice.click(L(8, 1.2), (d) => lastCard(d).querySelector("input"), "tick");
  C.move(L(8, 1.3), L(8, 1.8), () => alice.center(byText("Revoke for everyone", "button")));
  alice.click(L(8, 1.9), byText("Revoke for everyone", "button"));
  E.sfx(L(8, 2.0), "lock", 0.8);
  E.spot(L(8, 0.6), End(8, 0.1), () => alice.rect(lastCard), "Revoke for everyone", { side: "left", pad: 10 });
  E.caption(L(8, 0.2), End(8, 0.3), "Or [[revoke]] it for everyone");
  E.caption(L(9, 0.1), End(9, 0.3), "Revoking stops [[future opens]]");
  C.show(L(9, 1.0), false);

  // ---------------------------------------------------------------- 7. The honest limit
  E.spot(L(10, 1.0), End(10, 0.1), () => bob.rect(".panel-ok"), "Already saved: it stays", { side: "right", pad: 10 });
  E.caption(L(10, 0.2), End(10, 0.3), "It can’t take back a [[saved copy]]");

  E.every((t) => { E.root.style.opacity = 1 - ease.in(prog(t, E.duration - 0.6, E.duration)); });
}
