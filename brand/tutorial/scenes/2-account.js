// Chapter 2: Create your account (email path in one window, Google's name step in another).
import { ease, env, prog } from "../engine.js";
import { ALICE, NOW, appState, avatar, badge, signedIn } from "./common.js";

export default async function scene(E) {
  const L = (i, d) => E.at(i, d), End = (i, d) => E.end(i, d);
  const AX = 1010, BX = 3010, Y = 560;

  // ---------------------------------------------------------------- what the service would say
  let signed = false, named = false;
  const info = { account: ALICE.account, email: ALICE.email, provider: "Email", issuer: "svx:email", created_at: NOW, signing_key_id: "a1", kem_key_id: "b2", kem_public: "" };
  const A = await E.appWindow({
    id: "acct", x: AX, y: Y, os: "mac", now: NOW,
    fixtures: {
      state: () => (signed ? appState(ALICE) : { ...appState(ALICE), configured: false, org_id: null, personal: false, email: null }),
      providers: { service_url: "https://api.getsvx.me:8443", dev: false, providers: [{ name: "Google", issuer: "https://accounts.google.com" }] },
      request_email_code: { challenge: "c1", expires_at: NOW + 600 },
      password_strength: { score: 4, ok: true, feedback: [] },
      email_sign_up: async () => { await E.gate("signup"); signed = true; return info; },
      account: info,
      account_name: { first_name: "Alice", last_name: "Example" },
    },
  });
  const B = await E.appWindow({
    id: "name", x: BX, y: Y, os: "mac", now: NOW,
    fixtures: {
      ...signedIn(ALICE),
      account: { ...info, provider: "Google", issuer: "https://accounts.google.com" },
      account_name: () => (named ? { first_name: "Alice", last_name: "Example" } : { first_name: null, last_name: null }),
      set_account_name: () => { named = true; return { first_name: "Alice", last_name: "Example" }; },
    },
  });

  const byText = (text, within) => (d) => [...d.querySelectorAll(within)].find((e) => e.textContent.trim() === text);
  const nth = (sel, i) => (d) => d.querySelectorAll(sel)[i];
  const card = (d) => d.querySelectorAll("section.card")[1] ?? d.querySelector("section.card");
  const emailBtn = ".btn-email", googleBtn = ".btn-google";
  const cont = byText("Continue", "button");

  E.every((t) => { E.world.style.opacity = ease.out(prog(t, L(1, -0.55), L(1, 0.25))); });
  E.titleCard(0.05, L(1, -0.1), 2, "Create your account");
  badge(E, L(1, 0.1), End(3, 0.5), AX - 450, 120, `${avatar(ALICE, "#ff6a3d")}<span>Alice’s computer</span>`);
  badge(E, L(4, 0.0), End(5, 0.3), BX - 450, 120, `${avatar(ALICE, "#ff6a3d")}<span>With a Google account</span>`);

  // ---------------------------------------------------------------- camera
  E.cam(0, AX, Y, 0.95);
  E.camOn(L(1, 0.0), L(1, 0.9), () => A.rect(".provider-buttons"), 1.55, { dy: 50 });
  E.camOn(L(1, 3.5), L(1, 4.3), () => A.rectFinal(card), 1.15, { dy: 40 });
  E.camOn(L(3, -0.2), L(3, 0.5), () => A.rectFinal(card), 1.3, { dy: 40 });
  E.camTo(L(4, -0.35), L(4, 0.75), BX, Y, 0.95, ease.inOutExpo);
  E.camOn(L(4, 0.9), L(4, 1.6), () => B.rect("section.card"), 1.4, { dy: 40 });
  E.camTo(End(5, 0.15), L(6, 0.6), AX, Y, 0.95, ease.inOutExpo);
  E.camOn(L(6, 0.8), L(6, 1.5), () => A.rect(".panel-ok"), 1.45, { dy: 60 });
  E.camOn(L(8, -0.1), L(8, 0.7), () => A.rect("section.card"), 1.25, { dy: 50 });
  E.camTo(L(9, 0.2), L(9, 1.1), AX, Y, 0.9);

  // ---------------------------------------------------------------- 1. two ways in
  E.spot(L(1, 0.15), L(1, 1.5), () => A.rect(googleBtn), "Google", { side: "right", pad: 8 });
  E.spot(L(1, 1.6), L(1, 3.1), () => A.rect(emailBtn), "Email + password", { side: "right", pad: 8 });
  E.caption(L(1, 0.3), End(1, 0.1), "[[Google]], or [[email]] and a password");

  const C = E.cursor;
  C.place([1500, 800]); C.show(L(1, 1.4));
  C.move(L(1, 1.5), L(1, 2.3), () => A.center(emailBtn));
  A.click(L(1, 2.4), emailBtn);
  A.scrollTo(L(1, 2.7), L(1, 3.4), card, 20);

  // ---------------------------------------------------------------- 2. the form, then the emailed code
  const f = (sel) => (d) => d.querySelectorAll(sel)[0];
  A.type(5.6, 6.0, f('input[autocomplete="given-name"]'), "Alice");
  A.type(6.05, 6.45, f('input[autocomplete="family-name"]'), "Example");
  A.type(6.55, 7.6, f('input[type="email"]'), "alice@example.com");
  A.type(7.7, 8.2, nth('input[autocomplete="new-password"]', 0), "plum-river-lantern-42");
  A.type(8.25, 8.6, nth('input[autocomplete="new-password"]', 1), "plum-river-lantern-42");
  C.move(8.2, 8.8, () => A.center(cont));
  A.click(8.95, cont);
  E.caption(L(2, 0.2), End(2, 0.2), "SVX emails you a [[6-digit code]]");

  // ---------------------------------------------------------------- 3. check spam
  E.spot(L(3, 0.05), 11.3, () => A.rect(".note-info"), "Check Spam, too", { side: "below", pad: 8 });
  C.move(11.0, 11.4, () => A.center("input.code-input"));
  A.click(11.45, "input.code-input");
  A.type(11.5, 11.95, "input.code-input", "482915");
  C.move(11.95, 12.3, () => A.center(byText("Create account", "button")));
  A.click(12.4, byText("Create account", "button"));
  E.caption(L(3, 0.1), 11.9, "Not there? Look in [[Spam]]");
  E.release(13.1, "signup");
  E.sfx(13.15, "success", 0.6);
  C.show(12.6, false);

  // ---------------------------------------------------------------- 4. the name (Google accounts)
  const first = 'input[autocomplete="given-name"]', last = 'input[autocomplete="family-name"]';
  C.place([BX + 400, Y + 220]);
  C.show(13.6);
  C.move(13.6, 14.0, () => B.center(first));
  B.click(14.05, first);
  B.type(14.1, 14.5, first, "Alice");
  C.move(14.55, 14.95, () => B.center(last));
  B.click(15.0, last);
  B.type(15.05, 15.6, last, "Example");
  E.caption(L(4, 0.4), End(4, 0.2), "Next, your [[name]]");
  E.spot(15.9, 18.4, () => B.rect("section.card p"), "Shown next to your email", { side: "below", pad: 10 });
  C.move(17.9, 18.5, () => B.center(byText("Continue", "button")));
  B.click(18.65, byText("Continue", "button"));
  E.caption(L(5, 1.0), End(5, 0.1), "So they know it’s [[really you]]");
  C.show(18.9, false);

  // ---------------------------------------------------------------- 5. keys, made here
  E.spot(L(6, 1.0), End(6, 0.4), () => A.rect(".panel-ok"), "Your keys are ready", { side: "right", pad: 12 });
  E.sfx(L(6, 1.0), "lock", 0.6);
  E.caption(L(6, 0.3), End(6, 0.2), "Keys made [[on this computer]]");
  E.caption(L(7, 0.1), End(7, 0.3), "They [[never leave it]]");

  // ---------------------------------------------------------------- 6. offer to back up
  E.spot(L(8, 0.4), End(8, 0.2), () => A.rect("section.card"), "Save a backup", { side: "below", pad: 12 });
  E.caption(L(8, 0.2), End(8, 0.3), "Save a [[backup]] of your keys");
  E.caption(L(9, 0.2), End(9, 0.6), "Why it matters: the [[last chapter]]");

  E.every((t) => { E.root.style.opacity = 1 - ease.in(prog(t, E.duration - 0.6, E.duration)); });
}
