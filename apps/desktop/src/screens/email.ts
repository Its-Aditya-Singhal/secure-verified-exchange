// Email + password accounts: create an account, sign in on a new device,
// forgotten password and key reset. Every step that touches keys needs a
// six-digit code the service emails. The password rules and the strength
// meter come from Rust (the service checks the same rules again); this
// screen only collects input and shows results.

import { type AccountInfo, type AppError, type PasswordStrength, api, asAppError } from "../api";
import { card, errorPanel, note } from "../components";
import { append, busy, button, clear, field, h } from "../dom";

export type EmailMode = "sign_up" | "sign_in" | "forgot" | "reset_keys";
type Purpose = "sign_up" | "sign_in" | "reset_password";

const LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];

/** A live strength meter for a new password. */
export function strengthMeter(): { el: HTMLElement; update(pw: string, inputs: string[]): Promise<PasswordStrength> } {
  const bar = h("div", { class: "meter-bar" });
  const label = h("span", { class: "meter-label" });
  const tips = h("p", { class: "muted small meter-tips" });
  const el = h("div", { class: "meter", "aria-live": "polite" }, h("div", { class: "meter-track" }, bar), label, tips);
  let seq = 0;
  async function update(pw: string, inputs: string[]): Promise<PasswordStrength> {
    const mine = ++seq;
    const s = await api.passwordStrength(pw, inputs);
    if (mine !== seq) return s;
    el.dataset.score = String(s.score);
    el.classList.toggle("meter-ok", s.ok);
    bar.style.width = pw ? `${(s.score + 1) * 20}%` : "0";
    label.textContent = pw ? (s.ok ? `${LABELS[s.score]}: good to use` : LABELS[s.score]) : "";
    tips.textContent = pw ? s.feedback.join(" ") : "At least 12 characters. A few unrelated words work well.";
    return s;
  }
  void update("", []);
  return { el, update };
}

function input(type: string, autocomplete: string, placeholder = ""): HTMLInputElement {
  return h("input", { type, autocomplete, placeholder, spellcheck: "false" });
}

/**
 * The email flow as a card. `done` gets the account after a sign-up or
 * sign-in (not after a password reset, which ends at "sign in now").
 */
export function emailFlow(opts: {
  mode: EmailMode;
  email?: string;
  replace?: boolean;
  done: (a: AccountInfo) => void | Promise<void>;
  onSwitch?: (mode: EmailMode) => void;
}): HTMLElement {
  const { mode } = opts;
  const body = h("div", { class: "stack" });
  const out = h("div", {});
  const email = input("email", "email", "you@example.com");
  email.value = opts.email ?? "";
  const first = input("text", "given-name");
  const last = input("text", "family-name");
  const pw = input("password", mode === "sign_in" || mode === "reset_keys" ? "current-password" : "new-password");
  const pw2 = input("password", "new-password");
  const meter = strengthMeter();
  const newPassword = mode === "sign_up" || mode === "forgot";
  const inputs = () => [email.value, first.value, last.value];
  const refresh = () => {
    if (newPassword) void meter.update(pw.value, inputs());
  };
  for (const i of [email, first, last, pw]) i.addEventListener("input", refresh);

  const title = {
    sign_up: "Create an account with your email",
    sign_in: "Sign in with your email",
    forgot: "Choose a new password",
    reset_keys: "Reset your keys",
  }[mode];

  const show = (e: unknown) => out.replaceChildren(errorPanel(asAppError(e)));

  // ----- Step 1: details, then send the code -----
  const send = button(mode === "forgot" ? "Email me a code" : "Continue", () => void (async () => {
    clear(out);
    const addr = email.value.trim();
    if (!addr.includes("@")) {
      out.appendChild(note("Enter your email address.", "warn"));
      return;
    }
    if (mode === "sign_up" && (!first.value.trim() || !last.value.trim())) {
      out.appendChild(note("Enter your first and last name.", "warn"));
      return;
    }
    if (mode !== "forgot" && !pw.value) {
      out.appendChild(note("Enter your password.", "warn"));
      return;
    }
    if (newPassword && mode === "sign_up") {
      const s = await meter.update(pw.value, inputs());
      if (!s.ok) {
        out.appendChild(note("Choose a stronger password (see the tips under the meter).", "warn"));
        return;
      }
      if (pw.value !== pw2.value) {
        out.appendChild(note("The two passwords don't match.", "warn"));
        return;
      }
    }
    await busy(send, "Sending the code…", async () => {
      try {
        const purpose: Purpose = mode === "sign_up" ? "sign_up" : mode === "forgot" ? "reset_password" : "sign_in";
        const sent = await api.requestEmailCode(addr, purpose);
        codeStep(addr, purpose, sent.challenge);
      } catch (e) {
        show(e);
      }
    });
  })(), "primary");

  append(body,
    mode === "sign_up"
      ? h("div", { class: "grid2" }, field("First name", first), field("Last name", last))
      : null,
    field("Email address", email),
    mode === "forgot" ? null : field(mode === "sign_up" ? "Password" : "Password", pw),
    mode === "sign_up" ? field("Confirm password", pw2) : null,
    mode === "sign_up" ? meter.el : null,
    h("div", { class: "actions" }, send),
    mode === "sign_in" && opts.onSwitch
      ? h("p", { class: "muted small" }, button("Forgot your password?", () => opts.onSwitch!("forgot"), "link"))
      : null,
    mode === "sign_up"
      ? h("p", { class: "muted small" },
        "Your name is shown to people you send files to, next to your verified email address.")
      : null,
  );

  // ----- Step 2: the code (and, for "forgot", the new password) -----
  function codeStep(addr: string, purpose: Purpose, firstChallenge: string) {
    let challenge = firstChallenge;
    const code = h("input", {
      type: "text", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "6",
      placeholder: "123456", class: "code-input", spellcheck: "false",
    });
    const res = h("div", {});
    const form = () => ({
      email: addr,
      password: pw.value,
      first_name: mode === "sign_up" ? first.value.trim() : null,
      last_name: mode === "sign_up" ? last.value.trim() : null,
      challenge,
      code: code.value.trim(),
    });

    const go = button(
      { sign_up: "Create account", sign_in: "Sign in", forgot: "Set new password", reset_keys: "Reset my keys" }[mode],
      () => void (async () => {
        clear(res);
        if (!/^\d{6}$/.test(code.value.trim())) {
          res.appendChild(note("Enter the 6 digits from the email.", "warn"));
          return;
        }
        if (mode === "forgot") {
          const s = await meter.update(pw.value, inputs());
          if (!s.ok) {
            res.appendChild(note("Choose a stronger password (see the tips under the meter).", "warn"));
            return;
          }
          if (pw.value !== pw2.value) {
            res.appendChild(note("The two passwords don't match.", "warn"));
            return;
          }
        }
        await busy(go, mode === "sign_up" ? "Creating your keys…" : "Checking…", async () => {
          try {
            if (mode === "forgot") {
              await api.resetPassword(addr, challenge, code.value.trim(), pw.value);
              pw.value = "";
              pw2.value = "";
              clear(body);
              append(body,
                note("Your password is changed. Sign in with it now.", "ok"),
                opts.onSwitch ? h("div", { class: "actions" }, button("Sign in", () => opts.onSwitch!("sign_in"), "primary")) : null,
              );
              return;
            }
            const a = await api.emailSignUp(form(), mode === "reset_keys", opts.replace ?? false);
            pw.value = "";
            pw2.value = "";
            await opts.done(a);
          } catch (e) {
            const err = asAppError(e);
            if (err.kind === "account_exists") {
              res.appendChild(anotherDevice(err, form));
            } else {
              res.appendChild(errorPanel(err));
            }
          }
        });
      })(),
      mode === "reset_keys" ? "danger" : "primary",
    );

    const resendOut = h("span", { class: "muted small" });
    const resend = button("Send a new code", () => void (async () => {
      resendOut.textContent = "";
      try {
        challenge = (await api.requestEmailCode(addr, purpose)).challenge;
        resendOut.textContent = "Sent. Use the newest code.";
      } catch (e) {
        resendOut.textContent = asAppError(e).message;
      }
    })(), "link");

    const pwFields = mode === "forgot"
      ? [field("New password", pw), field("Confirm new password", pw2), meter.el]
      : [];
    body.replaceChildren(
      h("p", {}, "We sent a 6-digit code to ", h("strong", {}, addr),
        ". It expires in 10 minutes."),
      note("Can't find it? Check your Spam or Junk folder. If it's there, open it and choose \u201cNot spam\u201d (or \u201cReport not spam\u201d), so future emails from SVX reach your inbox.", "info"),
      field("Code", code),
      ...pwFields,
      h("div", { class: "actions" }, go),
      h("p", { class: "small" }, resend, " ", resendOut),
      res,
    );
    clear(out);
    if (mode === "forgot") refresh();
    code.focus();
  }

  /** The account has keys on another device: restore the backup, or reset. */
  function anotherDevice(err: AppError, form: () => Parameters<typeof api.emailSignUp>[0]): HTMLElement {
    const rpw = input("password", "current-password", "Recovery password");
    const rres = h("div", {});
    const restore = button("Choose backup file…", () => void (async () => {
      clear(rres);
      if (!rpw.value) {
        rres.appendChild(note("Enter the recovery password first.", "warn"));
        return;
      }
      await busy(restore, "Restoring…", async () => {
        try {
          const a = await api.emailRestore(form(), rpw.value, opts.replace ?? false);
          if (a) await opts.done(a);
        } catch (e) {
          rres.appendChild(errorPanel(asAppError(e)));
        }
      });
    })(), "primary");
    const confirm = h("input", { type: "checkbox" });
    const xres = h("div", {});
    const reset = button("Reset my keys", () => void (async () => {
      clear(xres);
      if (!confirm.checked) {
        xres.appendChild(note("Tick the box to confirm first.", "warn"));
        return;
      }
      await busy(reset, "Resetting…", async () => {
        try {
          await opts.done(await api.emailSignUp(form(), true, opts.replace ?? false));
        } catch (e) {
          xres.appendChild(errorPanel(asAppError(e)));
        }
      });
    })(), "danger");
    return h("div", { class: "stack" },
      errorPanel(err),
      card("Restore from your backup",
        field("Recovery password", rpw),
        h("div", { class: "actions" }, restore),
        rres),
      card("No backup?",
        h("p", {}, "Resetting gives your account new keys. Files people sent you before can't be opened any more, and your other devices are signed out."),
        h("label", { class: "check" }, confirm, h("span", {}, "I understand that files sent to my old keys will no longer open")),
        h("div", { class: "actions" }, reset),
        xres),
    );
  }

  return card(title, body, out);
}

/** Settings: change the password of an email account. */
export function changePasswordCard(email: string): HTMLElement {
  const cur = input("password", "current-password");
  const pw = input("password", "new-password");
  const pw2 = input("password", "new-password");
  const meter = strengthMeter();
  pw.addEventListener("input", () => void meter.update(pw.value, [email]));
  const out = h("div", {});
  const save = button("Change password", () => void (async () => {
    clear(out);
    const s = await meter.update(pw.value, [email]);
    if (!s.ok) {
      out.appendChild(note("Choose a stronger password (see the tips under the meter).", "warn"));
      return;
    }
    if (pw.value !== pw2.value) {
      out.appendChild(note("The two new passwords don't match.", "warn"));
      return;
    }
    await busy(save, "Saving…", async () => {
      try {
        await api.changePassword(cur.value, pw.value);
        cur.value = pw.value = pw2.value = "";
        void meter.update("", [email]);
        out.appendChild(note("Password changed.", "ok"));
      } catch (e) {
        out.appendChild(errorPanel(asAppError(e)));
      }
    });
  })(), "primary");
  return card("Password",
    h("p", { class: "muted" }, "Your password and an emailed code are needed to sign in on a new computer. It doesn't unlock your files: your keys stay on this device."),
    field("Current password", cur),
    h("div", { class: "grid2" }, field("New password", pw), field("Confirm new password", pw2)),
    meter.el,
    h("div", { class: "actions" }, save),
    out);
}
