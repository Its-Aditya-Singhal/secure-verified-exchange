// First screen: continue with Google, or create an account with an email
// address and a password. The app makes this
// device's keys (in Rust, kept in the keychain); afterwards it suggests a
// backup. Company setup stays available as a link.

import { type AccountInfo, type Provider, type Providers, api, asAppError } from "../api";
import { brandSymbol } from "../brand";
import { card, errorPanel, note } from "../components";
import { busy, button, clear, field, h, icon } from "../dom";
import type { Ctx } from "../main";
import { type EmailMode, emailFlow } from "./email";

export function welcomeScreen(ctx: Ctx, root: HTMLElement): void {
  const body = h("div", { class: "stack" });
  const out = h("div", { class: "stack" });
  const devUser = h("input", { type: "text", placeholder: "alice", autocomplete: "off", spellcheck: "false" });
  let providers: Providers | null = null;

  root.append(
    h("header", { class: "welcome-head" },
      brandSymbol("brand-symbol brand-symbol-lg"),
      h("h1", {}, "Secure Verified Exchange"),
      h("p", { class: "lede" }, "Send files that only the people you choose can open, and stay in control after you send them.")),
    body,
    out,
    h("p", { class: "muted small center" },
      "Setting up for a company? ",
      button("Company or test server setup", () => ctx.go("setup"), "link")),
  );

  const dev = () => (providers?.dev ? devUser.value.trim() || null : null);

  async function finish(a: AccountInfo) {
    await ctx.refreshState();
    clear(body);
    clear(out);
    body.appendChild(backupOffer(ctx, a));
  }

  async function signIn(p: Provider, btn: HTMLButtonElement, reset = false) {
    clear(out);
    await busy(btn, providers?.dev ? "Signing in…" : "Finish signing in in your browser…", async () => {
      try {
        await finish(await api.signUp(p.issuer, reset, dev(), false));
      } catch (e) {
        const err = asAppError(e);
        if (err.kind === "account_exists") {
          out.appendChild(anotherDevice(p));
        } else {
          out.appendChild(errorPanel(err));
        }
      }
    });
  }

  /** The account has keys elsewhere: restore the backup, or reset. */
  function anotherDevice(p: Provider): HTMLElement {
    const confirm = h("input", { type: "checkbox" });
    const reset = button("Reset my keys", () => {
      if (!confirm.checked) {
        resetOut.replaceChildren(note("Tick the box to confirm first.", "warn"));
        return;
      }
      void signIn(p, reset, true);
    }, "danger");
    const resetOut = h("div", {});
    return h("div", { class: "stack" },
      errorPanel({ kind: "account_exists", message: "", deny_reason: null, exit_code: 2, path: null }),
      restoreCard(p),
      card("No backup?",
        h("p", {}, "Resetting gives your account new keys. Files people sent you before can't be opened any more, and your other devices are signed out."),
        h("label", { class: "check" }, confirm, h("span", {}, "I understand that files sent to my old keys will no longer open")),
        h("div", { class: "actions" }, reset),
        resetOut),
    );
  }

  function restoreCard(p: Provider): HTMLElement {
    const pw = h("input", { type: "password", autocomplete: "current-password", placeholder: "Recovery password" });
    const res = h("div", {});
    const go = button("Choose backup file…", () => void (async () => {
      clear(res);
      if (!pw.value) {
        res.appendChild(note("Enter the recovery password first.", "warn"));
        return;
      }
      await busy(go, "Restoring…", async () => {
        try {
          const a = await api.restore(p.issuer, pw.value, dev(), false);
          if (a) await finish(a);
        } catch (e) {
          res.appendChild(errorPanel(asAppError(e)));
        }
      });
    })(), "primary");
    return card("Restore from your backup",
      h("p", { class: "muted" }, `You'll sign in with ${p.name}, then choose your .svxbackup file.`),
      field("Recovery password", pw),
      h("div", { class: "actions" }, go),
      res);
  }

  async function load() {
    body.appendChild(note("Connecting to the SVX service…", "info"));
    try {
      providers = await api.providers();
    } catch (e) {
      clear(body);
      body.appendChild(errorPanel(asAppError(e)));
      return;
    }
    clear(body);
    const list = providers.providers;
    const buttons = list.map((p) => {
      const b = h("button", { type: "button", class: `btn btn-provider btn-${p.name.toLowerCase()}` },
        `Continue with ${p.name}`);
      b.addEventListener("click", () => void signIn(p, b));
      return b;
    });
    let restoreShown = false;
    const restoreSlot = h("div", {});
    const emailSlot = h("div", {});
    const showEmail = (mode: EmailMode) => {
      clear(out);
      emailSlot.replaceChildren(emailFlow({ mode, done: finish, onSwitch: showEmail }));
      emailSlot.scrollIntoView({ behavior: "smooth", block: "start" });
    };
    const emailButton = h("button", { type: "button", class: "btn btn-provider btn-email" }, "Create account with email");
    emailButton.addEventListener("click", () => showEmail("sign_up"));
    body.append(
      card(null,
        h("div", { class: "provider-buttons" }, ...buttons,
          buttons.length ? h("div", { class: "or" }, h("span", {}, "or")) : null,
          emailButton),
        h("p", { class: "muted small center" },
          "Already have an email account? ",
          button("Sign in with email", () => showEmail("sign_in"), "link")),
        providers.dev ? field("Test account", devUser, "Development stack: alice, bob or carol") : null,
        h("ul", { class: "promise" },
          h("li", {}, icon("ok"), "Your keys are made on this device and stay in its keychain."),
          h("li", {}, icon("ok"), "Files are encrypted and opened only in this app, never in a browser."),
          h("li", {}, icon("ok"), "Send by email address: the app finds the right keys for you.")),
        h("p", { class: "muted small" },
          "New computer? ",
          button("Restore a Google account from a backup", () => {
            if (restoreShown || !list.length) return;
            restoreShown = true;
            restoreSlot.appendChild(restoreCard(list[0]));
          }, "link")),
      ),
      restoreSlot,
      emailSlot,
    );
    if (providers.dev) devUser.focus();
    else (buttons[0] ?? emailButton).focus();
  }

  void load();
}

/** After sign-up: suggest saving the one encrypted backup. */
export function backupOffer(ctx: Ctx, a: AccountInfo): HTMLElement {
  const pw = h("input", { type: "password", autocomplete: "new-password" });
  const pw2 = h("input", { type: "password", autocomplete: "new-password" });
  const res = h("div", {});
  const save = button("Save backup…", () => void (async () => {
    clear(res);
    if (pw.value.length < 10) {
      res.appendChild(note("Use at least 10 characters. A few random words work well.", "warn"));
      return;
    }
    if (pw.value !== pw2.value) {
      res.appendChild(note("The two passwords don't match.", "warn"));
      return;
    }
    await busy(save, "Encrypting…", async () => {
      try {
        const p = await api.saveBackup(pw.value);
        if (p) {
          pw.value = "";
          pw2.value = "";
          res.appendChild(note(`Backup saved. Keep it somewhere safe, away from this computer.`, "ok"));
          done.textContent = "Continue";
        }
      } catch (e) {
        res.appendChild(errorPanel(asAppError(e)));
      }
    });
  })(), "primary");
  const done = button("Later", () => {
    ctx.go("send");
    void ctx.pickUpPending();
  });
  return h("div", { class: "stack" },
    h("div", { class: "panel panel-ok", role: "status" },
      h("div", { class: "panel-head" }, icon("ok"), h("h3", {}, `Signed in as ${a.email}`)),
      h("p", {}, "This device's keys are ready. People can now send you files by your email address.")),
    card("Save a backup of your keys",
      h("p", {}, "Your private keys never leave this device, so if you lose it, files sent to you can't be opened. One backup file, locked with a recovery password, lets you restore them on a new computer."),
      h("div", { class: "grid2" }, field("Recovery password", pw), field("Repeat password", pw2)),
      h("p", { class: "muted small" }, "There's no way to recover this password. Nobody else, including SVX, can open the backup without it."),
      h("div", { class: "actions" }, save, done),
      res),
  );
}
