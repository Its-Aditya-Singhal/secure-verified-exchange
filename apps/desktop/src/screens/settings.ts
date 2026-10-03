// Settings: current setup, output folder, change setup.

import { type AccountInfo, api, asAppError } from "../api";
import { card, errorPanel, facts, note } from "../components";
import { busy, button, clear, field, fmtTime, h } from "../dom";
import type { Ctx } from "../main";

export function settingsScreen(ctx: Ctx, root: HTMLElement): void {
  if (ctx.state.personal) {
    personalSettings(ctx, root);
    return;
  }
  const s = ctx.state;
  const out = h("div", {});
  const keyOut = h("div", {});

  async function changeOutput() {
    clear(out);
    try {
      if (await api.setOutputDir()) {
        await ctx.refreshState();
        ctx.go("settings");
      }
    } catch (e) {
      out.appendChild(errorPanel(asAppError(e)));
    }
  }

  async function changeSetup() {
    try {
      ctx.go("setup", { replace: true, form: await api.readConfigFile(s.config_path) });
    } catch {
      ctx.go("setup", { replace: true });
    }
  }

  root.append(
    h("header", { class: "screen-head" }, h("h1", {}, "Settings")),
    card(
      "Setup",
      facts([
        ["Organization", s.org_id ?? "–"],
        ["SVX service", s.service_url ?? "–"],
        ["Company sign-in", s.idp_issuer ?? "–"],
        ["Configuration file", h("span", { class: "mono small" }, s.config_path)],
      ]),
      s.dev ? note("Development mode is on: http and test users are allowed. Never use this with real data.", "warn") : null,
      h("div", { class: "actions" }, button("Change setup…", () => void changeSetup())),
    ),
    card(
      "Opened files",
      facts([["Saved to", h("span", { class: "mono small" }, s.output_dir ?? "–")]]),
      h("p", { class: "muted" }, "Opened files are private to your user account and never replace an existing file."),
      h("div", { class: "actions" }, button("Change folder…", () => void changeOutput())),
      out,
    ),
    card(
      "Signing key",
      facts([["Used for sending", h("span", { class: "mono small" }, s.prefs.signing_key ?? "None yet")]]),
      h("p", { class: "muted" }, "Keys kept in this computer's keychain can't be copied off it as a file. You can move an existing .sign.key file into the keychain; delete the file afterwards."),
      h("div", { class: "actions" }, button("Move a key file into the keychain…", async () => {
        clear(keyOut);
        try {
          const k = await api.importSigningKey();
          if (k) {
            await ctx.refreshState();
            ctx.go("settings");
          }
        } catch (e) {
          keyOut.appendChild(errorPanel(asAppError(e)));
        }
      })),
      keyOut,
    ),
    card(
      "About",
      h("p", {}, "Secure Verified Exchange 0.1.0. All checks, sign-in binding and decryption run in the SVX client library on this device; this window only shows the results."),
      h("p", { class: "muted small" }, "The svx command-line tool uses the same setup and sign-in session."),
    ),
  );
}

function personalSettings(ctx: Ctx, root: HTMLElement): void {
  const s = ctx.state;
  const accountBody = h("div", { class: "stack" }, note("Checking your account with the service…", "info"));
  const keysBody = h("div", { class: "stack" });
  const folderOut = h("div", {});

  const copy = (text: string, btn: HTMLButtonElement) => {
    void navigator.clipboard.writeText(text).then(() => {
      btn.textContent = "Copied";
      window.setTimeout(() => (btn.textContent = "Copy public key"), 1500);
    });
  };

  const showAccount = (a: AccountInfo) => {
    accountBody.replaceChildren(facts([
      ["Email", a.email],
      ["Signed in with", a.provider],
      ["Account ID", h("span", { class: "mono small" }, a.account)],
      ["Since", fmtTime(a.created_at)],
    ]));
    const copyBtn = button("Copy public key", () => copy(a.kem_public, copyBtn));
    keysBody.replaceChildren(
      facts([
        ["Signing key", h("span", { class: "mono small" }, a.signing_key_id)],
        ["Encryption key", h("span", { class: "mono small" }, a.kem_key_id)],
      ]),
      h("p", { class: "muted" }, "Both private keys are in this computer's keychain and are never shown, even to you. People don't need your public key: they find it from your email address in the signed directory."),
      h("div", { class: "actions" }, copyBtn),
    );
  };
  api.account().then(showAccount, (e) => accountBody.replaceChildren(errorPanel(asAppError(e))));

  // Backup
  const pw = h("input", { type: "password", autocomplete: "new-password" });
  const pw2 = h("input", { type: "password", autocomplete: "new-password" });
  const backupOut = h("div", {});
  const save = button("Save backup…", () => void (async () => {
    clear(backupOut);
    if (pw.value.length < 10) {
      backupOut.appendChild(note("Use at least 10 characters. A few random words work well.", "warn"));
      return;
    }
    if (pw.value !== pw2.value) {
      backupOut.appendChild(note("The two passwords don't match.", "warn"));
      return;
    }
    await busy(save, "Encrypting…", async () => {
      try {
        const p = await api.saveBackup(pw.value);
        if (p) {
          pw.value = "";
          pw2.value = "";
          backupOut.appendChild(note("Backup saved. Keep it somewhere safe, away from this computer.", "ok"));
        }
      } catch (e) {
        backupOut.appendChild(errorPanel(asAppError(e)));
      }
    });
  })(), "primary");

  // Reset keys
  const resetConfirm = h("input", { type: "checkbox" });
  const devUser = h("input", { type: "text", placeholder: "alice", autocomplete: "off", spellcheck: "false" });
  const resetOut = h("div", {});
  const reset = button("Reset my keys…", () => void (async () => {
    clear(resetOut);
    if (!resetConfirm.checked) {
      resetOut.appendChild(note("Tick the box to confirm first.", "warn"));
      return;
    }
    await busy(reset, s.dev ? "Resetting…" : "Finish signing in in your browser…", async () => {
      try {
        const a = await api.signUp(s.idp_issuer, true, s.dev ? devUser.value.trim() || null : null, true);
        await ctx.refreshState();
        showAccount(a);
        resetOut.appendChild(note("New keys are ready. Save a new backup: the old one no longer matches.", "ok"));
      } catch (e) {
        resetOut.appendChild(errorPanel(asAppError(e)));
      }
    });
  })(), "danger");

  // Sign out
  const outConfirm = h("input", { type: "checkbox" });
  const signOutOut = h("div", {});
  const signOut = button("Sign out of this computer", () => void (async () => {
    clear(signOutOut);
    if (!outConfirm.checked) {
      signOutOut.appendChild(note("Tick the box to confirm first.", "warn"));
      return;
    }
    try {
      await api.signOut();
      await ctx.refreshState();
      ctx.go("welcome");
    } catch (e) {
      signOutOut.appendChild(errorPanel(asAppError(e)));
    }
  })(), "danger");

  root.append(
    h("header", { class: "screen-head" }, h("h1", {}, "Settings")),
    card("Account", accountBody,
      s.dev ? note("Development service: test accounts only. Never use this with real data.", "warn") : null),
    card("Your keys", keysBody),
    card("Backup",
      h("p", {}, "One backup file, locked with a recovery password, restores your keys on a new computer. Without it, a lost computer means files sent to you can't be opened."),
      h("div", { class: "grid2" }, field("Recovery password", pw), field("Repeat password", pw2)),
      h("p", { class: "muted small" }, "There's no way to recover this password."),
      h("div", { class: "actions" }, save),
      backupOut),
    card("Opened files",
      facts([["Saved to", h("span", { class: "mono small" }, s.output_dir ?? "–")]]),
      h("p", { class: "muted" }, "Opened files are private to your user account and never replace an existing file."),
      h("div", { class: "actions" }, button("Change folder…", () => void (async () => {
        clear(folderOut);
        try {
          if (await api.setOutputDir()) {
            await ctx.refreshState();
            ctx.go("settings");
          }
        } catch (e) {
          folderOut.appendChild(errorPanel(asAppError(e)));
        }
      })())),
      folderOut),
    card("Lost a computer?",
      h("p", {}, "Resetting gives your account new keys and signs out your other computers. Files sent to your old keys can no longer be opened."),
      s.dev ? field("Test account", devUser) : null,
      h("label", { class: "check" }, resetConfirm, h("span", {}, "I understand that files sent to my old keys will no longer open")),
      h("div", { class: "actions" }, reset),
      resetOut),
    card("Sign out",
      h("p", {}, "Removes your keys and settings from this computer. You can sign in again later with your backup."),
      h("label", { class: "check" }, outConfirm, h("span", {}, "I have a backup, or I accept I can't open files sent to me before")),
      h("div", { class: "actions" }, signOut),
      signOutOut),
    card("About",
      h("p", {}, "Secure Verified Exchange 0.1.0. All checks, key handling and decryption run in the SVX client library on this device; this window only shows the results.")),
  );
}
