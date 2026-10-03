// Admin: sign in, revoke, audit trail, policies (read-only).

import { type WhoAmI, api, asAppError } from "../api";
import { card, errorPanel, facts, note } from "../components";
import { append, busy, button, clear, field, fmtTime, h, icon } from "../dom";
import type { Ctx } from "../main";

export function adminScreen(ctx: Ctx, root: HTMLElement): void {
  const account = h("div", {});
  const revokeBox = h("div", {});
  const auditBox = h("div", {});
  const policyBox = h("div", {});

  async function showAccount() {
    clear(account);
    let me: WhoAmI | null = null;
    try {
      me = await api.whoami();
    } catch (e) {
      account.appendChild(errorPanel(asAppError(e)));
      return;
    }
    if (me) {
      account.append(
        facts([
          ["Signed in as", me.email ? `${me.sub} (${me.email})` : me.sub],
          ["Organization", me.org_id],
          ["Groups", me.groups.join(", ") || "None"],
          ["Session ends", fmtTime(me.expires_at)],
        ]),
        h("div", { class: "actions" }, button("Sign out", async () => {
          await api.logout().catch(() => false);
          void showAccount();
        })),
      );
    } else {
      const devUser = h("input", { type: "text", placeholder: "example-admin", spellcheck: "false" });
      const signIn = button("Sign in", async () => {
        await busy(signIn, "Signing in…", async () => {
          try {
            await api.login(ctx.state.dev ? devUser.value.trim() || null : null);
            void showAccount();
          } catch (e) {
            account.appendChild(errorPanel(asAppError(e)));
          }
        });
      }, "primary");
      append(
        account,
        h("p", { class: "muted" }, "Administrators sign in to revoke files, read the audit trail and see policies. The session is short-lived and can't be used to open files."),
        ctx.state.dev ? field("Test user", devUser, "Dev stack admins: example-admin, acme-admin; senders: carol") : null,
        h("div", { class: "actions" }, signIn),
      );
    }
  }

  // Revoke
  const target = h("input", { type: "text", placeholder: "Artifact ID (32 hex characters)", class: "mono", spellcheck: "false" });
  const revokeOut = h("div", {});
  const confirmRevoke = () => {
    clear(revokeOut);
    const t = target.value.trim();
    if (!t) {
      revokeOut.appendChild(note("Enter an artifact ID or choose a .svx file.", "warn"));
      return;
    }
    const yes = button("Revoke", async () => {
      await busy(yes, "Revoking…", async () => {
        try {
          const id = await api.revoke(t);
          clear(revokeOut);
          revokeOut.appendChild(note(`Revoked ${id}. Nobody can open it from now on.`, "ok"));
        } catch (e) {
          clear(revokeOut);
          revokeOut.appendChild(errorPanel(asAppError(e)));
        }
      });
    }, "danger");
    revokeOut.appendChild(
      h("div", { class: "panel panel-warn" },
        h("div", { class: "panel-head" }, icon("warn"), h("h3", {}, "Revoke this file?")),
        h("p", {}, "No one will be able to open it from now on. This can't recall copies that were already opened."),
        h("div", { class: "actions" }, yes, button("Cancel", () => clear(revokeOut)))),
    );
  };
  revokeBox.append(
    h("div", { class: "row" },
      field("File to revoke", target),
      button("Choose .svx…", async () => {
        const p = await api.pick("artifact").catch(() => null);
        if (p) target.value = p;
      })),
    h("div", { class: "actions" }, button("Revoke…", confirmRevoke, "danger")),
    revokeOut,
  );

  // Audit
  const loadAudit = button("Load audit trail", async () => {
    await busy(loadAudit, "Loading…", async () => {
      clear(auditBox);
      auditBox.appendChild(loadAudit);
      try {
        const page = await api.audit(200);
        const rows = [...page.entries].sort((a, b) => b.seq - a.seq);
        auditBox.append(
          note(page.chain_valid ? "Tamper-evident hash chain verified." : "Hash chain did NOT verify. Contact SVX support.", page.chain_valid ? "ok" : "stop"),
          h("div", { class: "table-wrap" },
            h("table", { class: "table" },
              h("thead", {}, h("tr", {}, ...["#", "When", "Event", "Who", "File", "Reason"].map((c) => h("th", {}, c)))),
              h("tbody", {}, ...rows.map((e) =>
                h("tr", {},
                  h("td", {}, e.seq),
                  h("td", {}, fmtTime(e.at)),
                  h("td", {}, e.event.replace(/_/g, " ")),
                  h("td", { class: "mono small" }, e.subject ?? "–"),
                  h("td", { class: "mono small" }, e.artifact_id ? e.artifact_id.slice(0, 12) + "…" : "–"),
                  h("td", {}, e.reason ?? ""))))),
          ),
        );
      } catch (e) {
        auditBox.appendChild(errorPanel(asAppError(e)));
      }
    });
  });
  auditBox.appendChild(loadAudit);

  // Policies
  const loadPolicies = button("Show policies", async () => {
    await busy(loadPolicies, "Loading…", async () => {
      clear(policyBox);
      policyBox.appendChild(loadPolicies);
      try {
        const ps = await api.policies();
        const names = Object.keys(ps).sort();
        if (!names.length) policyBox.appendChild(note("No policies yet.", "info"));
        for (const n of names) {
          const p = ps[n];
          policyBox.appendChild(
            h("div", { class: "policy" }, h("h3", { class: "mono" }, n),
              facts([
                ["Allowed groups", p.allow_groups.join(", ") || "–"],
                ["Allowed users", p.allow_users.join(", ") || "–"],
                ["Required sign-in strength", p.require_acr.join(", ") || "Any"],
                ["Maximum age", p.max_age_secs ? `${Math.round(p.max_age_secs / 86400)} days` : "–"],
              ])),
          );
        }
        policyBox.appendChild(h("p", { class: "muted small" }, "Editing policies will come with the web admin portal."));
      } catch (e) {
        policyBox.appendChild(errorPanel(asAppError(e)));
      }
    });
  });
  policyBox.appendChild(loadPolicies);

  root.append(
    h("header", { class: "screen-head" }, h("h1", {}, "Administration"),
      h("p", { class: "lede" }, `For ${ctx.state.org_id ?? "your organization"}'s SVX administrators.`)),
    card("Account", account),
    card("Revoke a file", revokeBox),
    card("Audit trail", auditBox),
    card("Policies", policyBox),
  );
  void showAccount();
}
