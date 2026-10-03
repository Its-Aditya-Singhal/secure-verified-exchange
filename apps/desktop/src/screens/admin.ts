// Administration: account, organization overview and settings, keys,
// policies, administrators, audit trail and revocation. Every action is a
// Rust command authorized by the SVX service (the organization's own
// administrators only); key rules live in svx_client::keyadmin.

import {
  type AdminOverview,
  type AuditEntry,
  type KeyDetail,
  type Policy,
  type WhoAmI,
  api,
  asAppError,
} from "../api";
import { card, errorPanel, facts, note } from "../components";
import { append, busy, button, clear, field, fmtTime, h, icon, revealLabel } from "../dom";
import type { Ctx } from "../main";

type Tab = "overview" | "keys" | "policies" | "admins" | "audit" | "revoke";
const TABS: [Tab, string][] = [
  ["overview", "Organization"],
  ["keys", "Keys"],
  ["policies", "Policies"],
  ["admins", "Administrators"],
  ["audit", "Audit trail"],
  ["revoke", "Revoke a file"],
];

let lastTab: Tab = "overview";

function confirmPanel(title: string, body: string, action: string, run: () => Promise<void>, out: HTMLElement) {
  clear(out);
  const yes = button(action, async () => {
    await busy(yes, "Working…", async () => {
      try {
        await run();
      } catch (e) {
        clear(out);
        out.appendChild(errorPanel(asAppError(e)));
      }
    });
  }, "danger");
  out.appendChild(
    h("div", { class: "panel panel-warn" },
      h("div", { class: "panel-head" }, icon("warn"), h("h3", {}, title)),
      h("p", {}, body),
      h("div", { class: "actions" }, yes, button("Cancel", () => clear(out)))),
  );
}

const KIND_LABEL: Record<string, string> = {
  "ed25519-mldsa65": "Signing (post-quantum)",
  xwing: "Encryption (post-quantum)",
  ed25519: "Signing (classical, older files)",
  x25519: "Encryption (classical, older files)",
};

export function adminScreen(ctx: Ctx, root: HTMLElement): void {
  const account = h("div", {});
  const tabBar = h("div", { class: "tabs", role: "tablist" });
  const panel = h("div", { class: "stack" });
  let me: WhoAmI | null = null;

  async function showAccount() {
    clear(account);
    try {
      me = await api.whoami();
    } catch (e) {
      account.appendChild(errorPanel(asAppError(e)));
      return;
    }
    if (me) {
      account.append(
        h("div", { class: "row spread" },
          h("span", {}, icon("ok"), ` Signed in as ${me.email ?? me.sub} · session ends ${fmtTime(me.expires_at)}`),
          button("Sign out", async () => {
            await api.logout().catch(() => false);
            await showAccount();
            showTab(lastTab);
          }, "link")),
      );
    } else {
      const devUser = h("input", { type: "text", placeholder: "example-admin", spellcheck: "false" });
      const signIn = button("Sign in", async () => {
        await busy(signIn, "Signing in…", async () => {
          try {
            await api.login(ctx.state.dev ? devUser.value.trim() || null : null);
            await showAccount();
            showTab(lastTab);
          } catch (e) {
            account.appendChild(errorPanel(asAppError(e)));
          }
        });
      }, "primary");
      append(
        account,
        h("p", { class: "muted" }, "Administrators sign in with their company login. The session is short-lived and can't be used to open files."),
        ctx.state.dev ? field("Test user", devUser, "Dev stack admins: example-admin, acme-admin") : null,
        h("div", { class: "actions" }, signIn),
      );
    }
  }

  function showTab(t: Tab) {
    lastTab = t;
    clear(tabBar);
    for (const [id, label] of TABS) {
      tabBar.appendChild(h("button", {
        type: "button", role: "tab", class: `tab${id === t ? " is-current" : ""}`,
        "aria-selected": id === t ? "true" : "false",
        onclick: () => showTab(id),
      }, label));
    }
    clear(panel);
    if (!me) {
      panel.appendChild(note("Sign in as an administrator to manage your organization.", "info"));
      return;
    }
    const render = { overview, keys, policies, admins, audit, revoke }[t];
    void render(panel);
  }

  async function loadOverview(target: HTMLElement): Promise<AdminOverview | null> {
    target.appendChild(h("p", { class: "muted" }, "Loading…"));
    try {
      const o = await api.adminOverview();
      clear(target);
      return o;
    } catch (e) {
      clear(target);
      target.appendChild(errorPanel(asAppError(e)));
      return null;
    }
  }

  // ----- Organization -----
  async function overview(target: HTMLElement) {
    const o = await loadOverview(target);
    if (!o) return;
    const org = o.org;
    const name = h("input", { type: "text", value: org.display_name });
    const agentUrl = h("input", { type: "url", value: org.key_agent_url ?? "", placeholder: "https://svx-agent.your-domain" });
    const out = h("div", {});
    const save = button("Save changes", async () => {
      clear(out);
      await busy(save, "Saving…", async () => {
        try {
          const n = name.value.trim();
          const u = agentUrl.value.trim();
          await api.updateOrg({
            display_name: n !== org.display_name ? n : null,
            key_agent_url: u && u !== org.key_agent_url ? u : null,
            remove_key_agent: !u && org.key_agent_url !== null,
          });
          showTab("overview");
        } catch (e) {
          out.appendChild(errorPanel(asAppError(e)));
        }
      });
    }, "primary");
    const a = o.agent;
    target.append(
      card("Organization",
        facts([
          ["ID", h("span", { class: "mono" }, org.org_id)],
          ["Domain", `${org.domain} (verified ${fmtTime(org.verified_at)})`],
          ["Company sign-in", org.idp_issuer],
          ["Client ID", org.idp_client_id],
        ]),
        h("div", { class: "grid2" },
          field("Display name", name),
          field("Key agent URL", agentUrl, "Where your key agent runs. Leave empty if your organization only sends."),
        ),
        h("div", { class: "actions" }, save),
        out,
      ),
      card("Key agent",
        !a
          ? note("No key agent: your organization can send files but not receive them.", "info")
          : a.reachable
            ? note(`Reachable at ${a.url}; it holds ${a.key_ids.length} key(s).`, "ok")
            : note(`Not reachable at ${a.url}: ${a.error ?? "no answer"}. Files sent to you can't be opened until it's back.`, "stop"),
      ),
    );
  }

  // ----- Keys -----
  async function keys(target: HTMLElement) {
    const o = await loadOverview(target);
    if (!o) return;
    const out = h("div", { class: "stack" });
    const onAgent = new Set(o.agent?.key_ids ?? []);
    const row = (k: KeyDetail) => {
      const actions = h("div", { class: "row" });
      if (k.status === "active") {
        actions.appendChild(button("Retire", () =>
          confirmPanel("Retire this key?", "It stops being used for new files but still works for existing ones.", "Retire",
            async () => { await api.setKeyStatus(k.key_id, "retired"); showTab("keys"); }, out), "link"));
      }
      if (k.status !== "revoked") {
        actions.appendChild(button("Revoke", () =>
          confirmPanel("Revoke this key?", "Use this if the key may be compromised. Files that depend on it are refused from now on. This can't be undone.", "Revoke",
            async () => { await api.setKeyStatus(k.key_id, "revoked"); showTab("keys"); }, out), "link"));
      }
      const tags = [
        k.key_id === o.this_computer_key ? h("span", { class: "badge badge-ok" }, "this computer") : null,
        !k.kind.startsWith("ed25519") && k.status !== "revoked"
          ? onAgent.has(k.key_id)
            ? h("span", { class: "badge badge-ok" }, "on key agent")
            : h("span", { class: "badge badge-warn" }, "not on key agent")
          : null,
      ];
      return h("tr", {},
        h("td", {}, KIND_LABEL[k.kind] ?? k.kind),
        h("td", { class: "mono small" }, k.key_id.slice(0, 16) + "…"),
        h("td", {}, h("span", { class: `status status-${k.status}` }, k.status), " ", ...tags),
        h("td", {}, fmtTime(k.created_at)),
        h("td", {}, actions));
    };
    const table = h("div", { class: "table-wrap" },
      h("table", { class: "table" },
        h("thead", {}, h("tr", {}, ...["Kind", "Key ID", "Status", "Added", ""].map((c) => h("th", {}, c)))),
        h("tbody", {}, ...o.org.keys.map(row))));

    // This computer's signing key.
    const signOut = h("div", {});
    const create = button("Create a new signing key", async () => {
      clear(signOut);
      await busy(create, "Creating…", async () => {
        try {
          const k = await api.createSigningKey();
          await ctx.refreshState();
          signOut.appendChild(note(`Created ${k.key_id.slice(0, 12)}… in this computer's keychain and registered it.`, "ok"));
          showTab("keys");
        } catch (e) {
          signOut.appendChild(errorPanel(asAppError(e)));
        }
      });
    }, "primary");
    const register = button("Register another sender's key…", async () => {
      clear(signOut);
      try {
        const k = await api.registerSigningPublic();
        if (k) showTab("keys");
      } catch (e) {
        signOut.appendChild(errorPanel(asAppError(e)));
      }
    });

    // Encryption key rotation.
    const encOut = h("div", { class: "stack" });
    const pendingKey = o.pending_encryption_key;
    const encryption = pendingKey
      ? h("div", { class: "stack" },
          h("p", {}, `New key ${pendingKey.key_id.slice(0, 12)}… was written to:`),
          h("p", { class: "mono small" }, pendingKey.secret_file),
          h("ol", { class: "steps-list" },
            h("li", {}, "Copy this file to the key agent server (owner-only, e.g. chmod 600) and add it to the agent's kem_keys."),
            h("li", {}, "Restart the key agent."),
            h("li", {}, "Activate it here. The app checks that the agent has it first."),
            h("li", {}, "Delete the copy on this computer.")),
          h("div", { class: "actions" },
            (() => {
              const act = button("Activate", async () => {
                clear(encOut);
                await busy(act, "Checking the key agent…", async () => {
                  try {
                    await api.activateEncryptionKey();
                    await ctx.refreshState();
                    showTab("keys");
                  } catch (e) {
                    encOut.appendChild(errorPanel(asAppError(e)));
                  }
                });
              }, "primary");
              return act;
            })(),
            button(revealLabel(), () => void api.reveal(pendingKey.secret_file).catch(() => undefined)),
            button("Discard", async () => {
              await api.discardPendingEncryptionKey().catch(() => undefined);
              await ctx.refreshState();
              showTab("keys");
            }, "link")),
          encOut)
      : h("div", { class: "stack" },
          h("p", {}, "Rotate the encryption key your key agent uses to receive files. Older keys stay on the agent for files already sent."),
          h("div", { class: "actions" }, button("Create a new encryption key…", async () => {
            clear(encOut);
            try {
              const k = await api.exportEncryptionKey();
              if (k) {
                await ctx.refreshState();
                showTab("keys");
              }
            } catch (e) {
              encOut.appendChild(errorPanel(asAppError(e)));
            }
          })),
          encOut);

    target.append(
      card("Registered keys", table, out),
      card("Signing keys (sending)",
        o.this_computer_key
          ? note(`This computer signs with ${o.this_computer_key.slice(0, 12)}… from its keychain.`, "ok")
          : o.signing_key_problem
            ? note(`This computer's signing key can't be used: ${o.signing_key_problem}`, "warn")
            : note("This computer has no signing key yet.", "info"),
        h("p", { class: "muted" }, "Each sender's computer has its own key. Senders who don't administer SVX create a key file with the svx tool and send you the .sign.pub file to register."),
        h("div", { class: "actions" }, create, register),
        signOut),
      card("Encryption key (receiving)", encryption),
    );
  }

  // ----- Policies -----
  async function policies(target: HTMLElement) {
    target.appendChild(h("p", { class: "muted" }, "Loading…"));
    let ps: Record<string, Policy>;
    try {
      ps = await api.policies();
    } catch (e) {
      clear(target);
      target.appendChild(errorPanel(asAppError(e)));
      return;
    }
    clear(target);
    const list = h("div", { class: "stack" });
    const editor = h("div", {});
    const names = Object.keys(ps).sort();
    if (!names.length) list.appendChild(note("No policies yet. Senders name a policy when they send you a file; without it, nobody can open the file.", "info"));
    for (const n of names) {
      const p = ps[n];
      list.appendChild(
        h("div", { class: "policy" },
          h("div", { class: "row spread" }, h("h3", { class: "mono" }, n),
            h("div", { class: "row" },
              button("Edit", () => edit(n, p), "link"),
              button("Delete", () => confirmPanel(`Delete policy ${n}?`,
                "Files sent under this policy can't be opened by anyone until it exists again.", "Delete",
                async () => { await api.deletePolicy(n); showTab("policies"); }, editor), "link"))),
          facts([
            ["Allowed groups", p.allow_groups.join(", ") || "–"],
            ["Allowed users", p.allow_users.join(", ") || "–"],
            ["Required sign-in strength", p.require_acr.join(", ") || "Any"],
            ["Maximum age", p.max_age_secs ? `${Math.round(p.max_age_secs / 86400)} days` : "–"],
            ["Access window", p.not_before || p.not_after ? `${fmtTime(p.not_before)} – ${fmtTime(p.not_after)}` : "Always"],
          ])),
      );
    }

    function edit(name: string | null, p: Policy | null) {
      clear(editor);
      const list = (v: string[] | undefined) => (v ?? []).join(", ");
      const nameIn = h("input", { type: "text", value: name ?? "", placeholder: "e.g. incident-response", spellcheck: "false", disabled: name !== null });
      const groups = h("input", { type: "text", value: list(p?.allow_groups), placeholder: "e.g. incident-response, legal" });
      const users = h("input", { type: "text", value: list(p?.allow_users), placeholder: "user IDs, comma-separated" });
      const acr = h("input", { type: "text", value: list(p?.require_acr), placeholder: "e.g. phr (phishing-resistant MFA)" });
      const maxAge = h("input", { type: "number", min: "1", value: p?.max_age_secs ? String(Math.round(p.max_age_secs / 86400)) : "", placeholder: "days" });
      const out = h("div", {});
      const split = (s: string) => s.split(",").map((x) => x.trim()).filter(Boolean);
      const save = button("Save policy", async () => {
        clear(out);
        const n = nameIn.value.trim();
        if (!n) {
          out.appendChild(note("Give the policy a name.", "warn"));
          return;
        }
        const days = Number(maxAge.value);
        const policy: Policy = {
          allow_groups: split(groups.value),
          allow_users: split(users.value),
          require_acr: split(acr.value),
          max_age_secs: maxAge.value && days > 0 ? Math.round(days * 86400) : null,
          not_before: p?.not_before ?? null,
          not_after: p?.not_after ?? null,
        };
        await busy(save, "Saving…", async () => {
          try {
            await api.setPolicy(n, policy);
            showTab("policies");
          } catch (e) {
            out.appendChild(errorPanel(asAppError(e)));
          }
        });
      }, "primary");
      editor.appendChild(card(name ? `Edit ${name}` : "New policy",
        h("p", { class: "muted" }, "Someone may open a file if they're in an allowed group or listed as a user, and every other condition holds."),
        h("div", { class: "grid2" },
          field("Name", nameIn),
          field("Maximum file age (days)", maxAge, "Optional. Can only shorten the sender's expiry."),
          field("Allowed groups", groups, "From your company sign-in's groups claim."),
          field("Allowed users", users),
          field("Required sign-in strength", acr, "Optional acr values, e.g. multi-factor."),
        ),
        h("div", { class: "actions" }, save, button("Cancel", () => clear(editor), "link")),
        out));
      editor.scrollIntoView({ behavior: "smooth", block: "start" });
      nameIn.focus({ preventScroll: true });
    }

    target.append(
      card("Policies", list, h("div", { class: "actions" }, button("New policy…", () => edit(null, null), "primary"))),
      editor,
    );
  }

  // ----- Administrators -----
  async function admins(target: HTMLElement) {
    const o = await loadOverview(target);
    if (!o) return;
    const out = h("div", {});
    const subject = h("input", { type: "text", placeholder: "their user ID at your company sign-in", spellcheck: "false" });
    const add = button("Add administrator", async () => {
      clear(out);
      await busy(add, "Adding…", async () => {
        try {
          await api.addAdmin(subject.value.trim());
          showTab("admins");
        } catch (e) {
          out.appendChild(errorPanel(asAppError(e)));
        }
      });
    }, "primary");
    target.append(card("Administrators",
      h("div", { class: "table-wrap" }, h("table", { class: "table" },
        h("thead", {}, h("tr", {}, h("th", {}, "User ID"), h("th", {}, "Added"), h("th", {}, ""))),
        h("tbody", {}, ...o.org.admins.map((a) => h("tr", {},
          h("td", { class: "mono" }, a.subject, a.subject === me?.sub ? " (you)" : ""),
          h("td", {}, fmtTime(a.added_at)),
          h("td", {}, o.org.admins.length > 1
            ? button("Remove", () => confirmPanel(`Remove ${a.subject}?`,
                "They can no longer manage your organization in SVX.", "Remove",
                async () => { await api.removeAdmin(a.subject); showTab("admins"); }, out), "link")
            : h("span", { class: "muted small" }, "last administrator"))))))),
      h("div", { class: "row" }, field("Add an administrator", subject), add),
      h("p", { class: "muted small" }, "Use the user ID (sub) your company sign-in gives them; they can see it on their own Admin page after signing in."),
      out));
  }

  // ----- Audit -----
  async function audit(target: HTMLElement) {
    const filter = h("select", {},
      h("option", { value: "" }, "All events"),
      ...["decryption_authorized", "authorization_failure", "authentication_failure", "artifact_revoked",
        "revoked_artifact_access", "key_changed", "policy_changed", "admin_added", "admin_removed",
        "org_changed", "signature_failure", "replay_detected", "suspicious_repeated_attempts"]
        .map((e) => h("option", { value: e }, e.replace(/_/g, " "))));
    const tbody = h("tbody", {});
    const status = h("div", {});
    const more = button("Load older", () => void load(false));
    let before: number | null = null;
    let valid = true;
    const ev = () => filter.value || null;

    async function load(reset: boolean) {
      if (reset) {
        before = null;
        valid = true;
        clear(tbody);
      }
      await busy(more, "Loading…", async () => {
        try {
          const page = await api.auditPage(200, before, ev());
          valid &&= page.chain_valid;
          clear(status);
          status.appendChild(valid
            ? note("Tamper-evident hash chain verified for the records shown.", "ok")
            : note("The hash chain did NOT verify. Contact SVX support.", "stop"));
          page.entries.forEach((e: AuditEntry) => tbody.appendChild(h("tr", {},
            h("td", {}, e.seq),
            h("td", {}, fmtTime(e.at)),
            h("td", {}, e.event.replace(/_/g, " ")),
            h("td", { class: "mono small" }, e.subject ?? "–"),
            h("td", { class: "mono small" }, e.artifact_id ? e.artifact_id.slice(0, 12) + "…" : "–"),
            h("td", {}, e.reason ?? ""))));
          const last = page.entries[page.entries.length - 1];
          before = last ? last.seq : before;
          more.hidden = page.entries.length < 200;
        } catch (e) {
          clear(status);
          status.appendChild(errorPanel(asAppError(e)));
        }
      });
    }
    filter.addEventListener("change", () => void load(true));
    const exportOut = h("div", {});
    const exp = button("Export CSV…", async () => {
      clear(exportOut);
      await busy(exp, "Exporting…", async () => {
        try {
          const r = await api.exportAudit(ev());
          if (r) {
            const [path, n] = r;
            exportOut.appendChild(h("div", { class: "row" },
              note(`Saved ${n} records.`, "ok"),
              button(revealLabel(), () => void api.reveal(path).catch(() => undefined), "link")));
          }
        } catch (e) {
          exportOut.appendChild(errorPanel(asAppError(e)));
        }
      });
    });
    target.append(card("Audit trail",
      h("div", { class: "row" }, field("Show", filter), exp),
      exportOut,
      status,
      h("div", { class: "table-wrap" }, h("table", { class: "table" },
        h("thead", {}, h("tr", {}, ...["#", "When", "Event", "Who", "File", "Details"].map((c) => h("th", {}, c)))),
        tbody)),
      h("div", { class: "actions" }, more)));
    await load(true);
  }

  // ----- Revoke -----
  async function revoke(target: HTMLElement) {
    const t = h("input", { type: "text", placeholder: "Artifact ID (32 hex characters)", class: "mono", spellcheck: "false" });
    const out = h("div", {});
    target.append(card("Revoke a file",
      h("p", { class: "muted" }, "Nobody can open a revoked file from then on. Revoking can't recall copies that were already opened."),
      h("div", { class: "row" },
        field("File to revoke", t),
        button("Choose .svx…", async () => {
          const p = await api.pick("artifact").catch(() => null);
          if (p) t.value = p;
        })),
      h("div", { class: "actions" }, button("Revoke…", () => {
        const v = t.value.trim();
        if (!v) {
          clear(out);
          out.appendChild(note("Enter an artifact ID or choose a .svx file.", "warn"));
          return;
        }
        confirmPanel("Revoke this file?", "No one will be able to open it from now on.", "Revoke", async () => {
          const id = await api.revoke(v);
          clear(out);
          out.appendChild(note(`Revoked ${id}.`, "ok"));
        }, out);
      }, "danger")),
      out));
  }

  root.append(
    h("header", { class: "screen-head" }, h("h1", {}, "Administration"),
      h("p", { class: "lede" }, `For ${ctx.state.org_id ?? "your organization"}'s SVX administrators. Everything here is checked by the SVX service.`)),
    card(null, account),
    tabBar,
    panel,
  );
  void showAccount().then(() => showTab(lastTab));
}
