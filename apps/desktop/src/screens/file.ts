// One sent file: who it went to and where each person stands, and the
// sender's controls (approval, one-time, expiry, revoke). The rules live on
// the service, so changes apply to the copies already sent.

import { type SentFile, type UpdateFileRequest, api, asAppError } from "../api";
import { card, errorPanel, facts, note } from "../components";
import { append, busy, button, clear, field, fmtTime, h } from "../dom";
import type { Ctx } from "../main";
import { STATE_LABEL, fileLabel, isExpired, stateChip, viewOnlyBadge } from "./history";

const DAY = 86_400;
const SOONER: [string, number][] = [
  ["Now", 0],
  ["In 1 hour", 3600],
  ["In 1 day", DAY],
  ["In 7 days", 7 * DAY],
];

export function fileScreen(ctx: Ctx, root: HTMLElement, artifactId: string): void {
  const body = h("div", { class: "stack" });
  const msg = h("div", {});
  root.append(
    h("div", {}, button("‹ History", () => ctx.go("history"), "link")),
    body,
    msg,
  );

  async function change(u: UpdateFileRequest, btn?: HTMLButtonElement) {
    clear(msg);
    const run = async () => {
      try {
        render(await api.updateFile(artifactId, u));
      } catch (e) {
        msg.appendChild(errorPanel(asAppError(e)));
      }
    };
    if (btn) await busy(btn, "Saving…", run);
    else await run();
  }

  function render(f: SentFile) {
    clear(body);
    const revoked = f.revoked_at !== null;
    const expired = isExpired(f);
    const ended = revoked || expired;
    const expiry = [f.signed_expires_at, f.rules.expires_at].filter((t): t is number => t !== null);
    const effective = expiry.length ? Math.min(...expiry) : null;

    const people = h("ul", { class: "list" }, ...f.recipients.map((r) => {
      const rev = button("Revoke", () => void change({ revoke_recipients: [r.account] }, rev), "secondary");
      return h("li", {},
        h("div", { class: "list-row is-static" },
          h("span", { class: "list-main" },
            h("span", { class: "list-title" }, r.email ?? r.account),
            h("span", { class: "muted small" },
              r.opened_at ? `Opened ${fmtTime(r.opened_at)}`
                : r.requested_at ? `Asked ${fmtTime(r.requested_at)}` : "Hasn't tried to open it")),
          stateChip(STATE_LABEL[r.state], r.state),
          !ended && r.state !== "revoked" ? rev : null));
    }));

    const approval = h("input", { type: "checkbox", checked: f.rules.require_approval, disabled: ended });
    approval.addEventListener("change", () => void change({ require_approval: approval.checked }));
    const oneTime = h("input", { type: "checkbox", checked: f.rules.one_time, disabled: ended });
    oneTime.addEventListener("change", () => void change({ one_time: oneTime.checked }));

    // View-only can be lifted at any time (with a confirmation, since it
    // can't be taken back for copies already saved), and switched back on
    // only for a file that was sent view-only: the service refuses it for
    // any other.
    const liftConfirm = h("input", { type: "checkbox" });
    const lift = button("Turn off view-only", () => {
      if (!liftConfirm.checked) {
        clear(msg);
        msg.appendChild(note("Tick the box to confirm first.", "warn"));
        return;
      }
      void change({ view_only: false }, lift);
    }, "danger");
    const relock = button("Turn view-only back on", () => void change({ view_only: true }, relock));
    const keepCopy = h("input", { type: "checkbox", checked: f.rules.allow_share_requests, disabled: ended || !f.rules.view_only });
    keepCopy.addEventListener("change", () => void change({ allow_share_requests: keepCopy.checked }));

    const sooner = h("select", {}, ...SOONER
      .filter(([, s]) => effective === null || Date.now() / 1000 + s < effective)
      .map(([label, s]) => h("option", { value: String(s) }, label)));
    const setExpiry = button("Set", () => void change({ expires_at: Math.floor(Date.now() / 1000) + Number(sooner.value) }, setExpiry));

    const confirm = h("input", { type: "checkbox" });
    const revokeAll = button("Revoke for everyone", () => {
      if (!confirm.checked) {
        clear(msg);
        msg.appendChild(note("Tick the box to confirm first.", "warn"));
        return;
      }
      void change({ revoke: true }, revokeAll);
    }, "danger");

    append(body,
      h("header", { class: "screen-head file-head" },
        h("div", { class: "file-icon", "aria-hidden": "true" }, "SVX"),
        h("div", {}, h("h1", {}, fileLabel(f.file_name, f.artifact_id), " ", viewOnlyBadge(f.rules.view_only)),
          h("p", { class: "muted" }, `Sent ${fmtTime(f.created_at)}`,
            revoked ? ` · revoked ${fmtTime(f.revoked_at)}` : expired ? " · expired" : ""))),
      card("People", people,
        h("div", { class: "actions" },
          button("Send a new copy…", () => ctx.go("send", { to: f.recipients.map((r) => r.email).filter(Boolean) }))),
        h("p", { class: "muted small" }, "People can't be added to a file after it's sent: their keys are sealed into it. Send a new copy instead.")),
      card("Controls",
        ended ? note(revoked ? "This file is revoked: nobody can open it any more." : "This file has expired: nobody can open it any more.", "info") : null,
        h("label", { class: "toggle" }, approval,
          h("span", {}, h("strong", {}, "Ask me before each open"),
            h("span", { class: "muted small" }, "Requests appear under Requests and by email."))),
        h("label", { class: "toggle" }, oneTime,
          h("span", {}, h("strong", {}, "One-time"),
            h("span", { class: "muted small" }, "Each person can open it once."))),
        f.signed_view_only
          ? h("div", { class: "stack-tight" },
              h("p", {}, h("strong", {}, "View only: "), f.rules.view_only ? "on" : "off",
                h("span", { class: "muted small" }, f.rules.view_only
                  ? " People view it in the app and can't save, copy or print it."
                  : " Everyone who opens it can save it.")),
              ended ? null
                : f.rules.view_only
                  ? h("div", {}, h("label", { class: "check" }, liftConfirm,
                      h("span", {}, "Let everyone who opens it save it. This can't be taken back for copies they save.")),
                    h("div", { class: "actions" }, lift))
                  : h("div", { class: "actions" }, relock))
          : null,
        f.signed_view_only
          ? h("label", { class: "toggle toggle-sub" }, keepCopy,
              h("span", {}, h("strong", {}, "Let them ask to keep a copy"),
                h("span", { class: "muted small" }, "Requests appear under Requests. Approving lets that person save the file, and that can't be taken back.")))
          : null,
        facts([["Stops opening", effective ? fmtTime(effective) : "Never"]]),
        !ended && sooner.options.length
          ? h("div", { class: "row" }, field("Stop opening sooner", sooner), setExpiry)
          : null),
      ended ? null : card("Revoke",
        h("p", {}, "Nobody can open this file again, including people who haven't opened it yet. Copies already decrypted stay on their computers."),
        h("label", { class: "check" }, confirm, h("span", {}, "Revoke this file for everyone")),
        h("div", { class: "actions" }, revokeAll)),
      h("p", { class: "muted small mono" }, `File ID ${f.artifact_id}`),
    );
  }

  body.appendChild(note("Loading…", "info"));
  api.file(artifactId).then(render, (e) => {
    clear(body);
    body.appendChild(errorPanel(asAppError(e)));
  });
}
