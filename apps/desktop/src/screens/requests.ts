// Requests: people asking to open files I sent with "Ask me before each
// open". Approving happens only here, never from an email link.

import { type RequestView, api, asAppError } from "../api";
import { card, errorPanel, note } from "../components";
import { busy, button, clear, fmtTime, h } from "../dom";
import type { Ctx } from "../main";
import { fileLabel } from "./history";

export function requestsScreen(ctx: Ctx, root: HTMLElement): void {
  const body = h("div", { class: "stack" });
  root.append(
    h("header", { class: "screen-head" }, h("h1", {}, "Requests"),
      h("p", { class: "lede" }, "People waiting for your approval to open a file you sent.")),
    body,
  );

  const load = async () => {
    clear(body);
    body.appendChild(note("Loading…", "info"));
    let list: RequestView[];
    try {
      list = await api.requests();
    } catch (e) {
      clear(body);
      body.appendChild(errorPanel(asAppError(e)));
      return;
    }
    clear(body);
    void ctx.refreshRequests();
    if (!list.length) {
      body.appendChild(note("No requests waiting. When someone opens a file that needs your approval, it shows up here and you get an email.", "info"));
      return;
    }
    for (const r of list) body.appendChild(request(r));
  };

  function request(r: RequestView): HTMLElement {
    const who = r.requester_email ?? r.requester;
    const out = h("div", {});
    const confirm = h("input", { type: "checkbox" });
    const approve = button("Approve", () => void (async () => {
      clear(out);
      if (!confirm.checked) {
        out.appendChild(note("Tick the box to confirm you checked it's them.", "warn"));
        return;
      }
      await busy(approve, "Approving…", async () => {
        try {
          await api.approve(r.request_id);
          await load();
        } catch (e) {
          out.appendChild(errorPanel(asAppError(e)));
        }
      });
    })(), "primary");
    const decline = button("Decline", () => void (async () => {
      clear(out);
      await busy(decline, "Declining…", async () => {
        try {
          await api.decline(r.request_id);
          await load();
        } catch (e) {
          out.appendChild(errorPanel(asAppError(e)));
        }
      });
    })());
    return card(null,
      h("p", { class: "request-line" },
        h("strong", {}, who), " wants to open ", h("strong", {}, fileLabel(r.file_name, r.artifact_id))),
      h("p", { class: "muted small" }, `Asked ${fmtTime(r.requested_at)} · the request lapses ${fmtTime(r.expires_at)}`),
      h("label", { class: "check" }, confirm,
        h("span", {}, `I checked with ${who} (by phone, in person or another channel) that it's really them.`)),
      h("div", { class: "actions" }, approve, decline,
        button("See the file", () => ctx.go("file", r.artifact_id), "link")),
      out);
  }

  void load();
}
