// "What's your name?": Google accounts are created without a name (SVX asks
// Google only for the email address). The app asks for it once, before
// anything else; the service keeps it and shows it next to the email address.

import { api, asAppError } from "../api";
import { brandLockup } from "../brand";
import { card, errorPanel, note } from "../components";
import { busy, button, field, h } from "../dom";

export function nameScreen(main: HTMLElement, email: string, done: () => void): void {
  const input = (autocomplete: string) =>
    h("input", { type: "text", autocomplete, spellcheck: "false", maxlength: "64" }) as HTMLInputElement;
  const first = input("given-name");
  const last = input("family-name");
  const out = h("div", {});
  const save = button("Continue", () => void busy(save, "Saving…", async () => {
    out.replaceChildren();
    if (!first.value.trim() || !last.value.trim()) {
      out.appendChild(note("Enter your first and last name.", "warn"));
      return;
    }
    try {
      await api.setAccountName(first.value, last.value);
      done();
    } catch (e) {
      out.appendChild(errorPanel(asAppError(e)));
    }
  }), "primary");
  for (const i of [first, last]) {
    i.addEventListener("keydown", (e) => {
      if (e.key === "Enter") save.click();
    });
  }
  main.append(
    h("div", { class: "brand center-brand" }, brandLockup()),
    card("What's your name?",
      h("p", {}, "People you send files to see it next to your email address, ",
        h("strong", {}, email), ", so they know the file is from you."),
      h("div", { class: "grid2" }, field("First name", first), field("Last name", last)),
      h("p", { class: "muted small" }, "Use your real name. It can't be changed later."),
      h("div", { class: "actions" }, save),
      out),
  );
  first.focus();
}
