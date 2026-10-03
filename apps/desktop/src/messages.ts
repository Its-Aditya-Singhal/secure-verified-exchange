// Plain-language copy for each error kind (svx-client ErrorKind names).

import type { AppError } from "./api";

export interface Explained {
  tone: "stop" | "warn" | "info";
  title: string;
  body: string;
  /** Offer a retry (the condition may be temporary). */
  retry: boolean;
}

export function explain(e: AppError): Explained {
  switch (e.kind) {
    case "rejected":
      return {
        tone: "stop",
        title: "This file can't be trusted",
        body:
          "It has been changed since it was sent, is damaged, or doesn't come from a verified organization. " +
          "Nothing was decrypted and you weren't asked to sign in. Ask the sender to send it again.",
        retry: false,
      };
    case "not_recipient":
      return {
        tone: "stop",
        title: "This file wasn't sent to your organization",
        body: e.message.replace(/^this artifact is/i, "It's") + ". Only the organization it was sent to can open it.",
        retry: false,
      };
    case "expired":
      return {
        tone: "stop",
        title: "This file has expired",
        body: "The sender set an expiry date that has passed. Ask them to send a new copy if you still need it.",
        retry: false,
      };
    case "denied":
      if (e.deny_reason === "expired_or_revoked") {
        return {
          tone: "stop",
          title: "Access to this file has ended",
          body: "The file has been revoked or has expired. Nothing was decrypted.",
          retry: false,
        };
      }
      return {
        tone: "stop",
        title: "You're not allowed to open this file",
        body:
          "You signed in, but your organization's policy doesn't allow your account to open this file. " +
          "Nothing was decrypted. If you think you should have access, contact your administrator.",
        retry: false,
      };
    case "unavailable":
      return {
        tone: "warn",
        title: "Can't reach the SVX service",
        body:
          "The service or your organization's key agent didn't respond. Check your connection and try again. " +
          "Nothing was decrypted.",
        retry: true,
      };
    case "login":
      return {
        tone: "warn",
        title: "Sign-in didn't complete",
        body: "The sign-in was cancelled, timed out or was refused by your company login. You can try again.",
        retry: true,
      };
    case "not_logged_in":
      return {
        tone: "info",
        title: "Administrator sign-in needed",
        body: "Sign in on the Admin page first, then try again.",
        retry: false,
      };
    case "output_exists":
      return {
        tone: "info",
        title: "A file with this name is already there",
        body: `${e.path ?? "The destination"} already exists and is never overwritten. Choose another folder to save into.`,
        retry: false,
      };
    case "not_configured":
      return { tone: "info", title: "Set up needed", body: "Finish setup first.", retry: false };
    case "config":
      return { tone: "warn", title: "Check the details", body: e.message, retry: false };
    case "io":
      return { tone: "warn", title: "A file problem occurred", body: e.message, retry: false };
    default:
      return { tone: "warn", title: "Something went wrong", body: e.message, retry: true };
  }
}
