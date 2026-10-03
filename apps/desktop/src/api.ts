// Typed wrappers over the Rust commands (apps/desktop/src-tauri/src/main.rs).
// The UI only displays what these return; every security decision is made in
// Rust (svx-client).

import { invoke } from "@tauri-apps/api/core";

export interface AppError {
  kind: string;
  message: string;
  deny_reason: string | null;
  exit_code: number;
  path: string | null;
}

export interface Prefs {
  recent_recipients: string[];
  signing_key: string | null;
  last_policy: string | null;
}

export interface AppState {
  configured: boolean;
  config_path: string;
  config_error: string | null;
  org_id: string | null;
  service_url: string | null;
  idp_issuer: string | null;
  dev: boolean;
  output_dir: string | null;
  prefs: Prefs;
}

export interface SetupForm {
  service_url: string;
  registry_key: string;
  org_id: string;
  idp_client_id: string;
  dev: boolean;
  default_output_dir: string | null;
}

export interface SetupPreview {
  service_id: string;
  service_url: string;
  org_id: string;
  org_display_name: string;
  idp_issuer: string;
  can_receive: boolean;
}

export interface StatusView {
  artifact_id: string;
  sender_org: string;
  recipient_org: string;
  my_org: string;
  for_you: boolean;
  expired: boolean;
  created_at: number;
  expires_at: number | null;
  policy: string;
  service_id: string;
  /** Human-readable protection level of the file's suite. */
  protection: string;
  /** Whether the file resists quantum attacks (suite SVX-1H). */
  post_quantum: boolean;
}

export interface Progress {
  step: string;
  index: number;
  sender: string | null;
}

export interface OpenResult {
  path: string;
  name: string;
  is_folder: boolean;
  size: number;
  sender_org: string;
  artifact_id: string;
  classification: string | null;
  description: string | null;
  can_open: boolean;
}

export interface Recipient {
  org_id: string;
  display_name: string;
  domain: string;
  can_receive: boolean;
}

export interface SendRequest {
  input: string;
  recipient: string;
  policy: string;
  expires_at: number | null;
  classification: string | null;
  description: string | null;
  signing_key: string;
  register: boolean;
}

export interface PackResult {
  path: string;
  artifact_id: string;
  sender_org: string;
  recipient_org: string;
  service_id: string;
  policy: string;
  expires_at: number | null;
  signing_key_id: string;
  registered: boolean;
  protection: string;
}

export interface WhoAmI {
  sub: string;
  org_id: string;
  issuer: string;
  email: string | null;
  groups: string[];
  acr: string | null;
  expires_at: number;
}

export interface AuditEntry {
  seq: number;
  at: number;
  event: string;
  subject: string | null;
  artifact_id: string | null;
  txn: string | null;
  reason: string | null;
  hash: string;
}

export interface AuditPage {
  entries: AuditEntry[];
  chain_valid: boolean;
}

export interface Policy {
  allow_users: string[];
  allow_groups: string[];
  require_acr: string[];
  max_age_secs: number | null;
  [key: string]: unknown;
}

export type PickKind =
  | "send_file"
  | "send_folder"
  | "artifact"
  | "signing_key"
  | "config"
  | "output_dir";

/** Normalize anything thrown by invoke into an AppError. */
export function asAppError(e: unknown): AppError {
  if (e && typeof e === "object" && "kind" in e && "message" in e) {
    return e as AppError;
  }
  return {
    kind: "other",
    message: String(e),
    deny_reason: null,
    exit_code: 2,
    path: null,
  };
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    throw asAppError(e);
  }
}

export const api = {
  state: () => call<AppState>("state"),
  takePending: () => call<string[]>("take_pending"),
  setupVerify: (form: SetupForm) => call<SetupPreview>("setup_verify", { form }),
  setupSave: (form: SetupForm, replace: boolean) =>
    call<SetupPreview>("setup_save", { form, replace }),
  readConfigFile: (path: string) => call<SetupForm>("read_config_file", { path }),
  status: (path: string) => call<StatusView>("status", { path }),
  open: (path: string, outputDir: string | null, devUser: string | null) =>
    call<OpenResult>("open", { path, outputDir, devUser }),
  recipient: (org: string) => call<Recipient>("recipient", { org }),
  send: (req: SendRequest) => call<PackResult>("send", { req }),
  login: (devUser: string | null) => call<WhoAmI>("login", { devUser }),
  logout: () => call<boolean>("logout"),
  whoami: () => call<WhoAmI | null>("whoami"),
  revoke: (target: string) => call<string>("revoke", { target }),
  audit: (limit: number) => call<AuditPage>("audit", { limit }),
  policies: () => call<Record<string, Policy>>("policies"),
  pick: (kind: PickKind) => call<string | null>("pick", { kind }),
  reveal: (path: string) => call<void>("reveal", { path }),
  openDocument: (path: string) => call<void>("open_document", { path }),
};
