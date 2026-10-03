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
  /** A key file path or `keychain:<org>/<key_id>`. */
  signing_key: string | null;
  last_policy: string | null;
  pending_org: PendingOrg | null;
  pending_encryption_key: ExportedKemKey | null;
}

export interface OnboardRequest {
  service_url: string;
  registry_key: string;
  org_id: string;
  display_name: string;
  domain: string;
  idp_issuer: string;
  idp_client_id: string;
  group_claim: string | null;
  key_agent_url: string | null;
  dev: boolean;
  default_output_dir: string | null;
}

export interface PendingOrg {
  request: OnboardRequest;
  txt_name: string;
  txt_value: string;
  registered_at: number;
}

export type KeyKind = "ed25519-mldsa65" | "xwing" | "ed25519" | "x25519";
export type KeyStatus = "active" | "retired" | "revoked";

export interface KeyDetail {
  key_id: string;
  kind: KeyKind;
  public_key: string;
  status: KeyStatus;
  created_at: number;
  retired_at: number | null;
  revoked_at: number | null;
}

export interface KeyEntry {
  key_id: string;
  kind: KeyKind;
  public_key: string;
  status: KeyStatus;
}

export interface OrgOverview {
  org_id: string;
  display_name: string;
  domain: string;
  idp_issuer: string;
  idp_client_id: string;
  group_claim: string;
  key_agent_url: string | null;
  verified_at: number;
  admins: { subject: string; added_at: number }[];
  keys: KeyDetail[];
}

export interface AgentStatus {
  url: string;
  reachable: boolean;
  error: string | null;
  key_ids: string[];
}

export interface ExportedKemKey {
  key_id: string;
  secret_file: string;
  public_file: string;
}

export interface NewSigningKey {
  key_ref: string;
  key_id: string;
}

export interface AdminOverview {
  org: OrgOverview;
  agent: AgentStatus | null;
  this_computer_key: string | null;
  signing_key_problem: string | null;
  pending_encryption_key: ExportedKemKey | null;
}

export interface OrgSettingsForm {
  display_name?: string | null;
  key_agent_url?: string | null;
  remove_key_agent?: boolean;
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
  not_before: number | null;
  not_after: number | null;
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
  onboardRegister: (req: OnboardRequest) => call<PendingOrg>("onboard_register", { req }),
  onboardComplete: (devUser: string | null, replace: boolean) =>
    call<SetupPreview>("onboard_complete", { devUser, replace }),
  onboardCancel: () => call<void>("onboard_cancel"),
  adminOverview: () => call<AdminOverview>("admin_overview"),
  updateOrg: (form: OrgSettingsForm) => call<void>("update_org", { form }),
  addAdmin: (subject: string) => call<void>("add_admin", { subject }),
  removeAdmin: (subject: string) => call<void>("remove_admin", { subject }),
  setPolicy: (name: string, policy: Policy) => call<Policy>("set_policy", { name, policy }),
  deletePolicy: (name: string) => call<void>("delete_policy", { name }),
  auditPage: (limit: number, beforeSeq: number | null, event: string | null) =>
    call<AuditPage>("audit_page", { limit, beforeSeq, event }),
  exportAudit: (event: string | null) => call<[string, number] | null>("export_audit", { event }),
  createSigningKey: () => call<NewSigningKey>("create_signing_key"),
  importSigningKey: () => call<NewSigningKey | null>("import_signing_key"),
  registerSigningPublic: () => call<KeyEntry | null>("register_signing_public"),
  exportEncryptionKey: () => call<ExportedKemKey | null>("export_encryption_key"),
  activateEncryptionKey: () => call<KeyEntry>("activate_encryption_key"),
  discardPendingEncryptionKey: () => call<void>("discard_pending_encryption_key"),
  setKeyStatus: (keyId: string, status: KeyStatus) =>
    call<KeyEntry>("set_key_status", { keyId, status }),
  pick: (kind: PickKind) => call<string | null>("pick", { kind }),
  reveal: (path: string) => call<void>("reveal", { path }),
  openDocument: (path: string) => call<void>("open_document", { path }),
};
