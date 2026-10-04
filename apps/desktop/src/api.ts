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
  /** Ask for Touch ID / password before using the keys (null = on). */
  ask_presence: boolean | null;
  relock_minutes: number | null;
  /** Check for app updates (null = on). */
  check_updates: boolean | null;
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
  /** A personal account (Google or email), not a company setup. */
  personal: boolean;
  email: string | null;
  /** This computer can ask for Touch ID / the password / Windows Hello. */
  presence_available: boolean;
  /** ... and does now (never on development services). */
  presence_active: boolean;
  /** This build checks for updates. */
  updates_available: boolean;
  /** This computer can show view-only files (not Linux). */
  view_supported: boolean;
}

/** A newer release, verified against the release key built into the app. */
export interface AvailableUpdate {
  version: string;
  notes: string;
  released_at: number;
  platform: string;
  package: { url: string; size: number; sha512: string; signature: string };
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
  /** The sender's verified email (personal) or organization name. */
  sender_name: string;
  recipient_org: string;
  recipients: string[];
  my_org: string;
  for_you: boolean;
  expired: boolean;
  created_at: number;
  expires_at: number | null;
  policy: string;
  service_id: string;
  /** Human-readable protection level of the file's suite. */
  protection: string;
  /** Whether the file resists quantum attacks (suites SVX-1H and SVX-2). */
  post_quantum: boolean;
  /** Suite ID: 1 = SVX-1, 3 = SVX-1H, 4 = SVX-2. */
  suite_id: number;
  /** Signed as view-only: shown in the app, never written to disk. */
  view_only: boolean;
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

// ----- Personal accounts -----

export interface Provider {
  name: string;
  issuer: string;
}

export interface Providers {
  service_url: string;
  dev: boolean;
  providers: Provider[];
}

export interface AccountInfo {
  account: string;
  email: string;
  provider: string;
  issuer: string;
  created_at: number | null;
  signing_key_id: string;
  kem_key_id: string;
  kem_public: string;
}

export interface Contact {
  account: string;
  email: string;
}

export interface PasswordStrength {
  score: number;
  ok: boolean;
  feedback: string[];
}

export interface CodeSent {
  challenge: string;
  expires_at: number;
}

export interface EmailForm {
  email: string;
  password: string;
  first_name: string | null;
  last_name: string | null;
  challenge: string;
  code: string;
}

export interface FileRules {
  require_approval: boolean;
  one_time: boolean;
  expires_at: number | null;
  /** Recipients can view it in the app but not save it. */
  view_only: boolean;
  /** For a view-only file: recipients may ask to keep a copy. */
  allow_share_requests: boolean;
}

export interface PersonalSendRequest {
  input: string;
  to: string[];
  require_approval: boolean;
  one_time: boolean;
  expires_at: number | null;
  view_only: boolean;
  allow_share_requests: boolean;
}

export interface SendResult {
  path: string;
  artifact_id: string;
  recipients: Contact[];
  rules: FileRules;
  expires_at: number | null;
  protection: string;
}

export type RecipientState = "not_opened" | "requested" | "approved" | "opened" | "declined" | "revoked";

export interface RecipientStatus {
  account: string;
  email: string | null;
  state: RecipientState;
  requested_at: number | null;
  opened_at: number | null;
}

export interface SentFile {
  artifact_id: string;
  sender: string;
  sender_email: string | null;
  created_at: number;
  signed_expires_at: number | null;
  rules: FileRules;
  /** Sent as view-only: view-only can be switched back on for this file (and no other). */
  signed_view_only: boolean;
  revoked_at: number | null;
  recipients: RecipientStatus[];
  file_name: string | null;
}

export interface ReceivedFile {
  artifact_id: string;
  sender: string;
  sender_email: string | null;
  created_at: number;
  state: RecipientState;
  requested_at: number | null;
  opened_at: number | null;
  view_only: boolean;
  file_name: string | null;
}

export interface HistoryView {
  sent: SentFile[];
  received: ReceivedFile[];
}

export interface RequestView {
  /** What they ask for: to open the file, or to keep a view-only file as a normal file. */
  kind: "open" | "share";
  request_id: string;
  artifact_id: string;
  requester: string;
  requester_email: string | null;
  requested_at: number;
  expires_at: number;
  file_name: string | null;
}

export interface UpdateFileRequest {
  require_approval?: boolean;
  one_time?: boolean;
  expires_at?: number;
  view_only?: boolean;
  allow_share_requests?: boolean;
  revoke?: boolean;
  revoke_recipients?: string[];
}

/** Whether a file can be sent view-only, and why not (from Rust). */
export interface ViewCheck {
  ok: boolean;
  /** An Office file: converted to PDF for viewing; the original is what "keep a copy" saves. */
  office: boolean;
  reason: string | null;
}

export type ShareState = "unrestricted" | "forbidden" | "not_requested" | "pending" | "approved" | "declined";

export interface ShareStatus {
  artifact_id: string;
  state: ShareState;
  expires_at: number | null;
}

/** What the viewer window may know: layout and names, never the document. */
export interface ViewInfo {
  file_name: string;
  sender: string;
  /** Each page's natural [width, height]. */
  pages: [number, number][];
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
  providers: () => call<Providers>("providers"),
  signUp: (issuer: string | null, reset: boolean, devUser: string | null, replace: boolean) =>
    call<AccountInfo>("sign_up", { issuer, reset, devUser, replace }),
  restore: (issuer: string | null, password: string, devUser: string | null, replace: boolean) =>
    call<AccountInfo | null>("restore", { issuer, password, devUser, replace }),
  checkUpdate: () => call<AvailableUpdate | null>("check_update"),
  setCheckUpdates: (on: boolean) => call<AppState>("set_check_updates", { on }),
  installUpdate: () => call<void>("install_update"),
  setPresence: (on: boolean, relockMinutes: number) =>
    call<AppState>("set_presence", { on, relockMinutes }),
  lockNow: () => call<void>("lock_now"),
  requestEmailCode: (email: string, purpose: "sign_up" | "sign_in" | "reset_password") =>
    call<CodeSent>("request_email_code", { email, purpose }),
  emailSignUp: (form: EmailForm, reset: boolean, replace: boolean) =>
    call<AccountInfo>("email_sign_up", { form, reset, replace }),
  emailRestore: (form: EmailForm, recoveryPassword: string, replace: boolean) =>
    call<AccountInfo | null>("email_restore", { form, recoveryPassword, replace }),
  resetPassword: (email: string, challenge: string, code: string, newPassword: string) =>
    call<void>("reset_password", { email, challenge, code, newPassword }),
  changePassword: (current: string, next: string) => call<void>("change_password", { current, new: next }),
  passwordStrength: (password: string, inputs: string[]) =>
    call<PasswordStrength>("password_strength", { password, inputs }),
  saveBackup: (password: string) => call<string | null>("save_backup", { password }),
  account: () => call<AccountInfo>("account"),
  lookup: (email: string) => call<Contact>("lookup", { email }),
  sendPersonal: (req: PersonalSendRequest) => call<SendResult>("send_personal", { req }),
  requests: () => call<RequestView[]>("requests"),
  approve: (requestId: string) => call<unknown>("approve", { requestId }),
  decline: (requestId: string) => call<unknown>("decline", { requestId }),
  history: () => call<HistoryView>("history"),
  file: (artifactId: string) => call<SentFile>("file", { artifactId }),
  updateFile: (artifactId: string, update: UpdateFileRequest) =>
    call<SentFile>("update_file", { artifactId, update }),
  cancelOpen: () => call<void>("cancel_open"),
  viewCheck: (path: string) => call<ViewCheck>("view_check", { path }),
  viewOpen: (path: string) => call<void>("view_open", { path }),
  viewInfo: (id: number) => call<ViewInfo>("view_info", { id }),
  /** 8 bytes (width, height as little-endian u32), then RGBA rows, watermark burned in. */
  viewPage: (id: number, page: number, width: number) =>
    call<ArrayBuffer>("view_page", { id, page, width }),
  viewShare: (id: number, ask: boolean) => call<ShareStatus>("view_share", { id, ask }),
  viewSave: (id: number) => call<OpenResult>("view_save", { id }),
  viewClose: () => call<void>("view_close"),
  setOutputDir: () => call<string | null>("set_output_dir"),
  signOut: () => call<void>("sign_out"),
  pick: (kind: PickKind) => call<string | null>("pick", { kind }),
  reveal: (path: string) => call<void>("reveal", { path }),
  openDocument: (path: string) => call<void>("open_document", { path }),
};
