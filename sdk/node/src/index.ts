/**
 * SVX secure verified exchange — Node.js SDK.
 *
 * Data fields use the same snake_case names as the SVX JSON API and the
 * Python SDK; methods and options are camelCase.
 *
 * A thin, typed layer over the Rust `svx-client` library (the same code the
 * `svx` CLI runs). Nothing security-relevant is implemented in JavaScript:
 * verification, login binding, key release and decryption all happen in the
 * native addon.
 *
 * ```ts
 * import { Client } from "@svx/sdk";
 * const client = Client.load();
 * const result = await client.open("incident.svx", { outputDir: "/home/me/SVX" });
 * ```
 *
 * Errors are thrown as subclasses of {@link SvxError}; security refusals
 * ({@link RefusedError}) are distinct from outages ({@link UnavailableError})
 * and local problems.
 */

import * as native from "../native";

// ---------------------------------------------------------------------------
// Errors

/** Stable machine-readable error category. */
export type ErrorKind =
  | "config"
  | "io"
  | "rejected"
  | "not_recipient"
  | "expired"
  | "denied"
  | "unavailable"
  | "login"
  | "not_logged_in"
  | "output_exists"
  | "invalid"
  | "account_exists"
  | "cancelled"
  | "other";

/** Coarse reason reported by the service for {@link AccessDeniedError}. */
export type DenyReason =
  | "not_authorized"
  | "expired_or_revoked"
  | "invalid_artifact"
  | "invalid_request"
  | "unavailable"
  | "already_opened"
  | "declined";

/** Base class of all SVX errors. */
export class SvxError extends Error {
  /** Stable category, e.g. `"denied"`. */
  readonly kind: ErrorKind;
  /** What the `svx` CLI would exit with: 1 refused, 2 local error, 3 unavailable. */
  readonly exitCode: number;
  readonly denyReason: DenyReason | null;

  constructor(
    message: string,
    kind: ErrorKind = "other",
    exitCode = 2,
    denyReason: DenyReason | null = null,
  ) {
    super(message);
    this.name = new.target.name;
    this.kind = kind;
    this.exitCode = exitCode;
    this.denyReason = denyReason;
  }
}

/** A security refusal: the artifact was not opened, by design. */
export class RefusedError extends SvxError {}
/** The artifact failed verification (tampered, untrusted sender...). */
export class RejectedError extends RefusedError {}
/** The artifact is addressed to a different organization. */
export class NotRecipientError extends RefusedError {}
/** The artifact has expired (checked locally before any login). */
export class ExpiredError extends RefusedError {}
/** The managed service or key agent refused to release keys. */
export class AccessDeniedError extends RefusedError {}
/** The SVX service could not be reached. Nothing was decrypted. */
export class UnavailableError extends SvxError {}
/** Signing in to the organization's identity provider failed. */
export class LoginError extends SvxError {}
/** An admin operation needs {@link Client.login} first. */
export class NotLoggedInError extends LoginError {}
/** Missing or invalid configuration or arguments. */
export class ConfigError extends SvxError {}
/** The output file exists and `overwrite` was not requested. */
export class OutputExistsError extends SvxError {}

const ERRORS: Record<string, new (m: string, k: ErrorKind, c: number, d: DenyReason | null) => SvxError> = {
  rejected: RejectedError,
  not_recipient: NotRecipientError,
  expired: ExpiredError,
  denied: AccessDeniedError,
  unavailable: UnavailableError,
  login: LoginError,
  not_logged_in: NotLoggedInError,
  config: ConfigError,
  output_exists: OutputExistsError,
};

const PREFIX = "SVX_ERROR:";

function translate(e: unknown): unknown {
  if (e instanceof Error && e.message.startsWith(PREFIX)) {
    try {
      const j = JSON.parse(e.message.slice(PREFIX.length)) as {
        kind: ErrorKind;
        message: string;
        exitCode: number;
        denyReason: DenyReason | null;
      };
      const Cls = ERRORS[j.kind] ?? SvxError;
      return new Cls(j.message, j.kind, j.exitCode, j.denyReason);
    } catch {
      return e;
    }
  }
  return e;
}

function call<T>(f: () => T): T {
  try {
    return f();
  } catch (e) {
    throw translate(e);
  }
}

async function callAsync<T>(f: () => Promise<T>): Promise<T> {
  try {
    return await f();
  } catch (e) {
    throw translate(e);
  }
}

// ---------------------------------------------------------------------------
// Result types (JSON from the native layer)

export interface Envelope {
  role: "service" | "recipient-org";
  key_id: string;
}

/** Header fields. Unverified when returned by {@link inspect}. */
export interface ArtifactInfo {
  format_version: string;
  suite_id: number;
  /** Human-readable protection level, e.g. "maximum (...)". */
  protection: string;
  /** True for the post-quantum suites (SVX-1H 0x0003, SVX-2 0x0004). */
  post_quantum: boolean;
  artifact_id: string;
  /** Unix seconds, UTC. */
  created_at: number;
  expires_at: number | null;
  sender_org: string;
  sender_key_id: string;
  recipient_org: string;
  /** Every recipient (several for personal files sent to several people). */
  recipients: string[];
  service_id: string;
  policy_ref: string;
  chunk_size: number;
  envelopes: Envelope[];
  encrypted_manifest_bytes: number;
  unknown_fields: number[];
}

export interface Verified {
  info: ArtifactInfo;
  chunk_count: number;
  expired: boolean;
}

/** Result of {@link Client.status}: verified against the registry. */
export interface Status extends Verified {
  for_you: boolean;
  /** The sender's verified email (personal accounts) or organization name. */
  sender_name: string;
}

export interface FileEntry {
  name: string;
  size: number;
  content_type?: string;
}

export interface Manifest {
  svx_manifest: number;
  files: FileEntry[];
  classification?: string;
  description?: string;
}

export interface OpenResult {
  /** The written file; `null` for {@link Client.openBytes}. */
  path: string | null;
  sender_org: string;
  artifact_id: string;
  manifest: Manifest;
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

/** An access policy held by the recipient organization. */
export interface Policy {
  /** Subjects (`sub` claims) explicitly allowed. */
  allow_users?: string[];
  /** Groups allowed. */
  allow_groups?: string[];
  /** If non-empty, the token's `acr` must be one of these. */
  require_acr?: string[];
  /** Maximum artifact age from its signed creation time. */
  max_age_secs?: number | null;
  /** Access window, Unix seconds. */
  not_before?: number | null;
  not_after?: number | null;
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

export interface KeyEntry {
  key_id: string;
  kind: "ed25519-mldsa65" | "xwing" | "ed25519" | "x25519";
  public_key: string;
  status: "active" | "retired" | "revoked";
}

export interface OrgRecord {
  v: number;
  org_id: string;
  display_name: string;
  domain: string;
  idp_issuer: string;
  key_agent_url: string | null;
  keys: KeyEntry[];
  issued_at: number;
}

/** Progress step names reported to `onStep`. */
export type StepName =
  | "verifying"
  | "signature_valid"
  | "connecting"
  | "authenticating"
  | "checking_authorization"
  | "awaiting_approval"
  | "access_approved"
  | "decrypting";

export interface LoginOptions {
  /** Development IdP user; only with `dev = true` configurations. */
  devUser?: string;
  /** Open the system browser (default) or only print the sign-in URL. */
  browser?: boolean;
}

export interface OpenOptions extends LoginOptions {
  /** Default: the configured directory, else `~/SVX`. */
  outputDir?: string;
  overwrite?: boolean;
  /** Called for each step; `detail` is the sender for `signature_valid`. */
  onStep?: (name: StepName, detail: string | null) => void;
}

export interface PackOptions {
  /** Default: `input` with the extension `.svx`. */
  output?: string;
  recipient: string;
  policy: string;
  /** Path to your organization's `*.sign.key`. */
  signingKey: string;
  /** Unix seconds, or a Date. */
  expiresAt?: number | Date;
  classification?: string;
  description?: string;
  /** File name recorded in the encrypted manifest. */
  name?: string;
  overwrite?: boolean;
  /** Record the artifact with the service (needs {@link Client.login}). */
  register?: boolean;
}

function openResult(json: string): OpenResult {
  return JSON.parse(json) as OpenResult;
}

// ---------------------------------------------------------------------------
// Offline functions

/** The native core's version. */
export const version: string = native.version();

/** Parse the header WITHOUT verifying it. Never trust the result. */
export function inspect(path: string): ArtifactInfo {
  return JSON.parse(call(() => native.inspect(path))) as ArtifactInfo;
}

/** Verify signature and integrity offline against `*.sign.pub` files. */
export function verify(path: string, trust: string[]): Verified {
  return JSON.parse(call(() => native.verify(path, trust))) as Verified;
}

/** Write `<prefix>.sign.key` (owner-only) and `.sign.pub`; returns the key ID. */
export function generateSigningKey(prefix: string, owner: string): string {
  return call(() => native.generateSigningKey(prefix, owner));
}

/** Write `<prefix>.kem.key` (owner-only) and `.kem.pub`; returns the key ID. */
export function generateKemKey(prefix: string, owner: string): string {
  return call(() => native.generateKemKey(prefix, owner));
}

// ---------------------------------------------------------------------------
// Managed client

/**
 * An SVX client bound to one configuration (see `svx init`).
 *
 * Opening always signs the user in again: key release requires a login
 * bound to a one-time key generated for that open.
 */
export class Client {
  private readonly n: native.NativeClient;

  private constructor(n: native.NativeClient) {
    this.n = n;
  }

  /**
   * Load `config` (path to `config.toml`), else `$SVX_CONFIG`, else the
   * platform configuration directory — exactly like the CLI. The admin
   * session cache lives next to it.
   */
  static load(config?: string): Client {
    return new Client(call(() => new native.NativeClient(config ?? null)));
  }

  get configPath(): string {
    return this.n.configPath();
  }

  /** The loaded configuration (contains no secrets). */
  get config(): Record<string, unknown> {
    return JSON.parse(this.n.configJson()) as Record<string, unknown>;
  }

  /** Verify against the registry. No login, no key release. */
  async status(path: string): Promise<Status> {
    return JSON.parse(await callAsync(() => this.n.status(path))) as Status;
  }

  /**
   * Verify, sign in, obtain both key shares and decrypt to a file. The
   * plaintext is written owner-only under the manifest's file name, and
   * only after the whole payload authenticated.
   */
  async open(path: string, o: OpenOptions = {}): Promise<OpenResult> {
    const j = await callAsync(() =>
      this.n.open(
        path,
        o.outputDir ?? null,
        o.overwrite ?? false,
        o.devUser ?? null,
        o.browser ?? true,
        o.onStep as ((name: string, detail: string | null) => void) | undefined,
      ),
    );
    return openResult(j);
  }

  /**
   * Like {@link open} but returns the plaintext in memory. JavaScript cannot
   * reliably wipe memory; prefer {@link open} for highly sensitive content.
   */
  async openBytes(
    path: string,
    o: Omit<OpenOptions, "outputDir" | "overwrite"> = {},
  ): Promise<{ result: OpenResult; data: Buffer }> {
    const r = await callAsync(() =>
      this.n.openBytes(
        path,
        o.devUser ?? null,
        o.browser ?? true,
        o.onStep as ((name: string, detail: string | null) => void) | undefined,
      ),
    );
    return { result: openResult(r.json), data: r.data };
  }

  /**
   * Sign and encrypt `input` for `recipient`. Recipient and service keys
   * come from the signed registry; `signingKey` must be an active
   * registered key of your organization.
   */
  async pack(input: string, o: PackOptions): Promise<PackResult> {
    const expiresAt =
      o.expiresAt instanceof Date ? Math.floor(o.expiresAt.getTime() / 1000) : o.expiresAt;
    const j = await callAsync(() =>
      this.n.pack({
        input,
        output: o.output,
        recipient: o.recipient,
        policy: o.policy,
        signingKey: o.signingKey,
        expiresAt,
        classification: o.classification,
        description: o.description,
        name: o.name,
        overwrite: o.overwrite,
        register: o.register,
      }),
    );
    return JSON.parse(j) as PackResult;
  }

  /** Sign in and cache a short-lived admin session (owner-only file). */
  async login(o: LoginOptions = {}): Promise<WhoAmI> {
    return JSON.parse(
      await callAsync(() => this.n.login(o.devUser ?? null, o.browser ?? true)),
    ) as WhoAmI;
  }

  /** Delete the cached session; `false` if there was none. */
  logout(): boolean {
    return call(() => this.n.logout());
  }

  /** Re-validate the cached session with the IdP. */
  async whoami(): Promise<WhoAmI> {
    return JSON.parse(await callAsync(() => this.n.whoami())) as WhoAmI;
  }

  /** Revoke by artifact file or hex ID; returns the artifact ID. */
  async revoke(artifact: string): Promise<string> {
    return callAsync(() => this.n.revoke(artifact));
  }

  async policies(): Promise<Record<string, Policy>> {
    return JSON.parse(await callAsync(() => this.n.policies())) as Record<string, Policy>;
  }

  async setPolicy(name: string, policy: Policy): Promise<Policy> {
    return JSON.parse(
      await callAsync(() => this.n.setPolicy(name, JSON.stringify(policy))),
    ) as Policy;
  }

  async audit(limit = 50): Promise<AuditPage> {
    return JSON.parse(await callAsync(() => this.n.audit(limit))) as AuditPage;
  }

  /** The organization's registry record, verified with the pinned key. */
  async orgRecord(org: string): Promise<OrgRecord> {
    return JSON.parse(await callAsync(() => this.n.orgRecord(org))) as OrgRecord;
  }
}
