//! Personal accounts (Phase 5d): sign-up, the email directory, per-file
//! rules, opening with the sender's approval, one-time files and history.
//!
//! Apart from sign-up, every request here is signed with the account's
//! device key ([`authenticate`]). The service still holds one half of every
//! file key, so revocation, expiry, approval and one-time opening are
//! enforced here before that half is released.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, Method, Uri};
use serde::Deserialize;
use sqlx::FromRow;
use svx_core::crypto::{
    KemPublicKey, KeyKind, VerifyingKey, os_rng, random_bytes, seal_released_share,
};
use svx_core::format::EnvelopeRole;
use svx_oidc::IssuerConfig;
use svx_protocol::personal::{
    Account, ApprovalRequest, FileRules, FileStatus, History, KEYS_ON_ANOTHER_DEVICE,
    OpenedReceipt, PersonalReleaseRequest, PersonalReleaseResponse, ReceivedFile, RecipientState,
    RecipientStatus, RegisterFileRequest, ReleaseMode, RequestAuth, RequestKind, SHARE_TTL_SECS,
    ShareState, ShareStatus, SignUpRequest, UpdateFileRequest, signup_nonce,
};
use svx_protocol::{
    DenyReason, KeyKindWire, KeyStatus, SealedShare, SignedOrgRecord, parse_client_key, unix_now,
};

use super::public::signed_org_record;
use super::release::verified_head;
use crate::error::{ApiError, ApiResult, is_unique_violation};
use crate::limits::{ClientIp, DAY, HOUR, MINUTE, TOO_MANY_ACCOUNT, account_allows, check_ip};
use crate::notify::{self, Email};
use crate::{AppState, audit, db};

/// A sender's approval lets that recipient open the file for this long;
/// a pending request waits this long.
pub const APPROVAL_TTL_SECS: i64 = 24 * 3600;
/// A one-time open becomes final after this long even without a receipt
/// (so a crash mid-decryption can be retried).
pub const ONE_TIME_RETRY_SECS: i64 = 600;
/// Directory lookups per account per minute.
const DIRECTORY_PER_MINUTE: u32 = 30;
/// Shown to the owner of a suspended account.
pub(crate) const SUSPENDED: &str =
    "this account is suspended; contact support if you think this is a mistake";

fn deny(r: DenyReason) -> ApiError {
    ApiError::Deny(r)
}

/// Release endpoints answer without detail: a suspended account is
/// simply not authorized.
fn quiet(e: ApiError) -> ApiError {
    match e {
        ApiError::Conflict(_) => ApiError::Unauthorized,
        e => e,
    }
}

fn bad(msg: &str) -> ApiError {
    ApiError::BadRequest(msg.into())
}

// ----- Accounts -----

/// A signed-in personal account.
#[derive(Clone, Debug, FromRow)]
pub(crate) struct PersonalAccount {
    pub org_id: String,
    pub issuer: String,
    pub email: String,
    pub created_at: i64,
}

impl PersonalAccount {
    pub(crate) fn to_wire(&self) -> Account {
        Account {
            account: self.org_id.clone(),
            email: self.email.clone(),
            issuer: self.issuer.clone(),
            created_at: self.created_at,
        }
    }
}

const ACCOUNT_COLUMNS: &str = "org_id, issuer, email, created_at";

async fn account_by_org(st: &AppState, org_id: &str) -> ApiResult<Option<PersonalAccount>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {ACCOUNT_COLUMNS} FROM personal_accounts WHERE org_id = $1"
    ))
    .bind(org_id)
    .fetch_optional(&st.db)
    .await?)
}

/// Whether `svx-admin suspend` suspended this account.
pub(crate) async fn is_suspended(db: impl sqlx::PgExecutor<'_>, org_id: &str) -> ApiResult<bool> {
    Ok(
        sqlx::query_scalar::<_, bool>(
            "SELECT suspended_at IS NOT NULL FROM orgs WHERE org_id = $1",
        )
        .bind(org_id)
        .fetch_optional(db)
        .await?
        .unwrap_or(false),
    )
}

async fn email_of(st: &AppState, org_id: &str) -> ApiResult<Option<String>> {
    Ok(account_by_org(st, org_id).await?.map(|a| a.email))
}

/// Authenticate a request signed with an account's device key: a known
/// personal account, one of its active SVX-2 signing keys, a signature
/// over the method, path, body, time and a fresh nonce.
pub(crate) async fn authenticate(
    st: &AppState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> ApiResult<PersonalAccount> {
    let auth = RequestAuth::from_headers(|n| headers.get(n).and_then(|v| v.to_str().ok()))
        .ok_or(ApiError::Unauthorized)?;
    let account = account_by_org(st, &auth.account)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    let key = db::keys(&st.db, &account.org_id)
        .await?
        .iter()
        .filter_map(db::KeyRow::to_entry)
        .find(|k| {
            k.key_id == auth.key_id && k.kind == KeyKindWire::Max && k.status == KeyStatus::Active
        })
        .and_then(|k| k.verifying_key().ok())
        .ok_or(ApiError::Unauthorized)?;
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let now = unix_now();
    if auth.verify(&key, method.as_str(), path, body, now).is_err() {
        return Err(ApiError::Unauthorized);
    }
    if is_suspended(&st.db, &account.org_id).await? {
        return Err(ApiError::Conflict(SUSPENDED.into()));
    }
    // Each signed request is accepted once.
    sqlx::query("DELETE FROM request_nonces WHERE at < $1")
        .bind(now - 600)
        .execute(&st.db)
        .await?;
    match sqlx::query("INSERT INTO request_nonces (nonce, at) VALUES ($1, $2)")
        .bind(&auth.nonce[..])
        .bind(now)
        .execute(&st.db)
        .await
    {
        Ok(_) => Ok(account),
        Err(e) if is_unique_violation(&e) => {
            audit::note(
                &st.db,
                &account.org_id,
                audit::Record {
                    event: audit::event::REPLAY,
                    reason: Some("signed request replayed".into()),
                    ..Default::default()
                },
            )
            .await;
            Err(ApiError::Unauthorized)
        }
        Err(e) => Err(e.into()),
    }
}

/// `POST /v1/accounts`: sign up, or register this device's keys.
pub async fn sign_up(
    State(st): State<AppState>,
    ip: Option<Extension<ClientIp>>,
    Json(req): Json<SignUpRequest>,
) -> ApiResult<Json<Account>> {
    let idp = st
        .personal_idps
        .iter()
        .find(|p| p.issuer == req.issuer)
        .ok_or_else(|| bad("unknown sign-in provider"))?;
    let signing = VerifyingKey::from_kind_bytes(KeyKind::MaxSigning, &req.signing_public)
        .map_err(|_| bad("signing_public must be an Ed25519 + ML-DSA-87 + SLH-DSA key"))?;
    let kem = KemPublicKey::from_kind_bytes(KeyKind::MaxKem, &req.kem_public)
        .map_err(|_| bad("kem_public must be an MLKEM1024-P384 key"))?;
    let cfg = IssuerConfig {
        issuer: idp.issuer.clone(),
        client_id: idp.client_id.clone(),
        group_claim: "groups".into(),
    };
    let nonce = signup_nonce(&req.signing_public, &req.kem_public);
    let who = st
        .oidc
        .validate(&cfg, &req.id_token, Some(&nonce))
        .await
        .map_err(|_| ApiError::Unauthorized)?;
    let email = who
        .email
        .clone()
        .filter(|e| who.email_verified && valid_email(e))
        .ok_or_else(|| bad("the sign-in provider did not confirm an email address"))?;
    let account = bind_device(
        &st,
        Identity {
            issuer: &who.issuer,
            subject: &who.sub,
            email: &email,
            client_id: &idp.client_id,
            names: None,
            password_hash: None,
        },
        &signing,
        &kem,
        req.reset,
        Existing::Allow,
        ip.map(|e| e.0),
    )
    .await?;
    Ok(Json(account.to_wire()))
}

/// Who is binding keys: a provider identity (`issuer`, `subject`) and the
/// confirmed email address.
pub(crate) struct Identity<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
    pub email: &'a str,
    pub client_id: &'a str,
    /// First and last name (email accounts).
    pub names: Option<(&'a str, &'a str)>,
    /// For a new email account.
    pub password_hash: Option<String>,
}

/// What [`bind_device`] may do with an account that already exists, or
/// doesn't.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Existing {
    /// Create it, or register this device for it (Google).
    Allow,
    /// Create only: refuse if the identity has an account.
    Refuse,
    /// Register this device only: refuse if there's no account.
    Require,
}

/// Create the personal account for `who`, or register this device's keys
/// for it: the same keys (a restored backup) are accepted, other keys only
/// with `reset` (the old ones are retired).
pub(crate) async fn bind_device(
    st: &AppState,
    who: Identity<'_>,
    signing: &VerifyingKey,
    kem: &KemPublicKey,
    reset: bool,
    existing_ok: Existing,
    ip: Option<ClientIp>,
) -> ApiResult<PersonalAccount> {
    let now = unix_now();
    let mut tx = st.db.begin().await?;
    // One sign-up at a time per identity.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(format!("{}\n{}", who.issuer, who.subject))
        .execute(&mut *tx)
        .await?;
    let existing: Option<PersonalAccount> = sqlx::query_as(&format!(
        "SELECT {ACCOUNT_COLUMNS} FROM personal_accounts WHERE issuer = $1 AND subject = $2"
    ))
    .bind(who.issuer)
    .bind(who.subject)
    .fetch_optional(&mut *tx)
    .await?;
    let (account, event) = match existing {
        None if existing_ok == Existing::Require => {
            return Err(bad("wrong email address, password or code"));
        }
        None => {
            check_ip(st, ip, "accounts", st.limits.accounts_per_ip_per_day, DAY)?;
            let taken: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM personal_accounts WHERE lower(email) = lower($1))",
            )
            .bind(who.email)
            .fetch_one(&mut *tx)
            .await?;
            if taken {
                return Err(ApiError::Conflict(
                    "this email already has an account with another sign-in provider".into(),
                ));
            }
            // A backup's keys belong to the account it was made for.
            let reused: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM org_keys WHERE key_id = $1 OR key_id = $2)",
            )
            .bind(&signing.key_id()[..])
            .bind(&kem.key_id()[..])
            .fetch_one(&mut *tx)
            .await?;
            if reused {
                return Err(ApiError::Conflict(
                    "these keys belong to another account".into(),
                ));
            }
            let org_id = format!("u.{}", hex::encode(random_bytes::<8>()));
            let domain = who.email.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
            let display = match who.names {
                Some((first, last)) => format!("{} {}", first.trim(), last.trim()),
                None => who.email.to_owned(),
            };
            sqlx::query(
                "INSERT INTO orgs (org_id, display_name, domain, idp_issuer, idp_client_id, group_claim, \
                 key_agent_url, challenge, created_at, verified_at, kind) \
                 VALUES ($1, $2, $3, $4, $5, 'groups', NULL, '', $6, $6, 'personal')",
            )
            .bind(&org_id)
            .bind(&display)
            .bind(domain.to_ascii_lowercase())
            .bind(who.issuer)
            .bind(who.client_id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO personal_accounts (org_id, issuer, subject, email, created_at, \
                 first_name, last_name) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(&org_id)
            .bind(who.issuer)
            .bind(who.subject)
            .bind(who.email)
            .bind(now)
            .bind(who.names.map(|n| n.0.trim()))
            .bind(who.names.map(|n| n.1.trim()))
            .execute(&mut *tx)
            .await?;
            if let Some(h) = &who.password_hash {
                sqlx::query(
                    "INSERT INTO email_accounts (org_id, password_hash, password_changed_at) \
                     VALUES ($1, $2, $3)",
                )
                .bind(&org_id)
                .bind(h)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            }
            insert_keys(&mut tx, &org_id, signing, kem, now).await?;
            let a = PersonalAccount {
                org_id,
                issuer: who.issuer.to_owned(),
                email: who.email.to_owned(),
                created_at: now,
            };
            (a, "account created")
        }
        Some(_) if existing_ok == Existing::Refuse => {
            return Err(ApiError::Conflict(
                "this email already has an account: sign in instead".into(),
            ));
        }
        Some(a) => {
            if is_suspended(&mut *tx, &a.org_id).await? {
                return Err(ApiError::Conflict(SUSPENDED.into()));
            }
            let active: Vec<Vec<u8>> = sqlx::query_scalar(
                "SELECT key_id FROM org_keys WHERE org_id = $1 AND status = 'active'",
            )
            .bind(&a.org_id)
            .fetch_all(&mut *tx)
            .await?;
            let same = active.len() == 2
                && active.contains(&signing.key_id().to_vec())
                && active.contains(&kem.key_id().to_vec());
            if same {
                // This device restored the account's backup: nothing to do.
                (a, "device signed in")
            } else if reset {
                sqlx::query(
                    "UPDATE org_keys SET status = 'retired', retired_at = $2 \
                     WHERE org_id = $1 AND status = 'active'",
                )
                .bind(&a.org_id)
                .bind(now)
                .execute(&mut *tx)
                .await?;
                insert_keys(&mut tx, &a.org_id, signing, kem, now).await?;
                (a, "keys reset")
            } else {
                return Err(ApiError::Conflict(KEYS_ON_ANOTHER_DEVICE.into()));
            }
        }
    };
    tx.commit().await?;
    audit::append(
        &st.db,
        &account.org_id,
        audit::Record {
            event: audit::event::KEY_CHANGED,
            subject: Some(who.subject.to_owned()),
            reason: Some(event.into()),
            ..Default::default()
        },
    )
    .await?;
    Ok(account)
}

pub(crate) fn valid_email(e: &str) -> bool {
    e.len() <= 254
        && e.split_once('@')
            .is_some_and(|(l, d)| !l.is_empty() && d.contains('.') && !d.starts_with('.'))
        && !e.chars().any(|c| c.is_whitespace() || c.is_control())
}

async fn insert_keys(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: &str,
    signing: &VerifyingKey,
    kem: &KemPublicKey,
    now: i64,
) -> ApiResult<()> {
    for (id, kind, public) in [
        (signing.key_id(), KeyKindWire::Max, signing.to_vec()),
        (kem.key_id(), KeyKindWire::MlKem1024P384, kem.to_vec()),
    ] {
        sqlx::query(
            "INSERT INTO org_keys (org_id, key_id, kind, public_key, status, created_at) \
             VALUES ($1, $2, $3, $4, 'active', $5) \
             ON CONFLICT (org_id, key_id) DO UPDATE SET status = 'active', retired_at = NULL",
        )
        .bind(org_id)
        .bind(&id[..])
        .bind(kind.as_str())
        .bind(&public[..])
        .bind(now)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// `GET /v1/me`: the signed-in account.
pub async fn me(
    State(st): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> ApiResult<Json<Account>> {
    let me = authenticate(&st, &method, &uri, &headers, b"").await?;
    Ok(Json(me.to_wire()))
}

#[derive(Deserialize)]
pub struct DirectoryQuery {
    email: String,
}

/// `GET /v1/directory?email=`: the signed registry record of the account
/// with this email. Only signed-in accounts can look people up, and only
/// a few times a minute.
pub async fn directory(
    State(st): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    Query(q): Query<DirectoryQuery>,
) -> ApiResult<Json<SignedOrgRecord>> {
    let me = authenticate(&st, &method, &uri, &headers, b"").await?;
    if !st.limiter.allow(&me.org_id, DIRECTORY_PER_MINUTE) {
        return Err(ApiError::Conflict(
            "too many lookups; wait a minute and try again".into(),
        ));
    }
    let org: Option<String> =
        sqlx::query_scalar("SELECT org_id FROM personal_accounts WHERE lower(email) = lower($1)")
            .bind(q.email.trim())
            .fetch_optional(&st.db)
            .await?;
    let org = org.ok_or(ApiError::NotFound)?;
    Ok(Json(signed_org_record(&st, &org).await?))
}

// ----- Files -----

#[derive(Clone, Debug, FromRow)]
struct FileRow {
    artifact_id: Vec<u8>,
    sender: String,
    header_hash: Vec<u8>,
    created_at: i64,
    signed_expires_at: Option<i64>,
    require_approval: bool,
    one_time: bool,
    expires_at: Option<i64>,
    revoked_at: Option<i64>,
    view_only: bool,
    allow_share_requests: bool,
    /// The flag signed into the file (format 1.4).
    signed_view_only: bool,
}

impl FileRow {
    fn id(&self) -> [u8; 16] {
        self.artifact_id.as_slice().try_into().unwrap_or_default()
    }

    fn rules(&self) -> FileRules {
        FileRules {
            require_approval: self.require_approval,
            one_time: self.one_time,
            expires_at: self.expires_at,
            view_only: self.view_only,
            allow_share_requests: self.allow_share_requests,
        }
    }

    /// The earlier of the signed and the server-side expiry.
    fn effective_expiry(&self) -> Option<i64> {
        match (self.signed_expires_at, self.expires_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

const FILE_COLUMNS: &str = "artifact_id, sender, header_hash, created_at, signed_expires_at, \
    require_approval, one_time, expires_at, revoked_at, view_only, allow_share_requests, signed_view_only";

async fn file(st: &AppState, artifact_id: &[u8]) -> ApiResult<Option<FileRow>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {FILE_COLUMNS} FROM personal_files WHERE artifact_id = $1"
    ))
    .bind(artifact_id)
    .fetch_optional(&st.db)
    .await?)
}

/// The caller's own file, or 404 (also for other people's files).
async fn own_file(st: &AppState, me: &PersonalAccount, artifact_hex: &str) -> ApiResult<FileRow> {
    let id = parse_id(artifact_hex)?;
    file(st, &id)
        .await?
        .filter(|f| f.sender == me.org_id)
        .ok_or(ApiError::NotFound)
}

fn parse_id(h: &str) -> ApiResult<[u8; 16]> {
    let mut id = [0u8; 16];
    hex::decode_to_slice(h, &mut id).map_err(|_| bad("IDs are 32 hex characters"))?;
    Ok(id)
}

#[derive(FromRow)]
struct RecipientRow {
    recipient: String,
    revoked_at: Option<i64>,
}

#[derive(FromRow)]
struct ApprovalRow {
    request_id: Vec<u8>,
    artifact_id: Vec<u8>,
    requester: String,
    state: String,
    requested_at: i64,
    decided_at: Option<i64>,
    expires_at: i64,
    kind: String,
    used_at: Option<i64>,
    final_at: Option<i64>,
}

impl ApprovalRow {
    fn request_id(&self) -> [u8; 16] {
        self.request_id.as_slice().try_into().unwrap_or_default()
    }
}

#[derive(FromRow)]
struct OpenRow {
    first_released_at: i64,
    final_at: Option<i64>,
}

/// The requester's latest request of this kind (`open` or `share`).
async fn latest_request(
    st: &AppState,
    artifact_id: &[u8],
    requester: &str,
    kind: &str,
) -> ApiResult<Option<ApprovalRow>> {
    Ok(sqlx::query_as(
        "SELECT request_id, artifact_id, requester, state, requested_at, decided_at, expires_at, kind, \
         used_at, final_at FROM approvals WHERE artifact_id = $1 AND requester = $2 AND kind = $3 \
         ORDER BY requested_at DESC, request_id DESC LIMIT 1",
    )
    .bind(artifact_id)
    .bind(requester)
    .bind(kind)
    .fetch_optional(&st.db)
    .await?)
}

async fn latest_approval(
    st: &AppState,
    artifact_id: &[u8],
    requester: &str,
) -> ApiResult<Option<ApprovalRow>> {
    latest_request(st, artifact_id, requester, "open").await
}

/// Whether `requester` may save a view-only file as a normal file, from
/// the sender's decisions and the file's rules.
async fn share_state(
    st: &AppState,
    f: &FileRow,
    requester: &str,
    now: i64,
) -> ApiResult<(ShareState, Option<i64>)> {
    if !f.view_only {
        return Ok((ShareState::Unrestricted, None));
    }
    let latest = latest_request(st, &f.artifact_id, requester, "share").await?;
    Ok(match latest {
        Some(a) if a.state == "approved" => match a.decided_at {
            Some(d) if now - d <= SHARE_TTL_SECS => {
                (ShareState::Approved, Some(d + SHARE_TTL_SECS))
            }
            _ => fresh_share_state(f),
        },
        Some(a)
            if a.state == "declined" && a.decided_at.is_some_and(|d| now - d <= SHARE_TTL_SECS) =>
        {
            (ShareState::Declined, None)
        }
        Some(a) if a.state == "pending" && a.expires_at > now => {
            (ShareState::Pending, Some(a.expires_at))
        }
        _ => fresh_share_state(f),
    })
}

fn fresh_share_state(f: &FileRow) -> (ShareState, Option<i64>) {
    if f.allow_share_requests {
        (ShareState::NotRequested, None)
    } else {
        (ShareState::Forbidden, None)
    }
}

async fn open_row(
    st: &AppState,
    artifact_id: &[u8],
    recipient: &str,
) -> ApiResult<Option<OpenRow>> {
    Ok(sqlx::query_as(
        "SELECT first_released_at, final_at FROM opens WHERE artifact_id = $1 AND recipient = $2",
    )
    .bind(artifact_id)
    .bind(recipient)
    .fetch_optional(&st.db)
    .await?)
}

/// Whether a one-time open is used up at `now`.
fn used_up(o: &OpenRow, now: i64) -> bool {
    o.final_at.is_some() || now - o.first_released_at > ONE_TIME_RETRY_SECS
}

async fn recipient_state(
    st: &AppState,
    f: &FileRow,
    recipient: &str,
    revoked_at: Option<i64>,
    now: i64,
) -> ApiResult<(RecipientState, Option<i64>, Option<i64>)> {
    let open = open_row(st, &f.artifact_id, recipient).await?;
    let approval = latest_approval(st, &f.artifact_id, recipient).await?;
    let requested_at = approval.as_ref().map(|a| a.requested_at);
    let opened_at = open.as_ref().map(|o| o.first_released_at);
    let state = if revoked_at.is_some() || f.revoked_at.is_some() {
        RecipientState::Revoked
    } else if open.is_some() {
        RecipientState::Opened
    } else {
        match approval {
            Some(a) if a.state == "pending" && a.expires_at > now => RecipientState::Requested,
            Some(a) if a.state == "approved" => RecipientState::Approved,
            Some(a) if a.state == "declined" => RecipientState::Declined,
            _ => RecipientState::NotOpened,
        }
    };
    Ok((state, requested_at, opened_at))
}

async fn file_status(st: &AppState, f: &FileRow) -> ApiResult<FileStatus> {
    let now = unix_now();
    let rows: Vec<RecipientRow> = sqlx::query_as(
        "SELECT recipient, revoked_at FROM personal_file_recipients \
         WHERE artifact_id = $1 ORDER BY position",
    )
    .bind(&f.artifact_id)
    .fetch_all(&st.db)
    .await?;
    let mut recipients = Vec::with_capacity(rows.len());
    for r in rows {
        let (state, requested_at, opened_at) =
            recipient_state(st, f, &r.recipient, r.revoked_at, now).await?;
        recipients.push(RecipientStatus {
            email: email_of(st, &r.recipient).await?,
            account: r.recipient,
            state,
            requested_at,
            opened_at,
        });
    }
    Ok(FileStatus {
        artifact_id: f.id(),
        sender_email: email_of(st, &f.sender).await?,
        sender: f.sender.clone(),
        created_at: f.created_at,
        signed_expires_at: f.signed_expires_at,
        rules: f.rules(),
        signed_view_only: f.signed_view_only,
        revoked_at: f.revoked_at,
        recipients,
    })
}

fn check_rules(rules: &FileRules, signed_expires_at: Option<i64>) -> ApiResult<()> {
    if let (Some(e), Some(s)) = (rules.expires_at, signed_expires_at)
        && e > s
    {
        return Err(bad(
            "the expiry can't be later than the one signed into the file",
        ));
    }
    Ok(())
}

/// `POST /v1/me/files`: register a file the caller just made. Personal
/// files can only be opened once registered.
pub async fn register_file(
    State(st): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<FileStatus>> {
    let me = authenticate(&st, &method, &uri, &headers, &body).await?;
    let lim = st.limits.files_per_account_per_day;
    if !account_allows(&st, &me.org_id, "files", lim, DAY) {
        return Err(ApiError::TooMany(TOO_MANY_ACCOUNT.into()));
    }
    let req: RegisterFileRequest =
        serde_json::from_slice(&body).map_err(|e| bad(&format!("invalid request: {e}")))?;
    let head = verified_head(&st, &req.header_region, &req.trailer).await?;
    let h = &head.header;
    if h.sender_org.as_str() != me.org_id {
        return Err(bad("this file was made by another account"));
    }
    check_rules(&req.rules, h.expires_at)?;
    // The sender's choice is signed into the file; the rule starts out the
    // same (the sender can relax it later).
    if req.rules.view_only != h.view_only {
        return Err(bad(if h.view_only {
            "this file is view-only: register it with the view-only rule"
        } else {
            "the view-only rule needs a file made view-only"
        }));
    }
    let recipients = h.all_recipients();
    for r in recipients {
        if account_by_org(&st, r.as_str()).await?.is_none() {
            return Err(bad(&format!("{r} is not a personal account")));
        }
    }
    let now = unix_now();
    let mut tx = st.db.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO personal_files (artifact_id, sender, header_hash, created_at, signed_expires_at, \
         require_approval, one_time, expires_at, revoked_at, registered_at, view_only, allow_share_requests, \
         signed_view_only) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, $9, $10, $11, $10)",
    )
    .bind(&h.artifact_id[..])
    .bind(&me.org_id)
    .bind(head.header_hash().as_bytes())
    .bind(h.created_at)
    .bind(h.expires_at)
    .bind(req.rules.require_approval)
    .bind(req.rules.one_time)
    .bind(req.rules.expires_at)
    .bind(now)
    .bind(req.rules.view_only)
    .bind(req.rules.allow_share_requests && req.rules.view_only)
    .execute(&mut *tx)
    .await;
    match inserted {
        Ok(_) => {}
        Err(e) if is_unique_violation(&e) => {
            return Err(ApiError::Conflict("this file is already registered".into()));
        }
        Err(e) => return Err(e.into()),
    }
    for (i, r) in recipients.iter().enumerate() {
        sqlx::query(
            "INSERT INTO personal_file_recipients (artifact_id, recipient, position) VALUES ($1, $2, $3)",
        )
        .bind(&h.artifact_id[..])
        .bind(r.as_str())
        .bind(i as i32)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    let aid = hex::encode(h.artifact_id);
    audit::append(
        &st.db,
        &me.org_id,
        audit::Record {
            event: audit::event::ARTIFACT_REGISTERED,
            artifact_id: Some(aid),
            reason: Some(format!(
                "{} recipient(s); approval {}, one-time {}, view-only {}",
                recipients.len(),
                on_off(req.rules.require_approval),
                on_off(req.rules.one_time),
                on_off(req.rules.view_only)
            )),
            ..Default::default()
        },
    )
    .await?;
    let f = file(&st, &h.artifact_id).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(file_status(&st, &f).await?))
}

fn on_off(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}

/// `GET /v1/me/files/{artifact_id}` (sender only).
pub async fn get_file(
    State(st): State<AppState>,
    Path(artifact_hex): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> ApiResult<Json<FileStatus>> {
    let me = authenticate(&st, &method, &uri, &headers, b"").await?;
    let f = own_file(&st, &me, &artifact_hex).await?;
    Ok(Json(file_status(&st, &f).await?))
}

/// `PATCH /v1/me/files/{artifact_id}`: change rules or revoke (sender only).
pub async fn update_file(
    State(st): State<AppState>,
    Path(artifact_hex): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<FileStatus>> {
    let me = authenticate(&st, &method, &uri, &headers, &body).await?;
    let req: UpdateFileRequest =
        serde_json::from_slice(&body).map_err(|e| bad(&format!("invalid request: {e}")))?;
    let f = own_file(&st, &me, &artifact_hex).await?;
    let mut rules = f.rules();
    if let Some(v) = req.require_approval {
        rules.require_approval = v;
    }
    if let Some(v) = req.one_time {
        rules.one_time = v;
    }
    if req.expires_at.is_some() {
        rules.expires_at = req.expires_at;
    }
    if let Some(v) = req.view_only {
        // Only a file made view-only holds what the viewer shows.
        if v && !f.signed_view_only {
            return Err(bad(
                "only a file sent as view-only can be view-only: send it again with view-only on",
            ));
        }
        rules.view_only = v;
    }
    if let Some(v) = req.allow_share_requests {
        rules.allow_share_requests = v;
    }
    // Share requests only mean something for a view-only file.
    rules.allow_share_requests &= rules.view_only;
    check_rules(&rules, f.signed_expires_at)?;
    let now = unix_now();
    let mut tx = st.db.begin().await?;
    sqlx::query(
        "UPDATE personal_files SET require_approval = $2, one_time = $3, expires_at = $4, \
         view_only = $7, allow_share_requests = $8, \
         revoked_at = CASE WHEN $5 THEN COALESCE(revoked_at, $6) ELSE revoked_at END \
         WHERE artifact_id = $1",
    )
    .bind(&f.artifact_id)
    .bind(rules.require_approval)
    .bind(rules.one_time)
    .bind(rules.expires_at)
    .bind(req.revoke)
    .bind(now)
    .bind(rules.view_only)
    .bind(rules.allow_share_requests)
    .execute(&mut *tx)
    .await?;
    for r in &req.revoke_recipients {
        let n = sqlx::query(
            "UPDATE personal_file_recipients SET revoked_at = COALESCE(revoked_at, $3) \
             WHERE artifact_id = $1 AND recipient = $2",
        )
        .bind(&f.artifact_id)
        .bind(r)
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(bad(&format!("{r} is not a recipient of this file")));
        }
    }
    tx.commit().await?;
    let event = if req.revoke || !req.revoke_recipients.is_empty() {
        audit::event::ARTIFACT_REVOKED
    } else {
        audit::event::POLICY_CHANGED
    };
    audit::append(
        &st.db,
        &me.org_id,
        audit::Record {
            event,
            artifact_id: Some(hex::encode(f.id())),
            reason: Some(if req.revoke {
                "file revoked".into()
            } else if !req.revoke_recipients.is_empty() {
                format!("revoked for {}", req.revoke_recipients.join(", "))
            } else {
                format!(
                    "approval {}, one-time {}, expiry {:?}, view-only {}, share requests {}",
                    on_off(rules.require_approval),
                    on_off(rules.one_time),
                    rules.expires_at,
                    on_off(rules.view_only),
                    on_off(rules.allow_share_requests)
                )
            }),
            ..Default::default()
        },
    )
    .await?;
    let f = file(&st, &f.artifact_id).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(file_status(&st, &f).await?))
}

// ----- Opening -----

/// Record a refusal in the recipient's audit trail and return it.
async fn refuse(
    st: &AppState,
    me: &PersonalAccount,
    aid: &str,
    event: &str,
    reason: &str,
    r: DenyReason,
) -> ApiError {
    audit::note(
        &st.db,
        &me.org_id,
        audit::Record {
            event,
            artifact_id: Some(aid.to_owned()),
            reason: Some(reason.to_owned()),
            ..Default::default()
        },
    )
    .await;
    deny(r)
}

/// `POST /v1/personal/release`: ask to open a file. Repeat the same request
/// (same one-time key and transaction) to poll while the sender decides.
///
/// Checks, in order: the signed file and its registration, that the caller
/// is a recipient, revocation, expiry, one-time use, the sender's approval,
/// a single-use transaction. Only then is the service's half of the key
/// released, sealed to the caller's one-time MLKEM1024-P384 key.
pub async fn release(
    State(st): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<PersonalReleaseResponse>> {
    // Release errors carry no detail.
    let me = authenticate(&st, &method, &uri, &headers, &body)
        .await
        .map_err(quiet)?;
    let lim = st.limits.releases_per_account_per_min;
    if !account_allows(&st, &me.org_id, "release", lim, MINUTE) {
        return Err(deny(DenyReason::Unavailable));
    }
    let req: PersonalReleaseRequest =
        serde_json::from_slice(&body).map_err(|_| deny(DenyReason::InvalidRequest))?;
    let client_key = parse_client_key(&req.client_key).ok_or(deny(DenyReason::InvalidRequest))?;
    let head = verified_head(&st, &req.header_region, &req.trailer).await?;
    let h = &head.header;
    let aid = hex::encode(h.artifact_id);
    let now = unix_now();

    // 1. A registered personal file, exactly this one.
    let Some(f) = file(&st, &h.artifact_id).await? else {
        return Err(refuse(
            &st,
            &me,
            &aid,
            audit::event::AUTHZ_FAILURE,
            "file not registered",
            DenyReason::InvalidArtifact,
        )
        .await);
    };
    if f.header_hash != head.header_hash().as_bytes() || f.sender != h.sender_org.as_str() {
        return Err(deny(DenyReason::InvalidArtifact));
    }
    // 2. The caller is named in the signed header and registered as a recipient.
    let named = h.all_recipients().iter().any(|r| r.as_str() == me.org_id);
    let row: Option<RecipientRow> = sqlx::query_as(
        "SELECT recipient, revoked_at FROM personal_file_recipients WHERE artifact_id = $1 AND recipient = $2",
    )
    .bind(&f.artifact_id)
    .bind(&me.org_id)
    .fetch_optional(&st.db)
    .await?;
    let Some(row) = row.filter(|_| named) else {
        return Err(refuse(
            &st,
            &me,
            &aid,
            audit::event::AUTHZ_FAILURE,
            "not a recipient",
            DenyReason::NotAuthorized,
        )
        .await);
    };
    // 3. Revocation (the whole file, or this recipient).
    if f.revoked_at.is_some() || row.revoked_at.is_some() {
        return Err(refuse(
            &st,
            &me,
            &aid,
            audit::event::REVOKED_ACCESS,
            "revoked by the sender",
            DenyReason::ExpiredOrRevoked,
        )
        .await);
    }
    // 4. Expiry (server clock).
    if f.effective_expiry().is_some_and(|e| now >= e) {
        return Err(refuse(
            &st,
            &me,
            &aid,
            audit::event::ARTIFACT_EXPIRED,
            "expired",
            DenyReason::ExpiredOrRevoked,
        )
        .await);
    }
    // 5. One-time: a short retry window after the first release. A copy the
    //    sender approved is the exception: saving a view-only file with a
    //    valid approved share request works once (with the same retry
    //    window) even after the single view, because the sender could
    //    equally have switched one-time off.
    let approved_copy = if req.mode == ReleaseMode::Save && f.view_only {
        latest_request(&st, &f.artifact_id, &me.org_id, "share")
            .await?
            .filter(|a| {
                a.state == "approved" && a.decided_at.is_some_and(|d| now - d <= SHARE_TTL_SECS)
            })
    } else {
        None
    };
    let mut share_grant = false;
    if f.one_time
        && let Some(o) = open_row(&st, &f.artifact_id, &me.org_id).await?
        && used_up(&o, now)
    {
        // Unspent: no save yet, or a save still in its retry window
        // without a receipt.
        let unspent = approved_copy.as_ref().is_some_and(|a| match a.used_at {
            None => true,
            Some(u) => a.final_at.is_none() && now - u <= ONE_TIME_RETRY_SECS,
        });
        if unspent {
            share_grant = true;
        } else {
            return Err(refuse(
                &st,
                &me,
                &aid,
                audit::event::AUTHZ_FAILURE,
                "one-time file already opened",
                DenyReason::AlreadyOpened,
            )
            .await);
        }
    }
    // 6. A view-only file can be shown in the app, but saved only with the
    //    sender's permission. Refused before anything is used up.
    if req.mode == ReleaseMode::Save
        && !matches!(
            share_state(&st, &f, &me.org_id, now).await?.0,
            ShareState::Unrestricted | ShareState::Approved
        )
    {
        return Err(refuse(
            &st,
            &me,
            &aid,
            audit::event::AUTHZ_FAILURE,
            "view-only file: saving needs the sender's permission",
            DenyReason::ViewOnly,
        )
        .await);
    }
    // 7. The sender's approval.
    if f.require_approval {
        let latest = latest_approval(&st, &f.artifact_id, &me.org_id).await?;
        match latest {
            Some(a)
                if a.state == "approved"
                    && a.decided_at.is_some_and(|d| now - d <= APPROVAL_TTL_SECS) => {}
            Some(a)
                if a.state == "declined"
                    && a.decided_at.is_some_and(|d| now - d <= APPROVAL_TTL_SECS) =>
            {
                return Err(deny(DenyReason::Declined));
            }
            Some(a) if a.state == "pending" && a.expires_at > now => {
                return Ok(Json(PersonalReleaseResponse::Pending {
                    request_id: a.request_id(),
                    sender_email: email_of(&st, &f.sender).await?,
                    expires_at: a.expires_at,
                }));
            }
            _ => return Ok(Json(request_approval(&st, &me, &f).await?)),
        }
    }
    // 8. Single-use transaction.
    match sqlx::query(
        "INSERT INTO release_txns (txn, artifact_id, org_id, at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&req.txn[..])
    .bind(&h.artifact_id[..])
    .bind(&me.org_id)
    .bind(now)
    .execute(&st.db)
    .await
    {
        Ok(_) => {}
        Err(e) if is_unique_violation(&e) => {
            return Err(refuse(
                &st,
                &me,
                &aid,
                audit::event::REPLAY,
                "transaction id reused",
                DenyReason::NotAuthorized,
            )
            .await);
        }
        Err(e) => return Err(e.into()),
    }
    // A save while a copy is approved uses that approval (whichever rule
    // allowed it); the first one starts its retry window.
    if let Some(a) = &approved_copy {
        sqlx::query("UPDATE approvals SET used_at = $2 WHERE request_id = $1 AND used_at IS NULL")
            .bind(&a.request_id)
            .bind(now)
            .execute(&st.db)
            .await?;
    }
    // 9. Release the service half, sealed to the one-time key.
    let share = st.keys.unwrap_service_share(&head).map_err(|e| {
        tracing::error!(error = %e, artifact = %aid, "service share unwrap failed");
        deny(DenyReason::InvalidArtifact)
    })?;
    let (encapped_key, ciphertext) = seal_released_share(
        EnvelopeRole::Service,
        &share,
        &client_key,
        &h.artifact_id,
        &req.txn,
        &mut os_rng(),
    )
    .map_err(|e| ApiError::Internal(e.to_string()))?;
    drop(share);
    sqlx::query(
        "INSERT INTO opens (artifact_id, recipient, first_released_at, last_released_at) \
         VALUES ($1, $2, $3, $3) ON CONFLICT (artifact_id, recipient) \
         DO UPDATE SET last_released_at = EXCLUDED.last_released_at",
    )
    .bind(&f.artifact_id)
    .bind(&me.org_id)
    .bind(now)
    .execute(&st.db)
    .await?;
    // Fail closed: no release without an audit record.
    let txn_hex = hex::encode(req.txn);
    audit::append(
        &st.db,
        &me.org_id,
        audit::Record {
            event: audit::event::DECRYPTION_AUTHORIZED,
            artifact_id: Some(aid.clone()),
            txn: Some(txn_hex.clone()),
            reason: Some(format!(
                "from {}; {}",
                f.sender,
                match (req.mode, share_grant) {
                    (ReleaseMode::Save, true) => "to save, with the sender's approved copy",
                    (ReleaseMode::Save, false) => "to save",
                    (ReleaseMode::View, _) => "to view",
                }
            )),
            ..Default::default()
        },
    )
    .await?;
    audit::note(
        &st.db,
        &f.sender,
        audit::Record {
            event: audit::event::DECRYPTION_AUTHORIZED,
            artifact_id: Some(aid),
            txn: Some(txn_hex),
            reason: Some(format!("opened by {}", me.org_id)),
            ..Default::default()
        },
    )
    .await;
    Ok(Json(PersonalReleaseResponse::Released {
        share: SealedShare {
            encapped_key,
            ciphertext,
        },
        view_only: f.view_only,
    }))
}

/// Create a pending request and tell the sender.
async fn request_approval(
    st: &AppState,
    me: &PersonalAccount,
    f: &FileRow,
) -> ApiResult<PersonalReleaseResponse> {
    let now = unix_now();
    let request_id = random_bytes::<16>();
    let expires_at = now + APPROVAL_TTL_SECS;
    sqlx::query(
        "INSERT INTO approvals (request_id, artifact_id, requester, state, requested_at, expires_at) \
         VALUES ($1, $2, $3, 'pending', $4, $5)",
    )
    .bind(&request_id[..])
    .bind(&f.artifact_id)
    .bind(&me.org_id)
    .bind(now)
    .bind(expires_at)
    .execute(&st.db)
    .await?;
    let aid = hex::encode(f.id());
    audit::append(
        &st.db,
        &f.sender,
        audit::Record {
            event: audit::event::APPROVAL_REQUESTED,
            artifact_id: Some(aid.clone()),
            reason: Some(format!("{} ({})", me.email, me.org_id)),
            ..Default::default()
        },
    )
    .await?;
    if let Some(to) = email_of(st, &f.sender).await? {
        notify::queue(
            st,
            &format!("approval:{aid}:{}:{}", me.org_id, now / 3600),
            Email {
                to,
                subject: format!("{} is asking to open a file you sent", me.email),
                body: format!(
                    "{} is asking to open a file you sent with Secure Verified Exchange.\n\n\
                     Open the app and go to Requests to approve or decline. If you weren't \
                     expecting this, check with them first (by phone or another channel) \
                     before you approve.\n\nFile ID: {aid}\n",
                    me.email
                ),
            },
        )
        .await;
    }
    Ok(PersonalReleaseResponse::Pending {
        request_id,
        sender_email: email_of(st, &f.sender).await?,
        expires_at,
    })
}

/// `POST /v1/personal/opened`: decryption finished; a one-time open is now
/// final.
pub async fn opened(
    State(st): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    let me = authenticate(&st, &method, &uri, &headers, &body)
        .await
        .map_err(quiet)?;
    let r: OpenedReceipt =
        serde_json::from_slice(&body).map_err(|e| bad(&format!("invalid request: {e}")))?;
    sqlx::query(
        "UPDATE opens SET final_at = COALESCE(final_at, $3) WHERE artifact_id = $1 AND recipient = $2",
    )
    .bind(&r.artifact_id[..])
    .bind(&me.org_id)
    .bind(unix_now())
    .execute(&st.db)
    .await?;
    // A save under an approved copy is now done: the approval is spent.
    sqlx::query(
        "UPDATE approvals SET final_at = COALESCE(final_at, $3) \
         WHERE artifact_id = $1 AND requester = $2 AND kind = 'share' AND state = 'approved' \
         AND used_at IS NOT NULL",
    )
    .bind(&r.artifact_id[..])
    .bind(&me.org_id)
    .bind(unix_now())
    .execute(&st.db)
    .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ----- Sender's decisions -----

fn approval_wire(a: &ApprovalRow, email: Option<String>) -> ApprovalRequest {
    ApprovalRequest {
        kind: if a.kind == "share" {
            RequestKind::Share
        } else {
            RequestKind::Open
        },
        request_id: a.request_id(),
        artifact_id: a.artifact_id.as_slice().try_into().unwrap_or_default(),
        requester: a.requester.clone(),
        requester_email: email,
        requested_at: a.requested_at,
        expires_at: a.expires_at,
    }
}

/// `GET /v1/me/requests`: requests waiting for the caller's decision.
pub async fn requests(
    State(st): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<ApprovalRequest>>> {
    let me = authenticate(&st, &method, &uri, &headers, b"").await?;
    let rows: Vec<ApprovalRow> = sqlx::query_as(
        "SELECT a.request_id, a.artifact_id, a.requester, a.state, a.requested_at, a.decided_at, a.expires_at, a.kind, \
         a.used_at, a.final_at \
         FROM approvals a JOIN personal_files f ON f.artifact_id = a.artifact_id \
         WHERE f.sender = $1 AND a.state = 'pending' AND a.expires_at > $2 \
         ORDER BY a.requested_at DESC LIMIT 200",
    )
    .bind(&me.org_id)
    .bind(unix_now())
    .fetch_all(&st.db)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for a in &rows {
        out.push(approval_wire(a, email_of(&st, &a.requester).await?));
    }
    Ok(Json(out))
}

/// `POST /v1/me/requests/{request_id}/approve` or `/decline`.
pub async fn decide(
    State(st): State<AppState>,
    Path((request_hex, decision)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<ApprovalRequest>> {
    let me = authenticate(&st, &method, &uri, &headers, &body).await?;
    let state = match decision.as_str() {
        "approve" => "approved",
        "decline" => "declined",
        _ => return Err(ApiError::NotFound),
    };
    let id = parse_id(&request_hex)?;
    let now = unix_now();
    let row: Option<ApprovalRow> = sqlx::query_as(
        "UPDATE approvals a SET state = $3, decided_at = $4 FROM personal_files f \
         WHERE a.request_id = $1 AND f.artifact_id = a.artifact_id AND f.sender = $2 \
           AND a.state = 'pending' AND a.expires_at > $4 \
         RETURNING a.request_id, a.artifact_id, a.requester, a.state, a.requested_at, a.decided_at, a.expires_at, a.kind, \
         a.used_at, a.final_at",
    )
    .bind(&id[..])
    .bind(&me.org_id)
    .bind(state)
    .bind(now)
    .fetch_optional(&st.db)
    .await?;
    let a = row.ok_or_else(|| {
        ApiError::Conflict("this request is no longer waiting for a decision".into())
    })?;
    audit::append(
        &st.db,
        &me.org_id,
        audit::Record {
            event: match (a.kind.as_str(), state) {
                ("share", "approved") => audit::event::SHARE_GRANTED,
                ("share", _) => audit::event::SHARE_DECLINED,
                (_, "approved") => audit::event::APPROVAL_GRANTED,
                _ => audit::event::APPROVAL_DECLINED,
            },
            artifact_id: Some(hex::encode(&a.artifact_id)),
            reason: Some(format!("for {}", a.requester)),
            ..Default::default()
        },
    )
    .await?;
    let email = email_of(&st, &a.requester).await?;
    Ok(Json(approval_wire(&a, email)))
}

// ----- Saving a view-only file -----

/// The caller's file as a recipient: registered, named, not revoked, not
/// expired. Anything else is refused the same way as a release would.
async fn received_file(
    st: &AppState,
    me: &PersonalAccount,
    artifact_hex: &str,
) -> ApiResult<FileRow> {
    let id = parse_id(artifact_hex)?;
    let f = file(st, &id).await?.ok_or(ApiError::NotFound)?;
    let row: Option<RecipientRow> = sqlx::query_as(
        "SELECT recipient, revoked_at FROM personal_file_recipients WHERE artifact_id = $1 AND recipient = $2",
    )
    .bind(&f.artifact_id)
    .bind(&me.org_id)
    .fetch_optional(&st.db)
    .await?;
    let Some(row) = row else {
        return Err(ApiError::NotFound);
    };
    if f.revoked_at.is_some()
        || row.revoked_at.is_some()
        || f.effective_expiry().is_some_and(|e| unix_now() >= e)
    {
        return Err(deny(DenyReason::ExpiredOrRevoked));
    }
    Ok(f)
}

fn share_status(f: &FileRow, state: (ShareState, Option<i64>)) -> ShareStatus {
    ShareStatus {
        artifact_id: f.id(),
        state: state.0,
        expires_at: state.1,
    }
}

/// `GET /v1/personal/share/{artifact_id}`: may the caller save this file?
pub async fn share_get(
    State(st): State<AppState>,
    Path(artifact_hex): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> ApiResult<Json<ShareStatus>> {
    let me = authenticate(&st, &method, &uri, &headers, b"").await?;
    let f = received_file(&st, &me, &artifact_hex).await?;
    let state = share_state(&st, &f, &me.org_id, unix_now()).await?;
    Ok(Json(share_status(&f, state)))
}

/// `POST /v1/personal/share/{artifact_id}`: ask the sender to let the caller
/// save a view-only file. Only one request waits at a time, and a decline
/// stands for 24 hours, so a sender can't be badgered.
pub async fn share_request(
    State(st): State<AppState>,
    Path(artifact_hex): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<ShareStatus>> {
    let me = authenticate(&st, &method, &uri, &headers, &body).await?;
    let lim = st.limits.shares_per_account_per_hour;
    if !account_allows(&st, &me.org_id, "share", lim, HOUR) {
        return Err(ApiError::TooMany(TOO_MANY_ACCOUNT.into()));
    }
    let f = received_file(&st, &me, &artifact_hex).await?;
    let now = unix_now();
    let state = share_state(&st, &f, &me.org_id, now).await?;
    match state.0 {
        ShareState::NotRequested => {}
        ShareState::Forbidden => return Err(deny(DenyReason::NotAuthorized)),
        // Already decided, waiting, or nothing to ask: say where things stand.
        _ => return Ok(Json(share_status(&f, state))),
    }
    let request_id = random_bytes::<16>();
    let expires_at = now + APPROVAL_TTL_SECS;
    sqlx::query(
        "INSERT INTO approvals (request_id, artifact_id, requester, state, requested_at, expires_at, kind) \
         VALUES ($1, $2, $3, 'pending', $4, $5, 'share')",
    )
    .bind(&request_id[..])
    .bind(&f.artifact_id)
    .bind(&me.org_id)
    .bind(now)
    .bind(expires_at)
    .execute(&st.db)
    .await?;
    let aid = hex::encode(f.id());
    audit::append(
        &st.db,
        &f.sender,
        audit::Record {
            event: audit::event::SHARE_REQUESTED,
            artifact_id: Some(aid.clone()),
            reason: Some(format!("{} ({})", me.email, me.org_id)),
            ..Default::default()
        },
    )
    .await?;
    if let Some(to) = email_of(&st, &f.sender).await? {
        notify::queue(
            &st,
            &format!("share:{aid}:{}:{}", me.org_id, now / 3600),
            Email {
                to,
                subject: format!("{} is asking to keep a file you sent", me.email),
                body: format!(
                    "{} is asking for permission to save a view-only file you sent with \
                     Secure Verified Exchange as a normal file. Once saved, it can be \
                     copied and shared.\n\nOpen the app and go to Requests to approve or \
                     decline. If you weren't expecting this, check with them first (by phone \
                     or another channel).\n\nFile ID: {aid}\n",
                    me.email
                ),
            },
        )
        .await;
    }
    Ok(Json(share_status(
        &f,
        (ShareState::Pending, Some(expires_at)),
    )))
}

/// `GET /v1/me/history`: files the caller sent and files sent to them,
/// newest first.
pub async fn history(
    State(st): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> ApiResult<Json<History>> {
    let me = authenticate(&st, &method, &uri, &headers, b"").await?;
    let now = unix_now();
    let sent: Vec<FileRow> = sqlx::query_as(&format!(
        "SELECT {FILE_COLUMNS} FROM personal_files WHERE sender = $1 \
         ORDER BY created_at DESC, artifact_id LIMIT 200"
    ))
    .bind(&me.org_id)
    .fetch_all(&st.db)
    .await?;
    let mut out = History::default();
    for f in &sent {
        out.sent.push(file_status(&st, f).await?);
    }
    let received: Vec<FileRow> = sqlx::query_as(&format!(
        "SELECT f.{} FROM personal_files f JOIN personal_file_recipients r ON r.artifact_id = f.artifact_id \
         WHERE r.recipient = $1 ORDER BY f.created_at DESC, f.artifact_id LIMIT 200",
        FILE_COLUMNS.replace(", ", ", f.")
    ))
    .bind(&me.org_id)
    .fetch_all(&st.db)
    .await?;
    for f in &received {
        let revoked: Option<i64> = sqlx::query_scalar(
            "SELECT revoked_at FROM personal_file_recipients WHERE artifact_id = $1 AND recipient = $2",
        )
        .bind(&f.artifact_id)
        .bind(&me.org_id)
        .fetch_one(&st.db)
        .await?;
        let (state, requested_at, opened_at) =
            recipient_state(&st, f, &me.org_id, revoked, now).await?;
        out.received.push(ReceivedFile {
            artifact_id: f.id(),
            sender_email: email_of(&st, &f.sender).await?,
            sender: f.sender.clone(),
            created_at: f.created_at,
            state,
            requested_at,
            opened_at,
            view_only: f.view_only,
        });
    }
    Ok(Json(out))
}
