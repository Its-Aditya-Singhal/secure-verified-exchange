//! Email + password accounts (`svx:email`): emailed codes, sign-up and
//! sign-in on a new device, forgotten and changed passwords.
//!
//! Every step that binds keys to an account needs a fresh code sent to the
//! address (proof that the person reads that inbox) and, for an existing
//! account, the password. Codes are six digits, stored only as a hash, used
//! once, valid for ten minutes and allow five tries. Wrong passwords lock
//! the account for a while. Code requests answer the same whether or not
//! an account exists.

use std::sync::LazyLock;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, Method, Uri};
use sha2::{Digest, Sha256};
use svx_core::crypto::{
    KemPublicKey, KeyKind, VerifyingKey, hash_password, needs_rehash, random_bytes, verify_password,
};
use svx_protocol::email_account::{
    ChangePasswordRequest, CodePurpose, EMAIL_ISSUER, EmailAccountRequest, EmailCodeRequest,
    EmailCodeResponse, KeyMode, PasswordResetRequest, password_strength, valid_code, valid_name,
};
use svx_protocol::personal::Account;
use svx_protocol::unix_now;
use tokio::sync::Semaphore;

use super::personal::{Existing, Identity, authenticate, bind_device, valid_email};
use crate::error::{ApiError, ApiResult};
use crate::limits::{ClientIp, HOUR, MailKind, check_ip, email_budget};
use crate::notify::Email;
use crate::{AppState, audit};

/// How long a code is valid.
pub const CODE_TTL_SECS: i64 = 600;
/// Tries per code (right or wrong).
pub const CODE_TRIES: i32 = 5;
/// Codes per address per hour, and the least time between two.
pub const CODES_PER_HOUR: i64 = 5;
pub const CODE_INTERVAL_SECS: i64 = 30;
/// Codes the whole service sends per minute (protects the mail account).
const CODES_PER_MINUTE: u32 = 120;
/// Wrong passwords in a row before the account is locked, and for how long.
pub const MAX_FAILED_PASSWORDS: i32 = 10;
pub const LOCK_SECS: i64 = 900;

/// The sign-in "client ID" recorded for email accounts.
const CLIENT_ID: &str = "svx";
const WRONG_CODE: &str = "the code is wrong or has expired: ask for a new one";
const WRONG_LOGIN: &str = "wrong email address, password or code";

/// Argon2id hashes use 64 MiB each: only a few at a time.
static HASHING: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(4));

fn bad(msg: &str) -> ApiError {
    ApiError::BadRequest(msg.into())
}

fn code_hash(challenge: &[u8; 16], code: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SVX email code\0");
    h.update(challenge);
    h.update(code.as_bytes());
    h.finalize().into()
}

/// A uniformly random six-digit code.
fn new_code() -> String {
    loop {
        let n = u32::from_le_bytes(random_bytes::<4>());
        // Reject the top sliver so every code is equally likely.
        if n < u32::MAX - (u32::MAX % 1_000_000) {
            return format!("{:06}", n % 1_000_000);
        }
    }
}

fn normalize(email: &str) -> ApiResult<(String, String)> {
    let e = email.trim();
    if !valid_email(e) {
        return Err(bad("enter a valid email address"));
    }
    Ok((e.to_owned(), e.to_lowercase()))
}

async fn email_account_org(st: &AppState, email_lc: &str) -> ApiResult<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT p.org_id FROM personal_accounts p JOIN email_accounts e USING (org_id) \
         WHERE p.issuer = $1 AND p.subject = $2",
    )
    .bind(EMAIL_ISSUER)
    .bind(email_lc)
    .fetch_optional(&st.db)
    .await?)
}

/// `POST /v1/auth/email/code`
pub async fn send_code(
    State(st): State<AppState>,
    ip: Option<Extension<ClientIp>>,
    Json(req): Json<EmailCodeRequest>,
) -> ApiResult<Json<EmailCodeResponse>> {
    let (email, email_lc) = normalize(&req.email)?;
    let now = unix_now();
    let lim = st.limits.codes_per_ip_per_hour;
    check_ip(&st, ip.map(|e| e.0), "codes", lim, HOUR)?;
    if !st.limiter.allow("email-codes", CODES_PER_MINUTE) {
        return Err(ApiError::Conflict(
            "the service is busy; try again in a minute".into(),
        ));
    }
    sqlx::query("DELETE FROM email_challenges WHERE created_at < $1")
        .bind(now - 24 * 3600)
        .execute(&st.db)
        .await?;
    let (recent, last): (i64, Option<i64>) = sqlx::query_as(
        "SELECT count(*), max(created_at) FROM email_challenges \
         WHERE email_lc = $1 AND created_at > $2",
    )
    .bind(&email_lc)
    .bind(now - 3600)
    .fetch_one(&st.db)
    .await?;
    if recent >= CODES_PER_HOUR {
        return Err(ApiError::Conflict(
            "too many codes for this address; try again later".into(),
        ));
    }
    if last.is_some_and(|t| now - t < CODE_INTERVAL_SECS) {
        return Err(ApiError::Conflict(
            "a code was just sent; wait half a minute before asking again".into(),
        ));
    }
    // Counted whether or not this address gets the email, so the answer
    // still doesn't tell who has an account.
    if !email_budget(&st, MailKind::Code).await {
        return Err(ApiError::TooMany(
            "the service has sent too many emails today; try again tomorrow".into(),
        ));
    }
    let challenge = random_bytes::<16>();
    let code = new_code();
    let expires_at = now + CODE_TTL_SECS;
    sqlx::query(
        "INSERT INTO email_challenges (challenge, email_lc, purpose, code_hash, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&challenge[..])
    .bind(&email_lc)
    .bind(req.purpose.as_str())
    .bind(&code_hash(&challenge, &code)[..])
    .bind(now)
    .bind(expires_at)
    .execute(&st.db)
    .await?;
    // Signing in or resetting a password only makes sense for an email
    // account; for other addresses nothing is sent, but the answer is the
    // same, so it doesn't tell who has an account.
    let send = match req.purpose {
        CodePurpose::SignUp => true,
        CodePurpose::SignIn | CodePurpose::ResetPassword => {
            email_account_org(&st, &email_lc).await?.is_some()
        }
    };
    if send {
        let what = match req.purpose {
            CodePurpose::SignUp => "create your account",
            CodePurpose::SignIn => "sign in on a new device",
            CodePurpose::ResetPassword => "choose a new password",
        };
        // Not through `notify::queue`: that keeps a copy of every email,
        // and a code must not be stored anywhere in clear.
        st.notifier.deliver(Email {
            html: None,
            to: email,
            subject: format!("{code} is your Secure Verified Exchange code"),
            body: format!(
                "Your code to {what} is {code}.\n\n\
                 Type it in the Secure Verified Exchange app. It works once and \
                 expires in 10 minutes.\n\n\
                 If you didn't ask for it, you can ignore this email: nobody can \
                 use your address without the code.\n"
            ),
        });
    }
    Ok(Json(EmailCodeResponse {
        challenge,
        expires_at,
    }))
}

/// Check an emailed code (counting the try). The code stays valid until
/// [`use_code`], so a mistyped password doesn't cost a new email.
async fn check_code(
    st: &AppState,
    challenge: &[u8; 16],
    email_lc: &str,
    code: &str,
    allowed: &[CodePurpose],
) -> ApiResult<CodePurpose> {
    if !valid_code(code) {
        return Err(bad("the code is the 6 digits from the email"));
    }
    let row: Option<(String, Vec<u8>)> = sqlx::query_as(
        "UPDATE email_challenges SET tries = tries + 1 \
         WHERE challenge = $1 AND email_lc = $2 AND expires_at > $3 AND tries < $4 \
         RETURNING purpose, code_hash",
    )
    .bind(&challenge[..])
    .bind(email_lc)
    .bind(unix_now())
    .bind(CODE_TRIES)
    .fetch_optional(&st.db)
    .await?;
    let (purpose, stored) = row.ok_or_else(|| bad(WRONG_CODE))?;
    let given = code_hash(challenge, code);
    let same = stored.len() == given.len()
        && stored
            .iter()
            .zip(given.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
    let purpose = allowed
        .iter()
        .copied()
        .find(|p| p.as_str() == purpose)
        .filter(|_| same)
        .ok_or_else(|| bad(WRONG_CODE))?;
    Ok(purpose)
}

async fn use_code(st: &AppState, challenge: &[u8; 16]) -> ApiResult<()> {
    sqlx::query("DELETE FROM email_challenges WHERE challenge = $1")
        .bind(&challenge[..])
        .execute(&st.db)
        .await?;
    Ok(())
}

async fn hash(password: String) -> ApiResult<String> {
    let _permit = HASHING
        .acquire()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .map_err(|e| ApiError::Internal(e.to_string()))
}

/// Check an email account's password, with lock-out after too many
/// wrong ones; upgrade the stored hash if its cost is out of date.
async fn check_password(st: &AppState, org_id: &str, password: &str) -> ApiResult<()> {
    let row: Option<(String, i32, i64)> = sqlx::query_as(
        "SELECT password_hash, failed, locked_until FROM email_accounts WHERE org_id = $1",
    )
    .bind(org_id)
    .fetch_optional(&st.db)
    .await?;
    let (stored, failed, locked_until) = row.ok_or_else(|| bad(WRONG_LOGIN))?;
    let now = unix_now();
    if locked_until > now {
        return Err(ApiError::Conflict(format!(
            "too many wrong passwords: try again in {} minutes, or reset your password",
            (locked_until - now + 59) / 60
        )));
    }
    let ok = {
        let _permit = HASHING
            .acquire()
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let (pw, h) = (password.to_owned(), stored.clone());
        tokio::task::spawn_blocking(move || verify_password(&pw, &h))
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?
    };
    if !ok {
        let failed = failed + 1;
        let (failed, locked_until) = if failed >= MAX_FAILED_PASSWORDS {
            (0, now + LOCK_SECS)
        } else {
            (failed, 0)
        };
        sqlx::query("UPDATE email_accounts SET failed = $2, locked_until = $3 WHERE org_id = $1")
            .bind(org_id)
            .bind(failed)
            .bind(locked_until)
            .execute(&st.db)
            .await?;
        audit::note(
            &st.db,
            org_id,
            audit::Record {
                event: audit::event::AUTHN_FAILURE,
                reason: Some(if locked_until > 0 {
                    "wrong password; account locked".into()
                } else {
                    "wrong password".into()
                }),
                ..Default::default()
            },
        )
        .await;
        return Err(bad(WRONG_LOGIN));
    }
    sqlx::query("UPDATE email_accounts SET failed = 0, locked_until = 0 WHERE org_id = $1")
        .bind(org_id)
        .execute(&st.db)
        .await?;
    if needs_rehash(&stored) {
        let h = hash(password.to_owned()).await?;
        sqlx::query("UPDATE email_accounts SET password_hash = $2 WHERE org_id = $1")
            .bind(org_id)
            .bind(h)
            .execute(&st.db)
            .await?;
    }
    Ok(())
}

fn strong_enough(password: &str, inputs: &[&str]) -> ApiResult<()> {
    let s = password_strength(password, inputs);
    if s.ok {
        return Ok(());
    }
    Err(bad(&format!(
        "choose a stronger password: {}",
        s.feedback.join(" ")
    )))
}

/// `POST /v1/accounts/email`: create an email account, or register this
/// device's keys for one.
pub async fn account(
    State(st): State<AppState>,
    ip: Option<Extension<ClientIp>>,
    Json(req): Json<EmailAccountRequest>,
) -> ApiResult<Json<Account>> {
    let ip = ip.map(|e| e.0);
    let (email, email_lc) = normalize(&req.email)?;
    let signing = VerifyingKey::from_kind_bytes(KeyKind::MaxSigning, &req.signing_public)
        .map_err(|_| bad("signing_public must be an Ed25519 + ML-DSA-87 + SLH-DSA key"))?;
    let kem = KemPublicKey::from_kind_bytes(KeyKind::MaxKem, &req.kem_public)
        .map_err(|_| bad("kem_public must be an MLKEM1024-P384 key"))?;
    let purpose = check_code(
        &st,
        &req.challenge,
        &email_lc,
        &req.code,
        &[CodePurpose::SignUp, CodePurpose::SignIn],
    )
    .await?;
    let account = match purpose {
        CodePurpose::SignUp => {
            let (Some(first), Some(last)) = (&req.first_name, &req.last_name) else {
                return Err(bad("first and last name are required"));
            };
            if !valid_name(first) || !valid_name(last) {
                return Err(bad(
                    "names are 1 to 64 characters, without @, < or > (they are shown next to your email)",
                ));
            }
            if req.keys == KeyMode::Reset {
                return Err(bad("a new account has no keys to reset"));
            }
            strong_enough(&req.password, &[&email, first, last])?;
            let password_hash = hash(req.password.clone()).await?;
            bind_device(
                &st,
                Identity {
                    issuer: EMAIL_ISSUER,
                    subject: &email_lc,
                    email: &email,
                    client_id: CLIENT_ID,
                    names: Some((first, last)),
                    password_hash: Some(password_hash),
                },
                &signing,
                &kem,
                false,
                Existing::Refuse,
                ip,
            )
            .await?
        }
        _ => {
            let org = email_account_org(&st, &email_lc)
                .await?
                .ok_or_else(|| bad(WRONG_LOGIN))?;
            check_password(&st, &org, &req.password).await?;
            bind_device(
                &st,
                Identity {
                    issuer: EMAIL_ISSUER,
                    subject: &email_lc,
                    email: &email,
                    client_id: CLIENT_ID,
                    names: None,
                    password_hash: None,
                },
                &signing,
                &kem,
                req.keys == KeyMode::Reset,
                Existing::Require,
                ip,
            )
            .await?
        }
    };
    use_code(&st, &req.challenge).await?;
    Ok(Json(account.to_wire()))
}

async fn names_of(st: &AppState, org_id: &str) -> ApiResult<(String, String)> {
    let row: (Option<String>, Option<String>) =
        sqlx::query_as("SELECT first_name, last_name FROM personal_accounts WHERE org_id = $1")
            .bind(org_id)
            .fetch_one(&st.db)
            .await?;
    Ok((row.0.unwrap_or_default(), row.1.unwrap_or_default()))
}

async fn set_password(st: &AppState, org_id: &str, password: String, why: &str) -> ApiResult<()> {
    let h = hash(password).await?;
    sqlx::query(
        "UPDATE email_accounts SET password_hash = $2, failed = 0, locked_until = 0, \
         password_changed_at = $3 WHERE org_id = $1",
    )
    .bind(org_id)
    .bind(h)
    .bind(unix_now())
    .execute(&st.db)
    .await?;
    audit::append(
        &st.db,
        org_id,
        audit::Record {
            event: audit::event::PASSWORD_CHANGED,
            reason: Some(why.into()),
            ..Default::default()
        },
    )
    .await?;
    Ok(())
}

/// `POST /v1/auth/email/reset`: a new password with an emailed code.
pub async fn reset_password(
    State(st): State<AppState>,
    Json(req): Json<PasswordResetRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let (email, email_lc) = normalize(&req.email)?;
    check_code(
        &st,
        &req.challenge,
        &email_lc,
        &req.code,
        &[CodePurpose::ResetPassword],
    )
    .await?;
    let org = email_account_org(&st, &email_lc)
        .await?
        .ok_or_else(|| bad(WRONG_CODE))?;
    let (first, last) = names_of(&st, &org).await?;
    strong_enough(&req.new_password, &[&email, &first, &last])?;
    set_password(&st, &org, req.new_password, "reset with an emailed code").await?;
    use_code(&st, &req.challenge).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// `POST /v1/me/password`: change the password (signed by the device).
pub async fn change_password(
    State(st): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    let me = authenticate(&st, &method, &uri, &headers, &body).await?;
    let req: ChangePasswordRequest =
        serde_json::from_slice(&body).map_err(|e| bad(&format!("invalid request: {e}")))?;
    if me.issuer != EMAIL_ISSUER {
        return Err(bad("this account signs in with Google and has no password"));
    }
    check_password(&st, &me.org_id, &req.current_password).await?;
    let (first, last) = names_of(&st, &me.org_id).await?;
    strong_enough(&req.new_password, &[&me.email, &first, &last])?;
    set_password(&st, &me.org_id, req.new_password, "changed").await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_six_digits() {
        for _ in 0..1000 {
            assert!(valid_code(&new_code()));
        }
    }

    #[test]
    fn code_hash_binds_the_challenge() {
        assert_ne!(code_hash(&[1; 16], "123456"), code_hash(&[2; 16], "123456"));
        assert_ne!(code_hash(&[1; 16], "123456"), code_hash(&[1; 16], "123457"));
    }
}
