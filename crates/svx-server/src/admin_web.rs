//! The operator's private admin page, served by `svx-admin web`.
//!
//! It listens on `127.0.0.1` on the server only and is reached through an
//! SSH port forward from the operator's Mac (`scripts/admin.sh`), so nothing
//! new faces the internet. The script makes a random token, sends it on
//! stdin and opens `/login?t=<token>` once; that sets a session cookie and
//! the token is spent. Every other request needs the cookie, a loopback
//! `Host` (no DNS rebinding), and changes also need a JSON body, the
//! `X-SVX-Admin: 1` header and a matching `Origin` (no cross-site forms).
//!
//! The page only draws what the JSON API returns; every decision is made
//! here and in [`crate::admin_ops`]. No file names or contents exist on the
//! service, so none are shown.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use svx_core::crypto::random_bytes;

use crate::admin_ops::{self, Activity, Notice, Stats, User};
use crate::notify::SendNow;

const COOKIE: &str = "svx_admin";
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
                   connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// Shortest accepted login token: 32 random bytes as hex.
pub const MIN_TOKEN_LEN: usize = 64;

struct Inner {
    db: PgPool,
    token: [u8; 32],
    /// SHA-256 of the session cookie, once the token has been used.
    session: Mutex<Option<[u8; 32]>>,
    last_seen: Mutex<Instant>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    /// Emails the account's owner after each action; `None` without SMTP.
    mail: Option<Arc<dyn SendNow>>,
}

/// One admin session: a token that logs in once, then a cookie.
#[derive(Clone)]
pub struct AdminWeb(Arc<Inner>);

fn sha(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}

impl AdminWeb {
    /// `token` must be at least [`MIN_TOKEN_LEN`] hex characters; `log`
    /// records each action (suspend, unsuspend, delete); `mail` tells the
    /// account's owner about it.
    pub fn new(
        db: PgPool,
        token: &str,
        log: impl Fn(&str) + Send + Sync + 'static,
        mail: Option<Arc<dyn SendNow>>,
    ) -> anyhow::Result<Self> {
        let token = token.trim();
        if token.len() < MIN_TOKEN_LEN || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            anyhow::bail!("the login token must be at least {MIN_TOKEN_LEN} hex characters");
        }
        Ok(AdminWeb(Arc::new(Inner {
            db,
            token: sha(token),
            session: Mutex::new(None),
            last_seen: Mutex::new(Instant::now()),
            log: Arc::new(log),
            mail,
        })))
    }

    /// Time since the last request.
    pub fn idle_for(&self) -> Duration {
        self.0.last_seen.lock().expect("lock").elapsed()
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/login", get(login))
            .route("/", get(index))
            .route("/app.js", get(app_js))
            .route("/app.css", get(app_css))
            .route("/api/stats", get(stats))
            .route("/api/users", get(users))
            .route("/api/user/{id}", get(user))
            .route("/api/suspend", post(suspend))
            .route("/api/unsuspend", post(unsuspend))
            .route("/api/delete", post(delete))
            .layer(middleware::from_fn_with_state(self.clone(), guard))
            .with_state(self.clone())
    }
}

/// An error the page shows: `{"error": "…"}` with a status.
struct Fail(StatusCode, &'static str);

impl IntoResponse for Fail {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

fn fail(status: StatusCode, msg: &'static str) -> Fail {
    Fail(status, msg)
}

/// The `Host` header, if it names this computer (any port).
fn loopback_host(h: &HeaderMap) -> Option<String> {
    let host = h.get(header::HOST)?.to_str().ok()?;
    let name = host.rsplit_once(':').map_or(host, |(n, _)| n);
    matches!(name, "127.0.0.1" | "localhost").then(|| host.to_owned())
}

fn cookie(h: &HeaderMap) -> Option<String> {
    h.get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| {
            let (k, v) = kv.trim().split_once('=')?;
            (k == COOKIE).then(|| v.to_owned())
        })
}

async fn guard(State(app): State<AdminWeb>, req: Request, next: Next) -> Response {
    let Some(host) = loopback_host(req.headers()) else {
        return fail(StatusCode::FORBIDDEN, "wrong host").into_response();
    };
    *app.0.last_seen.lock().expect("lock") = Instant::now();
    if req.uri().path() != "/login" {
        let session = *app.0.session.lock().expect("lock");
        let ok = match (session, cookie(req.headers())) {
            (Some(s), Some(c)) => sha(&c) == s,
            _ => false,
        };
        if !ok {
            return fail(
                StatusCode::UNAUTHORIZED,
                "this admin session has ended: run scripts/admin.sh again",
            )
            .into_response();
        }
    }
    if req.method() != Method::GET {
        let h = req.headers();
        let json_body = h
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("application/json"));
        let marked = h.get("x-svx-admin").is_some_and(|v| v == "1");
        let origin_ok = h
            .get(header::ORIGIN)
            .is_none_or(|o| o.to_str().ok() == Some(&format!("http://{host}")));
        if !(json_body && marked && origin_ok) {
            return fail(StatusCode::FORBIDDEN, "refused: not sent by the admin page")
                .into_response();
        }
    }
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    for (k, v) in [
        (header::CONTENT_SECURITY_POLICY, CSP),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::CACHE_CONTROL, "no-store"),
    ] {
        h.insert(k, HeaderValue::from_static(v));
    }
    resp
}

#[derive(Deserialize)]
struct LoginQuery {
    t: Option<String>,
}

async fn login(State(app): State<AdminWeb>, Query(q): Query<LoginQuery>) -> Response {
    let mut session = app.0.session.lock().expect("lock");
    let good = q.t.as_deref().is_some_and(|t| sha(t) == app.0.token);
    if session.is_some() || !good {
        return (
            StatusCode::UNAUTHORIZED,
            "This link has been used or is wrong. Run scripts/admin.sh again.",
        )
            .into_response();
    }
    let id = hex::encode(random_bytes::<32>());
    *session = Some(sha(&id));
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, "/".to_owned()),
            (
                header::SET_COOKIE,
                format!("{COOKIE}={id}; HttpOnly; SameSite=Strict; Path=/"),
            ),
        ],
    )
        .into_response()
}

async fn index() -> Response {
    static_file(
        "text/html; charset=utf-8",
        include_str!("admin_web/index.html"),
    )
}
async fn app_js() -> Response {
    static_file(
        "text/javascript; charset=utf-8",
        include_str!("admin_web/app.js"),
    )
}
async fn app_css() -> Response {
    static_file("text/css; charset=utf-8", include_str!("admin_web/app.css"))
}
fn static_file(kind: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, kind)], body).into_response()
}

fn db_error(e: sqlx::Error) -> Fail {
    tracing::error!(error = %e, "admin web: database error");
    fail(
        StatusCode::INTERNAL_SERVER_ERROR,
        "database error; see the server log",
    )
}

/// An account as the page shows it.
#[derive(Serialize)]
struct UserView {
    account: String,
    email: String,
    name: String,
    sign_in: String,
    created_at: i64,
    last_active: Option<i64>,
    suspended_at: Option<i64>,
    suspended_reason: Option<String>,
}

impl From<&User> for UserView {
    fn from(u: &User) -> Self {
        UserView {
            account: u.org_id.clone(),
            email: u.email.clone(),
            name: u.name(),
            sign_in: u.sign_in().to_owned(),
            created_at: u.created_at,
            last_active: u.last_active,
            suspended_at: u.suspended_at,
            suspended_reason: u.suspended_reason.clone(),
        }
    }
}

async fn stats(State(app): State<AdminWeb>) -> Result<Json<Stats>, Fail> {
    admin_ops::stats(&app.0.db)
        .await
        .map(Json)
        .map_err(db_error)
}

#[derive(Deserialize)]
struct UsersQuery {
    search: Option<String>,
    limit: Option<i64>,
}

async fn users(
    State(app): State<AdminWeb>,
    Query(q): Query<UsersQuery>,
) -> Result<Json<Vec<UserView>>, Fail> {
    let search = q.search.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let list = admin_ops::users(&app.0.db, search, q.limit.unwrap_or(200))
        .await
        .map_err(db_error)?;
    Ok(Json(list.iter().map(UserView::from).collect()))
}

/// The account with exactly this account ID.
async fn by_id(app: &AdminWeb, id: &str) -> Result<User, Fail> {
    match admin_ops::find(&app.0.db, id).await.map_err(db_error)? {
        Some(u) if u.org_id == id => Ok(u),
        _ => Err(fail(StatusCode::NOT_FOUND, "no such account")),
    }
}

#[derive(Serialize)]
struct UserDetail {
    user: UserView,
    activity: Activity,
}

async fn user(
    State(app): State<AdminWeb>,
    Path(id): Path<String>,
) -> Result<Json<UserDetail>, Fail> {
    let u = by_id(&app, &id).await?;
    let activity = admin_ops::activity(&app.0.db, &u.org_id)
        .await
        .map_err(db_error)?;
    Ok(Json(UserDetail {
        user: UserView::from(&u),
        activity,
    }))
}

#[derive(Deserialize)]
struct Action {
    account: String,
    reason: Option<String>,
    confirm_email: Option<String>,
}

#[derive(Serialize)]
struct Done {
    changed: bool,
    message: String,
}

/// Email the account's owner; returns what to add to the page's message.
async fn tell(app: &AdminWeb, notice: Notice, u: &User, reason: Option<&str>) -> &'static str {
    let Some(mail) = &app.0.mail else {
        return " No email was sent: email isn't set up on the server.";
    };
    match mail
        .send_now(admin_ops::notice_email(notice, u, reason))
        .await
    {
        Ok(()) => " They have been emailed.",
        Err(e) => {
            tracing::warn!(error = %e, "admin web: notice email failed");
            (app.0.log)(&format!("admin web: email to {} failed: {e}", u.org_id));
            " The email to them couldn't be sent (see the Terminal window)."
        }
    }
}

/// An optional reason: trimmed, empty means none, at most 200 characters.
fn reason(r: Option<&str>) -> Result<Option<&str>, Fail> {
    let r = r.map(str::trim).filter(|r| !r.is_empty());
    if r.is_some_and(|r| r.chars().count() > 200) {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "keep the reason under 200 characters",
        ));
    }
    Ok(r)
}

async fn suspend(State(app): State<AdminWeb>, Json(a): Json<Action>) -> Result<Json<Done>, Fail> {
    let u = by_id(&app, &a.account).await?;
    let reason = reason(a.reason.as_deref())?;
    let changed = admin_ops::suspend(&app.0.db, &u.org_id, reason)
        .await
        .map_err(db_error)?;
    let message = if changed {
        (app.0.log)(&format!(
            "admin web: suspended {} ({})",
            u.org_id,
            reason.unwrap_or("no reason given")
        ));
        let told = tell(&app, Notice::Suspended, &u, reason).await;
        format!("{} is suspended.{told}", u.email)
    } else {
        format!("{} was already suspended.", u.email)
    };
    Ok(Json(Done { changed, message }))
}

async fn unsuspend(State(app): State<AdminWeb>, Json(a): Json<Action>) -> Result<Json<Done>, Fail> {
    let u = by_id(&app, &a.account).await?;
    let changed = admin_ops::unsuspend(&app.0.db, &u.org_id)
        .await
        .map_err(db_error)?;
    let message = if changed {
        (app.0.log)(&format!("admin web: unsuspended {}", u.org_id));
        let told = tell(&app, Notice::Unsuspended, &u, None).await;
        format!("{} can use SVX again.{told}", u.email)
    } else {
        format!("{} was not suspended.", u.email)
    };
    Ok(Json(Done { changed, message }))
}

async fn delete(State(app): State<AdminWeb>, Json(a): Json<Action>) -> Result<Json<Done>, Fail> {
    let u = by_id(&app, &a.account).await?;
    let typed = a.confirm_email.as_deref().map(str::trim).unwrap_or("");
    if !typed.eq_ignore_ascii_case(&u.email) {
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "the email you typed doesn't match this account; nothing was deleted",
        ));
    }
    let reason = reason(a.reason.as_deref())?;
    let changed = admin_ops::erase(&app.0.db, &u.org_id)
        .await
        .map_err(db_error)?;
    if !changed {
        return Err(fail(StatusCode::NOT_FOUND, "no such account"));
    }
    (app.0.log)(&format!(
        "admin web: erased {} ({})",
        u.org_id,
        reason.unwrap_or("no reason given")
    ));
    let told = tell(&app, Notice::Erased, &u, reason).await;
    Ok(Json(Done {
        changed,
        message: format!("{} has been erased.{told}", u.email),
    }))
}
