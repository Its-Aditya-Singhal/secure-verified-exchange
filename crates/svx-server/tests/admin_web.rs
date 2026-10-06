//! The private admin page (`svx-admin web`): one-time login, session
//! cookie, loopback host only, no cross-site changes, and the actions.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::sync::Arc;

use svx_server::admin_web::AdminWeb;
use svx_server::notify::MemoryNotifier;
use svx_testkit::*;
use tower::ServiceExt;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HOST: &str = "127.0.0.1:9791";

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, Option<String>, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned());
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        cookie,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn get(path: &str, cookie: Option<&str>) -> Request<Body> {
    let mut b = Request::get(path).header(header::HOST, HOST);
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    b.body(Body::empty()).unwrap()
}

fn post(path: &str, cookie: &str, body: Value) -> Request<Body> {
    Request::post(path)
        .header(header::HOST, HOST)
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, format!("http://{HOST}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-svx-admin", "1")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn the_admin_page_logs_in_once_and_refuses_strangers() {
    let Some(w) = World::with_options(&WorldOptions::default()).await else {
        return;
    };
    assert!(AdminWeb::new(w.db.clone(), "too-short", |_| {}, None).is_err());
    let mail = Arc::new(MemoryNotifier::default());
    let app = AdminWeb::new(w.db.clone(), TOKEN, |_| {}, Some(mail.clone()))
        .unwrap()
        .router();

    // Nothing without a session.
    assert_eq!(send(&app, get("/", None)).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        send(&app, get("/api/stats", None)).await.0,
        StatusCode::UNAUTHORIZED
    );
    let wrong = format!("/login?t={}", TOKEN.replace('0', "1"));
    assert_eq!(
        send(&app, get(&wrong, None)).await.0,
        StatusCode::UNAUTHORIZED
    );
    // A page reached through another host name (DNS rebinding) is refused.
    let rebound = Request::get(format!("/login?t={TOKEN}"))
        .header(header::HOST, "admin.example.com:9791")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, rebound).await.0, StatusCode::FORBIDDEN);

    // The token logs in once.
    let (status, cookie, _) = send(&app, get(&format!("/login?t={TOKEN}"), None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let cookie = cookie.expect("session cookie");
    let (again, _, _) = send(&app, get(&format!("/login?t={TOKEN}"), None)).await;
    assert_eq!(again, StatusCode::UNAUTHORIZED);
    assert_eq!(
        send(&app, get("/api/stats", Some("svx_admin=guess")))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );

    // The page and its headers.
    let resp = app.clone().oneshot(get("/", Some(&cookie))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let csp = resp.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap();
    assert!(csp.contains("default-src 'none'") && csp.contains("frame-ancestors 'none'"));
    assert_eq!(resp.headers()[header::CACHE_CONTROL], "no-store");

    let alice = w.sign_up("alice").await;
    let (status, _, list) = send(&app, get("/api/users?search=alice", Some(&cookie))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["account"], alice.account.as_str());
    let (_, _, stats) = send(&app, get("/api/stats", Some(&cookie))).await;
    assert!(stats["accounts"].as_i64().unwrap() >= 1);

    // Changes must come from the page itself.
    let suspend = json!({ "account": alice.account, "reason": "spam reports" });
    let forged = Request::post("/api/suspend")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("account=x"))
        .unwrap();
    assert_eq!(send(&app, forged).await.0, StatusCode::FORBIDDEN);
    let mut cross = post("/api/suspend", &cookie, suspend.clone());
    cross
        .headers_mut()
        .insert(header::ORIGIN, "http://evil.example".parse().unwrap());
    assert_eq!(send(&app, cross).await.0, StatusCode::FORBIDDEN);
    let long = json!({ "account": alice.account, "reason": "x".repeat(201) });
    assert_eq!(
        send(&app, post("/api/suspend", &cookie, long)).await.0,
        StatusCode::BAD_REQUEST
    );
    assert!(mail.sent().is_empty());

    // Suspend and lift it; Alice is emailed each time, with the reason if given.
    let (status, _, done) = send(&app, post("/api/suspend", &cookie, suspend)).await;
    assert_eq!((status, &done["changed"]), (StatusCode::OK, &json!(true)));
    assert!(
        done["message"]
            .as_str()
            .unwrap()
            .contains("They have been emailed")
    );
    let sent = mail.sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to, alice.email);
    assert_eq!(sent[0].subject, "Your SVX account has been suspended");
    assert!(sent[0].body.contains("Reason: spam reports"));
    let path = format!("/api/user/{}", alice.account);
    let (_, _, detail) = send(&app, get(&path, Some(&cookie))).await;
    assert_eq!(detail["user"]["suspended_reason"], "spam reports");
    let lift = json!({ "account": alice.account });
    let (_, _, done) = send(&app, post("/api/unsuspend", &cookie, lift)).await;
    assert_eq!(done["changed"], json!(true));
    assert_eq!(mail.sent()[1].subject, "Your SVX account is active again");
    // Suspending again without a reason: the email has none.
    let bare = json!({ "account": alice.account, "reason": null });
    assert_eq!(
        send(&app, post("/api/suspend", &cookie, bare)).await.0,
        StatusCode::OK
    );
    assert!(!mail.sent()[2].body.contains("Reason"));
    // Accounts are named by ID only: an email in the ID slot finds nothing.
    let by_email = format!("/api/user/{}", alice.email);
    assert_eq!(
        send(&app, get(&by_email, Some(&cookie))).await.0,
        StatusCode::NOT_FOUND
    );

    // Delete needs the email typed again.
    let wrong = json!({ "account": alice.account, "confirm_email": "bob@example.com" });
    assert_eq!(
        send(&app, post("/api/delete", &cookie, wrong)).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        send(&app, get(&path, Some(&cookie))).await.0,
        StatusCode::OK
    );
    assert_eq!(mail.sent().len(), 3);
    let right = json!({
        "account": alice.account,
        "confirm_email": alice.email.to_uppercase(),
        "reason": "asked to be removed",
    });
    let (status, _, done) = send(&app, post("/api/delete", &cookie, right)).await;
    assert_eq!((status, &done["changed"]), (StatusCode::OK, &json!(true)));
    let last = mail.sent().pop().unwrap();
    assert_eq!(last.subject, "Your SVX account has been deleted");
    assert!(last.body.contains("Reason: asked to be removed"));
    assert_eq!(
        send(&app, get(&path, Some(&cookie))).await.0,
        StatusCode::NOT_FOUND
    );
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn logs_and_announcements_need_the_session_and_the_page() {
    let Some(w) = World::with_options(&WorldOptions::default()).await else {
        return;
    };
    let mail = Arc::new(MemoryNotifier::default());
    let app = AdminWeb::new(w.db.clone(), TOKEN, |_| {}, Some(mail.clone()))
        .unwrap()
        .router();
    for path in ["/api/logs", "/api/email-usage", "/api/announcements"] {
        assert_eq!(
            send(&app, get(path, None)).await.0,
            StatusCode::UNAUTHORIZED,
            "{path}"
        );
    }
    let (_, cookie, _) = send(&app, get(&format!("/login?t={TOKEN}"), None)).await;
    let cookie = cookie.unwrap();
    let alice = w.sign_up("alice").await;

    let (status, _, usage) = send(&app, get("/api/email-usage", Some(&cookie))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(usage["limit"], 500);
    // Alice's welcome email may already be counted (it's sent in the background).
    assert!(usage["announce_room"].as_i64().unwrap() >= 399);
    assert!(usage["by_kind"].get("test").is_none());

    // "hello" in base64.
    let body = json!({
        "subject": "SVX 0.2",
        "body": "Hello,\n\nnew things.",
        "files": [{ "name": "notes.txt", "content_type": "text/plain", "data": "aGVsbG8=" }],
        "accounts": [alice.account],
        "queue_rest": false,
    });
    // Not from the page: refused.
    let forged = Request::post("/api/announcements")
        .header(header::HOST, HOST)
        .header(header::COOKIE, &cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    assert_eq!(send(&app, forged).await.0, StatusCode::FORBIDDEN);
    let bad = json!({ "subject": " ", "body": "x", "accounts": [alice.account] });
    assert_eq!(
        send(&app, post("/api/announcements", &cookie, bad)).await.0,
        StatusCode::BAD_REQUEST
    );

    // A test goes out at once, with the file.
    let mut test = body.clone();
    test["to"] = json!("operator@example.com");
    let (status, _, done) = send(&app, post("/api/announcements/test", &cookie, test)).await;
    assert_eq!(status, StatusCode::OK, "{done}");
    assert_eq!(mail.sent()[0].to, "operator@example.com");
    assert_eq!(mail.sent_files()[0][0].data, b"hello");
    // A health-check alert (written by svx-check) counts too.
    sqlx::query(
        "INSERT INTO email_sends (at, kind) VALUES (extract(epoch from now())::bigint, 'alert')",
    )
    .execute(&w.db)
    .await
    .unwrap();
    let (_, _, usage) = send(&app, get("/api/email-usage", Some(&cookie))).await;
    assert!(usage["used"].as_i64().unwrap() >= 2);
    assert_eq!(usage["by_kind"]["test"], 1);
    assert_eq!(usage["by_kind"]["alert"], 1);

    let (status, _, created) = send(&app, post("/api/announcements", &cookie, body)).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["recipients"], 1);
    let (_, _, list) = send(&app, get("/api/announcements", Some(&cookie))).await;
    assert_eq!(list[0]["pending"], 1);
    let path = format!("/api/announcements/{}/stop", created["id"]);
    let (_, _, done) = send(&app, post(&path, &cookie, json!({}))).await;
    assert_eq!(done["changed"], true);

    // Unsubscribe from the account's page; the logs show both.
    let opt = format!("/api/user/{}/announcements", alice.account);
    let (_, _, done) = send(&app, post(&opt, &cookie, json!({ "off": true }))).await;
    assert_eq!(done["changed"], true);
    let (_, _, user) = send(
        &app,
        get(&format!("/api/user/{}", alice.account), Some(&cookie)),
    )
    .await;
    assert_eq!(user["user"]["announcements_off"], true);
    let (status, _, logs) = send(&app, get("/api/logs?problems=false", Some(&cookie))).await;
    assert_eq!(status, StatusCode::OK);
    let events: Vec<&str> = logs["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["event"].as_str().unwrap())
        .collect();
    for e in [
        "announcements_off",
        "announcement_stopped",
        "announcement",
        "announcement_test",
    ] {
        assert!(events.contains(&e), "{e} in {events:?}");
    }
    w.cleanup().await.unwrap();
}
