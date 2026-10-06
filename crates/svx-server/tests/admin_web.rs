//! The private admin page (`svx-admin web`): one-time login, session
//! cookie, loopback host only, no cross-site changes, and the actions.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use svx_server::admin_web::AdminWeb;
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
    assert!(AdminWeb::new(w.db.clone(), "too-short", |_| {}).is_err());
    let app = AdminWeb::new(w.db.clone(), TOKEN, |_| {}).unwrap().router();

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
    let no_reason = json!({ "account": alice.account, "reason": "  " });
    assert_eq!(
        send(&app, post("/api/suspend", &cookie, no_reason)).await.0,
        StatusCode::BAD_REQUEST
    );

    // Suspend and lift it.
    let (status, _, done) = send(&app, post("/api/suspend", &cookie, suspend)).await;
    assert_eq!((status, &done["changed"]), (StatusCode::OK, &json!(true)));
    let path = format!("/api/user/{}", alice.account);
    let (_, _, detail) = send(&app, get(&path, Some(&cookie))).await;
    assert_eq!(detail["user"]["suspended_reason"], "spam reports");
    let lift = json!({ "account": alice.account });
    let (_, _, done) = send(&app, post("/api/unsuspend", &cookie, lift)).await;
    assert_eq!(done["changed"], json!(true));
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
    let right = json!({ "account": alice.account, "confirm_email": alice.email.to_uppercase() });
    let (status, _, done) = send(&app, post("/api/delete", &cookie, right)).await;
    assert_eq!((status, &done["changed"]), (StatusCode::OK, &json!(true)));
    assert_eq!(
        send(&app, get(&path, Some(&cookie))).await.0,
        StatusCode::NOT_FOUND
    );
    w.cleanup().await.unwrap();
}
