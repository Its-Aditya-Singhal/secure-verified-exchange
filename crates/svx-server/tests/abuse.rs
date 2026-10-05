//! Abuse limits per network address and per account, the daily email
//! budget, and the operator's suspend and erase commands (`svx-admin`).

use svx_protocol::email_account::{CodePurpose, EmailCodeRequest};
use svx_protocol::personal::FileRules;
use svx_protocol::{DenyReason, ProtocolError, ReleaseSession};
use svx_server::admin_ops;
use svx_server::limits::Limits;
use svx_testkit::*;

macro_rules! world {
    ($limits:expr) => {
        match World::with_options(&WorldOptions {
            limits: Some($limits),
            ..Default::default()
        })
        .await
        {
            Some(w) => w,
            None => return,
        }
    };
}

const NO_APPROVAL: FileRules = FileRules {
    require_approval: false,
    one_time: false,
    expires_at: None,
    view_only: false,
    allow_share_requests: false,
};

fn invalid<T: std::fmt::Debug>(r: Result<T, ProtocolError>) -> String {
    match r {
        Err(ProtocolError::Invalid(d)) => d,
        other => panic!("expected a refusal with a reason, got {other:?}"),
    }
}

fn denied<T: std::fmt::Debug>(r: Result<T, ProtocolError>) -> DenyReason {
    match r {
        Err(ProtocolError::Denied(d)) => d,
        other => panic!("expected a denial, got {other:?}"),
    }
}

/// A request from network address `ip`; returns the HTTP status and body.
async fn from_ip(
    w: &World,
    ip: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> (u16, serde_json::Value) {
    let url = format!("{}{path}", w.service_url);
    let http = w.client.http();
    let req = match body {
        Some(b) => http.post(url).json(b),
        None => http.get(url),
    };
    let resp = req.header(CLIENT_IP_HEADER, ip).send().await.unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(serde_json::Value::Null))
}

async fn code_from(w: &World, ip: &str, email: &str) -> (u16, serde_json::Value) {
    let body = serde_json::to_value(EmailCodeRequest {
        email: email.into(),
        purpose: CodePurpose::SignUp,
    })
    .unwrap();
    from_ip(w, ip, "/v1/auth/email/code", Some(&body)).await
}

async fn count(w: &World, sql: &str, bind: &str) -> i64 {
    sqlx::query_scalar(sql)
        .bind(bind)
        .fetch_one(&w.db)
        .await
        .unwrap()
}

#[tokio::test]
async fn every_address_has_a_request_budget() {
    // Setting up the test world itself takes some requests from 127.0.0.1.
    const N: u32 = 60;
    let w = world!(Limits {
        requests_per_ip_per_min: N,
        registry_per_ip_per_min: 2,
        ..Limits::default()
    });
    for _ in 0..N {
        assert_eq!(from_ip(&w, "192.0.2.1", "/v1/service", None).await.0, 200);
    }
    let (status, body) = from_ip(&w, "192.0.2.1", "/v1/service", None).await;
    assert_eq!(status, 429);
    assert!(
        body["detail"]
            .as_str()
            .unwrap()
            .contains("too many requests")
    );
    // Another address, and another IPv6 /64, are counted apart; the same
    // /64 is one address.
    assert_eq!(from_ip(&w, "192.0.2.2", "/v1/service", None).await.0, 200);
    for _ in 0..N {
        assert_eq!(
            from_ip(&w, "2001:db8:0:1::1", "/healthz", None).await.0,
            200
        );
    }
    assert_eq!(
        from_ip(&w, "2001:db8:0:1::99", "/healthz", None).await.0,
        429
    );
    assert_eq!(
        from_ip(&w, "2001:db8:0:2::1", "/healthz", None).await.0,
        200
    );

    // Signed registry records cost more: their own, smaller budget.
    for _ in 0..2 {
        assert_eq!(
            from_ip(&w, "192.0.2.3", "/v1/service/record", None).await.0,
            200
        );
    }
    assert_eq!(
        from_ip(&w, "192.0.2.3", "/v1/service/record", None).await.0,
        429
    );
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn codes_per_address_and_the_daily_email_budget() {
    let w = world!(Limits {
        codes_per_ip_per_hour: 2,
        emails_per_day: 3,
        ..Limits::default()
    });
    assert_eq!(code_from(&w, "192.0.2.1", "a@example.test").await.0, 200);
    assert_eq!(code_from(&w, "192.0.2.1", "b@example.test").await.0, 200);
    let (status, body) = code_from(&w, "192.0.2.1", "c@example.test").await;
    assert_eq!(status, 429);
    assert!(body["detail"].as_str().unwrap().contains("network"));
    // A third email from elsewhere uses up the day's budget...
    assert_eq!(code_from(&w, "192.0.2.2", "c@example.test").await.0, 200);
    assert_eq!(w.mail.sent().len(), 3);
    // ... after which no address gets a code.
    let (status, body) = code_from(&w, "192.0.2.3", "d@example.test").await;
    assert_eq!(status, 429);
    assert!(body["detail"].as_str().unwrap().contains("emails today"));
    assert_eq!(w.mail.sent().len(), 3);
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn new_accounts_per_address() {
    let w = world!(Limits {
        accounts_per_ip_per_day: 1,
        ..Limits::default()
    });
    let alice = w.sign_up("alice").await;
    let mut rng = svx_core::crypto::os_rng();
    let sign = svx_core::crypto::SigningKey::generate_max(&mut rng);
    let kem = svx_core::crypto::KemSecretKey::generate_max(&mut rng);
    let d = invalid(w.sign_up_with("bob", &sign, &kem, false).await);
    assert!(d.contains("too many requests"), "{d}");
    // Signing in again on the same device isn't a new account.
    w.sign_up_with("alice", &alice.sign, &alice.kem, false)
        .await
        .unwrap();
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn files_and_opens_per_account() {
    let w = world!(Limits {
        files_per_account_per_day: 1,
        releases_per_account_per_min: 2,
        ..Limits::default()
    });
    let alice = w.sign_up("alice").await;
    let bob = w.sign_up("bob").await;
    let (file, _) = w.send(&alice, &[&bob], NO_APPROVAL).await.unwrap();
    let d = invalid(w.send(&alice, &[&bob], NO_APPROVAL).await);
    assert!(d.contains("this account"), "{d}");
    // Bob can still send: the limit is per account.
    w.send(&bob, &[&alice], NO_APPROVAL).await.unwrap();

    for _ in 0..2 {
        let s = ReleaseSession::new();
        w.ask(&bob, &file, &s).await.unwrap();
    }
    let s = ReleaseSession::new();
    // Release answers carry no detail.
    assert_eq!(
        denied(w.ask(&bob, &file, &s).await),
        DenyReason::Unavailable
    );
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn a_suspended_account_is_shut_out_until_lifted() {
    let w = world!(Limits::default());
    let alice = w.sign_up("alice").await;
    let bob = w.sign_up("bob").await;
    let (file, _) = w.send(&alice, &[&bob], NO_APPROVAL).await.unwrap();

    assert!(
        admin_ops::suspend(&w.db, &alice.account, "test")
            .await
            .unwrap()
    );
    assert!(
        !admin_ops::suspend(&w.db, &alice.account, "again")
            .await
            .unwrap()
    );
    let u = admin_ops::find(&w.db, &alice.email.to_uppercase())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(u.suspended_reason.as_deref(), Some("test"));

    // Her signed requests and new sign-ins are refused, with a reason.
    let d = invalid(w.get::<serde_json::Value>(&alice, "/v1/me").await);
    assert!(d.contains("suspended"), "{d}");
    let d = invalid(
        w.sign_up_with("alice", &alice.sign, &alice.kem, false)
            .await,
    );
    assert!(d.contains("suspended"), "{d}");
    // Nobody finds her, and what she sent no longer opens.
    assert!(w.lookup(&bob, &alice.email).await.is_err());
    assert!(w.open_personal(&bob, &file).await.is_err());
    // Release endpoints don't explain.
    let s = ReleaseSession::new();
    assert!(matches!(
        w.ask(&alice, &file, &s).await,
        Err(ProtocolError::Denied(DenyReason::NotAuthorized))
    ));

    assert!(admin_ops::unsuspend(&w.db, &alice.account).await.unwrap());
    assert_eq!(w.open_personal(&bob, &file).await.unwrap(), SECRET);
    w.get::<serde_json::Value>(&alice, "/v1/me").await.unwrap();
    let (entries, chain_ok) = svx_server::audit::list(&w.db, &alice.account, 50, None, None)
        .await
        .unwrap();
    assert!(chain_ok);
    let events: Vec<_> = entries.iter().map(|e| e.event.as_str()).collect();
    assert!(events.contains(&"account_suspended"));
    assert!(events.contains(&"account_unsuspended"));
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn erasing_an_account_leaves_nothing_of_it_but_others_records() {
    let w = world!(Limits::default());
    let alice = w.sign_up("alice").await;
    let bob = w.sign_up("bob").await;
    let carol = w.sign_up("carol").await;
    let approval = FileRules {
        require_approval: true,
        ..NO_APPROVAL
    };
    let (to_bob, _) = w.send(&alice, &[&bob], approval).await.unwrap();
    let (from_bob, _) = w.send(&bob, &[&alice], NO_APPROVAL).await.unwrap();
    let (from_carol, _) = w.send(&carol, &[&alice], NO_APPROVAL).await.unwrap();
    // Bob asks to open Alice's file: a request in her log, an email to her
    // naming him.
    let s = ReleaseSession::new();
    w.ask(&bob, &to_bob, &s).await.unwrap();
    assert_eq!(w.open_personal(&alice, &from_bob).await.unwrap(), SECRET);
    assert!(
        count(
            &w,
            "SELECT count(*) FROM notifications WHERE strpos(lower(body), lower($1)) > 0",
            &bob.email
        )
        .await
            > 0
    );

    // The audit log can't be edited or trimmed outside an erasure.
    assert!(
        sqlx::query("UPDATE audit SET reason = 'x' WHERE org_id = $1")
            .bind(&alice.account)
            .execute(&w.db)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM audit WHERE org_id = $1")
            .bind(&bob.account)
            .execute(&w.db)
            .await
            .is_err()
    );

    let stats = admin_ops::stats(&w.db).await.unwrap();
    assert_eq!(stats.accounts, 3);
    assert_eq!(stats.files, 3);
    assert!(admin_ops::erase(&w.db, &bob.account).await.unwrap());
    assert!(!admin_ops::erase(&w.db, &bob.account).await.unwrap());

    let b = bob.account.as_str();
    for sql in [
        "SELECT count(*) FROM orgs WHERE org_id = $1",
        "SELECT count(*) FROM personal_accounts WHERE org_id = $1",
        "SELECT count(*) FROM org_keys WHERE org_id = $1",
        "SELECT count(*) FROM personal_files WHERE sender = $1",
        "SELECT count(*) FROM personal_file_recipients WHERE recipient = $1",
        "SELECT count(*) FROM approvals WHERE requester = $1",
        "SELECT count(*) FROM opens WHERE recipient = $1",
        "SELECT count(*) FROM audit WHERE org_id = $1",
    ] {
        assert_eq!(count(&w, sql, b).await, 0, "{sql}");
    }
    for sql in [
        "SELECT count(*) FROM notifications WHERE strpos(lower(to_email || subject || body), lower($1)) > 0",
        "SELECT count(*) FROM email_challenges WHERE email_lc = lower($1)",
    ] {
        assert_eq!(count(&w, sql, &bob.email).await, 0, "{sql}");
    }
    // Alice's own log is whole and still checks out; Carol's file still opens.
    let (entries, chain_ok) = svx_server::audit::list(&w.db, &alice.account, 100, None, None)
        .await
        .unwrap();
    assert!(chain_ok && !entries.is_empty());
    assert_eq!(w.open_personal(&alice, &from_carol).await.unwrap(), SECRET);
    let stats = admin_ops::stats(&w.db).await.unwrap();
    assert_eq!((stats.accounts, stats.files), (2, 2));

    // The address is free again.
    let again = w.sign_up("bob").await;
    assert_ne!(again.account, bob.account);
    let list = admin_ops::users(&w.db, Some("BOB"), 10).await.unwrap();
    assert_eq!(list.len(), 1);
    w.cleanup().await.unwrap();
}
