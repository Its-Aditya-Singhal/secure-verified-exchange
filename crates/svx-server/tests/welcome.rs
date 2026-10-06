//! The welcome email to new accounts.

use std::time::Duration;

use svx_protocol::Method;
use svx_protocol::personal::{AccountName, SetNameRequest};
use svx_server::limits::ANNOUNCE_CEILING;
use svx_server::notify::Email;
use svx_testkit::*;

macro_rules! world {
    () => {
        match World::with_options(&WorldOptions {
            welcome_emails: true,
            ..Default::default()
        })
        .await
        {
            Some(w) => w,
            None => return,
        }
    };
}

fn welcomes(w: &World) -> Vec<Email> {
    w.mail
        .sent()
        .into_iter()
        .filter(|e| e.subject == "Welcome to SVX")
        .collect()
}

/// The welcome is sent in the background: wait for `n` of them.
async fn wait_for(w: &World, n: usize) -> Vec<Email> {
    for _ in 0..50 {
        let got = welcomes(w);
        if got.len() >= n {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    welcomes(w)
}

#[tokio::test]
async fn each_new_account_gets_one_welcome_and_nobody_else_does() {
    let w = world!();
    // A Google account has no name yet: its welcome waits for the name.
    let alice = w.sign_up("alice").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(welcomes(&w).is_empty());
    let set = SetNameRequest {
        first_name: "Alice".into(),
        last_name: "Example".into(),
    };
    let _: AccountName = w
        .call(&alice, Method::PUT, "/v1/me/name", Some(&set))
        .await
        .unwrap();
    let mail = wait_for(&w, 1).await;
    assert_eq!(mail.len(), 1);
    assert_eq!(mail[0].to, alice.email);
    assert!(mail[0].body.starts_with("Hi Alice, welcome aboard."));
    let html = mail[0].html.as_ref().expect("an HTML version");
    assert!(html.body.contains("cid:svx-banner"));
    assert_eq!(html.images[0].data[..4], *b"\x89PNG");
    assert!(!html.body.contains("href"));

    // An email account, with a name.
    let bob = w
        .sign_up_email(
            "bob.mail@example.test",
            "Tangerine-Ocelot-Fjord-42",
            ("Bob", "Example"),
        )
        .await;
    let mail = wait_for(&w, 2).await;
    assert_eq!(mail.len(), 2);
    let to_bob = mail.iter().find(|e| e.to == bob.email).unwrap();
    assert!(to_bob.body.starts_with("Hi Bob, welcome aboard."));

    // Signing in again on a device is not a new account.
    let _ = w
        .sign_up_with("alice", &alice.sign, &alice.kem, false)
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(welcomes(&w).len(), 2);
    let counted: i64 =
        sqlx::query_scalar("SELECT count(*) FROM email_sends WHERE kind = 'welcome'")
            .fetch_one(&w.db)
            .await
            .unwrap();
    assert_eq!(counted, 2);
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn no_welcome_when_the_allowance_is_short_but_sign_up_works() {
    let w = world!();
    sqlx::query(
        "INSERT INTO email_sends (at, kind) SELECT $1, 'notice' FROM generate_series(1, $2::int)",
    )
    .bind(svx_protocol::unix_now())
    .bind(ANNOUNCE_CEILING as i32)
    .execute(&w.db)
    .await
    .unwrap();
    let carol = w.sign_up("carol").await;
    assert!(carol.account.starts_with("u."));
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(welcomes(&w).is_empty());
    w.cleanup().await.unwrap();
}
