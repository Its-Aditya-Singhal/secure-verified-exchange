//! Names for accounts created without one (Google), and "last active".

use svx_protocol::Method;
use svx_protocol::personal::{AccountName, SetNameRequest};
use svx_server::admin_ops;
use svx_testkit::*;

macro_rules! world {
    () => {
        match World::with_options(&WorldOptions::default()).await {
            Some(w) => w,
            None => return,
        }
    };
}

fn name(first: &str, last: &str) -> SetNameRequest {
    SetNameRequest {
        first_name: first.into(),
        last_name: last.into(),
    }
}

#[tokio::test]
async fn a_google_account_gives_its_name_once_and_recipients_see_it() {
    let w = world!();
    let alice = w.sign_up("alice").await;
    let bob = w.sign_up("bob").await;
    let none: AccountName = w.get(&alice, "/v1/me/name").await.unwrap();
    assert_eq!(none, AccountName::default());

    for (f, l) in [
        ("", "Example"),
        ("Alice", "  "),
        ("<b>", "Example"),
        ("a@b", "Example"),
    ] {
        let r: Result<AccountName, _> = w
            .call(&alice, Method::PUT, "/v1/me/name", Some(&name(f, l)))
            .await;
        assert!(r.is_err(), "{f:?} {l:?}");
    }
    let set: AccountName = w
        .call(
            &alice,
            Method::PUT,
            "/v1/me/name",
            Some(&name(" Alice ", "Example")),
        )
        .await
        .unwrap();
    assert_eq!(set.first_name.as_deref(), Some("Alice"));
    let got: AccountName = w.get(&alice, "/v1/me/name").await.unwrap();
    assert_eq!(got, set);

    // Once only.
    let again: Result<AccountName, _> = w
        .call(
            &alice,
            Method::PUT,
            "/v1/me/name",
            Some(&name("Eve", "Example")),
        )
        .await;
    assert!(again.unwrap_err().to_string().contains("already set"));

    // Others see the name in the signed record.
    let rec = w.lookup(&bob, &alice.email).await.unwrap();
    assert_eq!(rec.display_name, "Alice Example");
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn an_email_account_already_has_its_name() {
    let w = world!();
    let carol = w
        .sign_up_email(
            "carol.mail@example.test",
            "Tangerine-Ocelot-Fjord-42",
            ("Carol", "Example"),
        )
        .await;
    let got: AccountName = w.get(&carol, "/v1/me/name").await.unwrap();
    assert_eq!(got.first_name.as_deref(), Some("Carol"));
    let r: Result<AccountName, _> = w
        .call(
            &carol,
            Method::PUT,
            "/v1/me/name",
            Some(&name("Eve", "Example")),
        )
        .await;
    assert!(r.is_err());
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn last_active_is_the_last_signed_request_at_most_every_five_minutes() {
    let w = world!();
    let alice = w.sign_up("alice").await;
    let users = admin_ops::users(&w.db, None, 10).await.unwrap();
    let u = users.iter().find(|u| u.org_id == alice.account).unwrap();
    assert!(
        u.last_active.unwrap() >= u.created_at,
        "a new account is active"
    );

    let seen = || async {
        sqlx::query_scalar::<_, Option<i64>>(
            "SELECT last_seen_at FROM personal_accounts WHERE org_id = $1",
        )
        .bind(&alice.account)
        .fetch_one(&w.db)
        .await
        .unwrap()
    };
    let _: AccountName = w.get(&alice, "/v1/me/name").await.unwrap();
    let first = seen().await.expect("recorded");
    // Pretend it was 4 minutes ago: not written again yet.
    sqlx::query("UPDATE personal_accounts SET last_seen_at = $2 WHERE org_id = $1")
        .bind(&alice.account)
        .bind(first - 240)
        .execute(&w.db)
        .await
        .unwrap();
    let _: AccountName = w.get(&alice, "/v1/me/name").await.unwrap();
    assert_eq!(seen().await, Some(first - 240));
    // 6 minutes ago: written.
    sqlx::query("UPDATE personal_accounts SET last_seen_at = $2 WHERE org_id = $1")
        .bind(&alice.account)
        .bind(first - 360)
        .execute(&w.db)
        .await
        .unwrap();
    let _: AccountName = w.get(&alice, "/v1/me/name").await.unwrap();
    assert!(seen().await.unwrap() >= first);
    w.cleanup().await.unwrap();
}
