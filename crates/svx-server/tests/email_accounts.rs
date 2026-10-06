//! Email + password accounts end to end: emailed codes, password rules,
//! sign-in on a new device, lock-out, password reset and change, and files
//! between an email account and a Google account.

use svx_core::crypto::{KemSecretKey, SigningKey, os_rng};
use svx_protocol::email_account::{CodePurpose, KeyMode};
use svx_protocol::personal::{FileRules, OrgKind};
use svx_protocol::{Method, ProtocolError};
use svx_testkit::*;

macro_rules! world {
    () => {
        match World::new().await {
            Some(w) => w,
            None => return,
        }
    };
}

fn invalid<T: std::fmt::Debug>(r: Result<T, ProtocolError>) -> String {
    match r {
        Err(ProtocolError::Invalid(d)) => d,
        other => panic!("expected a refusal with a reason, got {other:?}"),
    }
}

const PW: &str = "Tangerine-Ocelot-Fjord-42";
const NAMES: (&str, &str) = ("Alice", "Example");
const NO_APPROVAL: FileRules = FileRules {
    require_approval: false,
    one_time: false,
    expires_at: None,
    view_only: false,
    allow_share_requests: false,
};

fn keys() -> (SigningKey, KemSecretKey) {
    let mut rng = os_rng();
    (
        SigningKey::generate_max(&mut rng),
        KemSecretKey::generate_max(&mut rng),
    )
}

/// Let the next code be asked for right away.
async fn age_codes(w: &World) {
    sqlx::query("UPDATE email_challenges SET created_at = created_at - 60")
        .execute(&w.db)
        .await
        .unwrap();
}

#[tokio::test]
async fn email_account_sends_to_and_receives_from_google() {
    let w = world!();
    let alice = w.sign_up_email("Alice.Mail@Example.test", PW, NAMES).await;
    let bob = w.sign_up("bob").await;
    assert!(alice.account.starts_with("u."));
    assert_eq!(alice.email, "Alice.Mail@Example.test");

    // The code email names the code and nothing else useful to a thief.
    let mail = w.mail.sent();
    assert_eq!(mail.len(), 1);
    assert!(
        mail[0]
            .subject
            .ends_with("is your Secure Verified Exchange code")
    );
    assert!(!mail[0].body.contains("http"));
    // ... and the code itself is never stored in clear.
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM notifications")
        .fetch_one(&w.db)
        .await
        .unwrap();
    assert_eq!(stored, 0);

    // Bob finds her by email (any case); her record names her.
    let rec = w.lookup(&bob, "alice.mail@example.TEST").await.unwrap();
    assert_eq!(rec.org_id, alice.account);
    assert_eq!(rec.kind, OrgKind::Personal);
    assert_eq!(rec.display_name, "Alice Example");
    assert_eq!(
        rec.account_email.as_deref(),
        Some("Alice.Mail@Example.test")
    );

    // Files both ways.
    let (file, _) = w.send(&alice, &[&bob], NO_APPROVAL).await.unwrap();
    assert_eq!(w.open_personal(&bob, &file).await.unwrap(), SECRET);
    let (file, _) = w.send(&bob, &[&alice], NO_APPROVAL).await.unwrap();
    assert_eq!(w.open_personal(&alice, &file).await.unwrap(), SECRET);

    // Requests are signed with the device key, as for Google accounts.
    let me: svx_protocol::personal::Account = w.get(&alice, "/v1/me").await.unwrap();
    assert_eq!(me.issuer, "svx:email");
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn codes_are_single_use_short_lived_and_limited() {
    let w = world!();
    let email = "carol.mail@example.test";
    let (sign, kem) = keys();
    let (challenge, code) = w.email_code(email, CodePurpose::SignUp).await.unwrap();
    let code = code.unwrap();
    let wrong = if code == "000000" { "000001" } else { "000000" };

    // Asking again at once is refused; a little later it's fine.
    assert!(invalid(w.email_code(email, CodePurpose::SignUp).await).contains("half a minute"));

    // Wrong codes, malformed codes and another address's code fail.
    for bad in [wrong, "12345", "abcdef"] {
        let e = invalid(
            w.email_account(
                email,
                PW,
                Some(NAMES),
                challenge,
                bad,
                &sign,
                &kem,
                KeyMode::Keep,
            )
            .await,
        );
        assert!(e.contains("code"), "{e}");
    }
    assert!(
        invalid(
            w.email_account(
                "dave@example.test",
                PW,
                Some(NAMES),
                challenge,
                &code,
                &sign,
                &kem,
                KeyMode::Keep
            )
            .await
        )
        .contains("code")
    );

    // Five tries per code, the right one included. One wrong code was
    // counted (malformed codes and other addresses never match), so after
    // four more ...
    for _ in 0..4 {
        let _ = w
            .email_account(
                email,
                PW,
                Some(NAMES),
                challenge,
                wrong,
                &sign,
                &kem,
                KeyMode::Keep,
            )
            .await;
    }
    // ... now even the right code is refused.
    assert!(
        invalid(
            w.email_account(
                email,
                PW,
                Some(NAMES),
                challenge,
                &code,
                &sign,
                &kem,
                KeyMode::Keep
            )
            .await
        )
        .contains("expired")
    );

    // A fresh code works once.
    age_codes(&w).await;
    let (challenge, code) = w.email_code(email, CodePurpose::SignUp).await.unwrap();
    let code = code.unwrap();
    w.email_account(
        email,
        PW,
        Some(NAMES),
        challenge,
        &code,
        &sign,
        &kem,
        KeyMode::Keep,
    )
    .await
    .unwrap();
    assert!(
        invalid(
            w.email_account(
                email,
                PW,
                Some(NAMES),
                challenge,
                &code,
                &sign,
                &kem,
                KeyMode::Keep
            )
            .await
        )
        .contains("code")
    );

    // Expired codes are refused.
    age_codes(&w).await;
    let (challenge, code) = w.email_code(email, CodePurpose::SignIn).await.unwrap();
    sqlx::query("UPDATE email_challenges SET expires_at = 0")
        .execute(&w.db)
        .await
        .unwrap();
    assert!(
        invalid(
            w.email_account(
                email,
                PW,
                None,
                challenge,
                &code.unwrap(),
                &sign,
                &kem,
                KeyMode::Keep
            )
            .await
        )
        .contains("expired")
    );

    // A reset-password code can't create keys.
    age_codes(&w).await;
    let (challenge, code) = w
        .email_code(email, CodePurpose::ResetPassword)
        .await
        .unwrap();
    assert!(
        invalid(
            w.email_account(
                email,
                PW,
                None,
                challenge,
                &code.unwrap(),
                &sign,
                &kem,
                KeyMode::Keep
            )
            .await
        )
        .contains("code")
    );

    // At most five codes an hour per address.
    for _ in 0..2 {
        age_codes(&w).await;
        w.email_code(email, CodePurpose::SignIn).await.unwrap();
    }
    age_codes(&w).await;
    assert!(invalid(w.email_code(email, CodePurpose::SignIn).await).contains("too many"));
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn code_requests_dont_reveal_accounts() {
    let w = world!();
    let _alice = w.sign_up_email("alice.mail@example.test", PW, NAMES).await;
    let _bob = w.sign_up("bob").await;
    let before = w.mail.sent().len();
    // Sign-in codes for an address without an email account (nobody, or a
    // Google account) succeed the same way but send nothing.
    for email in ["nobody@example.test", "bob@example.test"] {
        let (_, code) = w.email_code(email, CodePurpose::SignIn).await.unwrap();
        assert!(code.is_none());
        // The same limits apply to every address.
        assert!(invalid(w.email_code(email, CodePurpose::SignIn).await).contains("half a minute"));
        age_codes(&w).await;
        let (_, code) = w
            .email_code(email, CodePurpose::ResetPassword)
            .await
            .unwrap();
        assert!(code.is_none());
    }
    assert_eq!(w.mail.sent().len(), before);
    // An email account gets its code.
    age_codes(&w).await;
    let (_, code) = w
        .email_code("alice.mail@example.test", CodePurpose::SignIn)
        .await
        .unwrap();
    assert!(code.is_some());
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn weak_passwords_bad_names_and_taken_emails_are_refused() {
    let w = world!();
    let _bob = w.sign_up("bob").await;
    let email = "erin@example.test";
    let (sign, kem) = keys();
    // The service checks even if the app is bypassed.
    for (i, (pw, names)) in [
        ("short", NAMES),
        ("Password123!", NAMES),
        ("ErinExample2024", ("Erin", "Example")),
        (PW, ("bob@bank.test", "Example")),
        (PW, ("Erin", "")),
    ]
    .into_iter()
    .enumerate()
    {
        if i > 0 {
            age_codes(&w).await;
        }
        let (challenge, code) = w.email_code(email, CodePurpose::SignUp).await.unwrap();
        let e = invalid(
            w.email_account(
                email,
                pw,
                Some(names),
                challenge,
                &code.unwrap(),
                &sign,
                &kem,
                KeyMode::Keep,
            )
            .await,
        );
        assert!(e.contains("password") || e.contains("name"), "{pw}: {e}");
        // Too many codes an hour otherwise.
        sqlx::query("DELETE FROM email_challenges")
            .execute(&w.db)
            .await
            .unwrap();
    }
    // Bob's address already has a (Google) account.
    let (challenge, code) = w
        .email_code("Bob@Example.test", CodePurpose::SignUp)
        .await
        .unwrap();
    let e = invalid(
        w.email_account(
            "Bob@Example.test",
            PW,
            Some(("Bob", "Example")),
            challenge,
            &code.unwrap(),
            &sign,
            &kem,
            KeyMode::Keep,
        )
        .await,
    );
    assert!(e.contains("another sign-in provider"), "{e}");
    // Bob signed up through the test provider (neither Google nor email).
    assert!(
        e.ends_with("it signs in with another sign-in method"),
        "{e}"
    );
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn new_device_lock_out_reset_and_change() {
    let w = world!();
    let email = "alice.mail@example.test";
    let alice = w.sign_up_email(email, PW, NAMES).await;

    // Sign-up again for the same address: sign in instead.
    age_codes(&w).await;
    let (sign, kem) = keys();
    let (challenge, code) = w.email_code(email, CodePurpose::SignUp).await.unwrap();
    assert!(
        invalid(
            w.email_account(
                email,
                PW,
                Some(NAMES),
                challenge,
                &code.unwrap(),
                &sign,
                &kem,
                KeyMode::Keep
            )
            .await
        )
        .contains("sign in instead")
    );

    // New device: the restored keys sign in; other keys need a reset.
    age_codes(&w).await;
    let (challenge, code) = w.email_code(email, CodePurpose::SignIn).await.unwrap();
    let code = code.unwrap();
    // A wrong password doesn't use up the code.
    assert!(
        invalid(
            w.email_account(
                email,
                "Wrong-Password-123",
                None,
                challenge,
                &code,
                &alice.sign,
                &alice.kem,
                KeyMode::Keep
            )
            .await
        )
        .contains("password")
    );
    let a = w
        .email_account(
            email,
            PW,
            None,
            challenge,
            &code,
            &alice.sign,
            &alice.kem,
            KeyMode::Keep,
        )
        .await
        .unwrap();
    assert_eq!(a.account, alice.account);
    age_codes(&w).await;
    let (challenge, code) = w.email_code(email, CodePurpose::SignIn).await.unwrap();
    let code = code.unwrap();
    assert!(
        invalid(
            w.email_account(
                email,
                PW,
                None,
                challenge,
                &code,
                &sign,
                &kem,
                KeyMode::Keep
            )
            .await
        )
        .contains("reset")
    );
    let a = w
        .email_account(
            email,
            PW,
            None,
            challenge,
            &code,
            &sign,
            &kem,
            KeyMode::Reset,
        )
        .await
        .unwrap();
    assert_eq!(a.account, alice.account);
    let alice = svx_testkit::personal::Person {
        account: a.account,
        email: a.email,
        sign,
        kem,
    };

    // Ten wrong passwords lock the account, even for the right one.
    sqlx::query("UPDATE email_accounts SET failed = 9")
        .execute(&w.db)
        .await
        .unwrap();
    age_codes(&w).await;
    let (challenge, code) = w.email_code(email, CodePurpose::SignIn).await.unwrap();
    let code = code.unwrap();
    let _ = w
        .email_account(
            email,
            "Wrong-Password-123",
            None,
            challenge,
            &code,
            &alice.sign,
            &alice.kem,
            KeyMode::Keep,
        )
        .await;
    assert!(
        invalid(
            w.email_account(
                email,
                PW,
                None,
                challenge,
                &code,
                &alice.sign,
                &alice.kem,
                KeyMode::Keep
            )
            .await
        )
        .contains("too many wrong passwords")
    );

    // Forgot password: a reset code and a strong new password unlock it.
    age_codes(&w).await;
    let (challenge, code) = w
        .email_code(email, CodePurpose::ResetPassword)
        .await
        .unwrap();
    let code = code.unwrap();
    let reset = |pw: &'static str| svx_protocol::email_account::PasswordResetRequest {
        challenge,
        code: code.clone(),
        email: email.into(),
        new_password: pw.into(),
    };
    let r: Result<serde_json::Value, _> = w
        .client
        .post_json(
            &w.service_url,
            "/v1/auth/email/reset",
            &reset("weakpassword1"),
            None,
        )
        .await;
    assert!(invalid(r).contains("stronger"));
    let new_pw = "Marmalade-Quokka-Glacier-7";
    let _: serde_json::Value = w
        .client
        .post_json(&w.service_url, "/v1/auth/email/reset", &reset(new_pw), None)
        .await
        .unwrap();
    // The old password no longer works; the new one does.
    age_codes(&w).await;
    let (challenge, code) = w.email_code(email, CodePurpose::SignIn).await.unwrap();
    let code = code.unwrap();
    assert!(
        w.email_account(
            email,
            PW,
            None,
            challenge,
            &code,
            &alice.sign,
            &alice.kem,
            KeyMode::Keep
        )
        .await
        .is_err()
    );
    w.email_account(
        email,
        new_pw,
        None,
        challenge,
        &code,
        &alice.sign,
        &alice.kem,
        KeyMode::Keep,
    )
    .await
    .unwrap();

    // Change password from the signed-in device.
    let change = |current: &str, new: &str| svx_protocol::email_account::ChangePasswordRequest {
        current_password: current.into(),
        new_password: new.into(),
    };
    let r: Result<serde_json::Value, _> = w
        .call(
            &alice,
            Method::POST,
            "/v1/me/password",
            Some(&change(PW, "Another-Long-Phrase-99")),
        )
        .await;
    assert!(invalid(r).contains("password"));
    let r: Result<serde_json::Value, _> = w
        .call(
            &alice,
            Method::POST,
            "/v1/me/password",
            Some(&change(new_pw, "alice.mail2024")),
        )
        .await;
    assert!(invalid(r).contains("stronger"));
    let _: serde_json::Value = w
        .call(
            &alice,
            Method::POST,
            "/v1/me/password",
            Some(&change(new_pw, "Another-Long-Phrase-99")),
        )
        .await
        .unwrap();
    // Google accounts have no password.
    let bob = w.sign_up("bob").await;
    let r: Result<serde_json::Value, _> = w
        .call(
            &bob,
            Method::POST,
            "/v1/me/password",
            Some(&change(PW, "Another-Long-Phrase-99")),
        )
        .await;
    assert!(invalid(r).contains("Google"));
    w.cleanup().await.unwrap();
}
