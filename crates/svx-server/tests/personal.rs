//! Personal accounts end to end: sign-up with the "Google" dev IdP, the
//! email directory, sender approval, one-time files, revocation, expiry and
//! signed device requests.

use std::io::Cursor;

use svx_protocol::personal::OrgKind;
use svx_protocol::personal::{
    ApprovalRequest, FileRules, FileStatus, History, PersonalReleaseResponse, RecipientState,
    ReleaseMode, RequestKind, ShareState, ShareStatus, UpdateFileRequest, sign_request,
};
use svx_protocol::{DenyReason, Method, ProtocolError, ReleaseSession};
use svx_testkit::personal::Person;
use svx_testkit::*;

macro_rules! world {
    () => {
        match World::new().await {
            Some(w) => w,
            None => return,
        }
    };
}

fn denied<T: std::fmt::Debug>(r: Result<T, ProtocolError>) -> DenyReason {
    match r {
        Err(ProtocolError::Denied(d)) => d,
        other => panic!("expected a denial, got {other:?}"),
    }
}

fn invalid<T: std::fmt::Debug>(r: Result<T, ProtocolError>) -> String {
    match r {
        Err(ProtocolError::Invalid(d)) => d,
        other => panic!("expected a refusal with a reason, got {other:?}"),
    }
}

const NO_APPROVAL: FileRules = FileRules {
    require_approval: false,
    one_time: false,
    expires_at: None,
    view_only: false,
    allow_share_requests: false,
};

async fn requests(w: &World, p: &Person) -> Vec<ApprovalRequest> {
    w.get(p, "/v1/me/requests").await.unwrap()
}

async fn decide(
    w: &World,
    p: &Person,
    req: &ApprovalRequest,
    decision: &str,
) -> Result<ApprovalRequest, ProtocolError> {
    w.call::<(), _>(
        p,
        Method::POST,
        &format!("/v1/me/requests/{}/{decision}", hex::encode(req.request_id)),
        None,
    )
    .await
}

async fn update(
    w: &World,
    p: &Person,
    status: &FileStatus,
    u: &UpdateFileRequest,
) -> Result<FileStatus, ProtocolError> {
    w.call(
        p,
        Method::PATCH,
        &format!("/v1/me/files/{}", hex::encode(status.artifact_id)),
        Some(u),
    )
    .await
}

#[tokio::test]
async fn sign_up_restore_reset_and_directory() {
    let w = world!();
    let alice = w.sign_up("alice").await;
    let bob = w.sign_up("bob").await;
    assert!(alice.account.starts_with("u.") && alice.account.len() == 18);
    assert_eq!(alice.email, "alice@example.test");

    let me: svx_protocol::personal::Account = w.get(&alice, "/v1/me").await.unwrap();
    assert_eq!(me.account, alice.account);

    // Alice finds Bob by email (any case): a signed personal record with his keys.
    let rec = w.lookup(&alice, "Bob@Example.test").await.unwrap();
    assert_eq!(rec.org_id, bob.account);
    assert_eq!(rec.kind, OrgKind::Personal);
    assert_eq!(rec.account_email.as_deref(), Some("bob@example.test"));
    assert_eq!(
        rec.active_kem_key().unwrap().public_key,
        bob.kem.public_key().to_vec()
    );
    assert!(w.lookup(&alice, "nobody@example.test").await.is_err());

    // Eve's provider didn't confirm an email: no account.
    let mut rng = svx_core::crypto::os_rng();
    let sign = svx_core::crypto::SigningKey::generate_max(&mut rng);
    let kem = svx_core::crypto::KemSecretKey::generate_max(&mut rng);
    assert!(invalid(w.sign_up_with("eve", &sign, &kem, false).await).contains("email"));

    // Signing in again with the restored keys is fine; new keys need a reset.
    let again = w
        .sign_up_with("alice", &alice.sign, &alice.kem, false)
        .await
        .unwrap();
    assert_eq!(again.account, alice.account);
    assert!(invalid(w.sign_up_with("alice", &sign, &kem, false).await).contains("reset"));
    let reset = w.sign_up_with("alice", &sign, &kem, true).await.unwrap();
    assert_eq!(reset.account, alice.account);
    // The old device key no longer works.
    assert_eq!(
        denied(w.get::<serde_json::Value>(&alice, "/v1/me").await),
        DenyReason::NotAuthorized
    );
    let new_alice = Person {
        account: alice.account.clone(),
        email: alice.email.clone(),
        sign,
        kem,
    };
    let rec = w.lookup(&bob, "alice@example.test").await.unwrap();
    assert_eq!(
        rec.active_kem_key().unwrap().public_key,
        new_alice.kem.public_key().to_vec()
    );
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn approval_then_one_time_open() {
    let w = world!();
    let alice = w.sign_up("alice").await;
    let bob = w.sign_up("bob").await;
    let carol = w.sign_up("carol").await;
    let (file, status) = w.send(&alice, &[&bob], FileRules::default()).await.unwrap();
    assert_eq!(status.recipients[0].state, RecipientState::NotOpened);

    // Bob asks: pending, and Alice gets one email (no file name, no link).
    let session = ReleaseSession::new();
    let first = w.ask(&bob, &file, &session).await.unwrap();
    let PersonalReleaseResponse::Pending {
        request_id,
        sender_email,
        ..
    } = first
    else {
        panic!("expected pending, got {first:?}");
    };
    assert_eq!(sender_email.as_deref(), Some("alice@example.test"));
    let mail = w.mail.sent();
    assert_eq!(mail.len(), 1);
    assert_eq!(mail[0].to, "alice@example.test");
    assert!(mail[0].subject.contains("bob@example.test"));
    assert!(!mail[0].body.contains("note.txt") && !mail[0].body.contains("http"));

    // Polling repeats the request: same request, no second email.
    let PersonalReleaseResponse::Pending {
        request_id: id2, ..
    } = w.ask(&bob, &file, &session).await.unwrap()
    else {
        panic!("expected pending");
    };
    assert_eq!(id2, request_id);
    assert_eq!(w.mail.sent().len(), 1);

    // Only Alice sees and decides the request.
    assert!(requests(&w, &bob).await.is_empty());
    let pending = requests(&w, &alice).await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].requester, bob.account);
    assert_eq!(
        pending[0].requester_email.as_deref(),
        Some("bob@example.test")
    );
    assert!(decide(&w, &bob, &pending[0], "approve").await.is_err());
    // Carol isn't a recipient at all.
    assert_eq!(
        denied(w.open_personal(&carol, &file).await),
        DenyReason::NotAuthorized
    );

    decide(&w, &alice, &pending[0], "approve").await.unwrap();
    assert!(requests(&w, &alice).await.is_empty());
    // A decision is final.
    assert!(decide(&w, &alice, &pending[0], "decline").await.is_err());

    let released = w.ask(&bob, &file, &session).await.unwrap();
    assert_eq!(w.finish_open(&bob, &file, &session, released).await, SECRET);

    // One-time: the receipt made it final.
    assert_eq!(
        denied(w.open_personal(&bob, &file).await),
        DenyReason::AlreadyOpened
    );

    let h: History = w.get(&alice, "/v1/me/history").await.unwrap();
    assert_eq!(h.sent.len(), 1);
    assert_eq!(h.sent[0].recipients[0].state, RecipientState::Opened);
    assert_eq!(
        h.sent[0].recipients[0].email.as_deref(),
        Some("bob@example.test")
    );
    let h: History = w.get(&bob, "/v1/me/history").await.unwrap();
    assert_eq!(h.received.len(), 1);
    assert_eq!(h.received[0].state, RecipientState::Opened);
    assert_eq!(
        h.received[0].sender_email.as_deref(),
        Some("alice@example.test")
    );
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn decline_and_revoke_while_pending() {
    let w = world!();
    let alice = w.sign_up("alice").await;
    let bob = w.sign_up("bob").await;
    let carol = w.sign_up("carol").await;
    let (file, status) = w
        .send(&alice, &[&bob, &carol], FileRules::default())
        .await
        .unwrap();
    assert_eq!(status.recipients.len(), 2);

    // Bob is declined.
    let s = ReleaseSession::new();
    w.ask(&bob, &file, &s).await.unwrap();
    // Carol asks too, then Alice revokes her while it's pending.
    let sc = ReleaseSession::new();
    w.ask(&carol, &file, &sc).await.unwrap();
    let pending = requests(&w, &alice).await;
    assert_eq!(pending.len(), 2);
    let bobs = pending.iter().find(|r| r.requester == bob.account).unwrap();
    decide(&w, &alice, bobs, "decline").await.unwrap();
    assert_eq!(denied(w.ask(&bob, &file, &s).await), DenyReason::Declined);

    let st = update(
        &w,
        &alice,
        &status,
        &UpdateFileRequest {
            revoke_recipients: vec![carol.account.clone()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let carol_state = st
        .recipients
        .iter()
        .find(|r| r.account == carol.account)
        .unwrap()
        .state;
    assert_eq!(carol_state, RecipientState::Revoked);
    // Even an approval now doesn't help.
    let carols = pending
        .iter()
        .find(|r| r.requester == carol.account)
        .unwrap();
    decide(&w, &alice, carols, "approve").await.unwrap();
    assert_eq!(
        denied(w.ask(&carol, &file, &sc).await),
        DenyReason::ExpiredOrRevoked
    );

    // Revoking the whole file stops everyone.
    update(
        &w,
        &alice,
        &status,
        &UpdateFileRequest {
            revoke: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        denied(w.ask(&bob, &file, &ReleaseSession::new()).await),
        DenyReason::ExpiredOrRevoked
    );
    let h: History = w.get(&bob, "/v1/me/history").await.unwrap();
    assert_eq!(h.received[0].state, RecipientState::Revoked);
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn rules_without_approval_one_time_and_expiry() {
    let w = world!();
    let alice = w.sign_up("alice").await;
    let bob = w.sign_up("bob").await;

    // No approval, not one-time: Bob opens it as often as he likes.
    let (file, status) = w.send(&alice, &[&bob], NO_APPROVAL).await.unwrap();
    assert_eq!(w.open_personal(&bob, &file).await.unwrap(), SECRET);
    assert_eq!(w.open_personal(&bob, &file).await.unwrap(), SECRET);
    assert!(w.mail.sent().is_empty());

    // One-time without approval: a retry is allowed until the receipt...
    let (file, _) = w
        .send(
            &alice,
            &[&bob],
            FileRules {
                one_time: true,
                ..NO_APPROVAL
            },
        )
        .await
        .unwrap();
    let r = w.ask(&bob, &file, &ReleaseSession::new()).await.unwrap();
    assert!(matches!(r, PersonalReleaseResponse::Released { .. }));
    assert_eq!(w.open_personal(&bob, &file).await.unwrap(), SECRET);
    assert_eq!(
        denied(w.open_personal(&bob, &file).await),
        DenyReason::AlreadyOpened
    );
    // ...or until the retry window passes.
    let (file, _) = w
        .send(
            &alice,
            &[&bob],
            FileRules {
                one_time: true,
                ..NO_APPROVAL
            },
        )
        .await
        .unwrap();
    w.ask(&bob, &file, &ReleaseSession::new()).await.unwrap();
    sqlx::query("UPDATE opens SET first_released_at = first_released_at - 601")
        .execute(&w.db)
        .await
        .unwrap();
    assert_eq!(
        denied(w.ask(&bob, &file, &ReleaseSession::new()).await),
        DenyReason::AlreadyOpened
    );

    // The expiry can't be later than the signed one.
    let late = UpdateFileRequest {
        expires_at: Some(status.signed_expires_at.unwrap() + 60),
        ..Default::default()
    };
    assert!(invalid(update(&w, &alice, &status, &late).await).contains("expiry"));
    w.cleanup().await.unwrap();
}

/// A file Alice made for Bob but never registered.
async fn w_file(w: &World, alice: &Person, bob: &Person) -> Vec<u8> {
    w.pack_personal(alice, &[bob], Some(now() + 3600))
}

#[tokio::test]
async fn expired_unregistered_and_foreign_files() {
    let w = world!();
    let alice = w.sign_up("alice").await;
    let bob = w.sign_up("bob").await;
    let (file, status) = w.send(&alice, &[&bob], NO_APPROVAL).await.unwrap();
    update(
        &w,
        &alice,
        &status,
        &UpdateFileRequest {
            expires_at: Some(now() - 1),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        denied(w.open_personal(&bob, &file).await),
        DenyReason::ExpiredOrRevoked
    );

    // Not registered: refused.
    let loose = w_file(&w, &alice, &bob).await;
    assert_eq!(
        denied(w.open_personal(&bob, &loose).await),
        DenyReason::InvalidArtifact
    );
    // Only the sender can register it, and only once.
    assert!(w.register(&bob, &loose, NO_APPROVAL).await.is_err());
    w.register(&alice, &loose, NO_APPROVAL).await.unwrap();
    assert!(w.register(&alice, &loose, NO_APPROVAL).await.is_err());
    // Only the sender sees or changes its rules.
    let path = format!("/v1/me/files/{}", hex::encode(status.artifact_id));
    assert!(w.get::<FileStatus>(&bob, &path).await.is_err());
    assert!(
        update(&w, &bob, &status, &UpdateFileRequest::default())
            .await
            .is_err()
    );

    // A personal file can't be opened through the company release.
    let session = ReleaseSession::new();
    let token = w.token(EXAMPLE, "alice", &session.nonce()).await;
    let mut trust = svx_core::TrustStore::new();
    w.client
        .org_record(&w.service_url, &alice.account, &w.registry_key())
        .await
        .unwrap()
        .add_signing_keys_to(&mut trust)
        .unwrap();
    let v = svx_core::verify(Cursor::new(&loose), &trust).unwrap();
    let r = w
        .client
        .release(&w.service_url, &w.agent_url, &session, v.head(), &token)
        .await;
    assert!(matches!(r, Err(ProtocolError::Denied(_))), "{r:?}");
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn signed_requests_are_single_use_and_bound() {
    let w = world!();
    let alice = w.sign_up("alice").await;
    let bob = w.sign_up("bob").await;
    let http = w.client.http();
    let send = |auth: svx_protocol::personal::RequestAuth, path: &str| {
        let mut req = http.get(format!("{}{path}", w.service_url));
        for (k, v) in auth.headers() {
            req = req.header(k, v);
        }
        req.send()
    };

    let auth = sign_request(&alice.sign, &alice.account, "GET", "/v1/me", b"", now()).unwrap();
    assert_eq!(send(auth.clone(), "/v1/me").await.unwrap().status(), 200);
    // The same signed request again: replay.
    assert_eq!(send(auth, "/v1/me").await.unwrap().status(), 401);
    // Signed for another path.
    let auth = sign_request(&alice.sign, &alice.account, "GET", "/v1/me", b"", now()).unwrap();
    assert_eq!(send(auth, "/v1/me/history").await.unwrap().status(), 401);
    // Too old.
    let auth = sign_request(
        &alice.sign,
        &alice.account,
        "GET",
        "/v1/me",
        b"",
        now() - 120,
    )
    .unwrap();
    assert_eq!(send(auth, "/v1/me").await.unwrap().status(), 401);
    // Bob's key can't speak for Alice.
    let auth = sign_request(&bob.sign, &alice.account, "GET", "/v1/me", b"", now()).unwrap();
    assert_eq!(send(auth, "/v1/me").await.unwrap().status(), 401);
    // No headers at all.
    assert_eq!(
        http.get(format!("{}/v1/me", w.service_url))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    w.cleanup().await.unwrap();
}

const VIEW_ONLY: FileRules = FileRules {
    require_approval: false,
    one_time: false,
    expires_at: None,
    view_only: true,
    allow_share_requests: true,
};

async fn share(
    w: &World,
    p: &Person,
    file: &FileStatus,
    ask: bool,
) -> Result<ShareStatus, ProtocolError> {
    let path = format!("/v1/personal/share/{}", hex::encode(file.artifact_id));
    if ask {
        w.call::<(), _>(p, Method::POST, &path, None).await
    } else {
        w.get(p, &path).await
    }
}

#[tokio::test]
async fn a_view_only_file_can_be_saved_only_with_the_senders_permission() {
    let w = world!();
    let alice = w.sign_up("alice").await;
    let bob = w.sign_up("bob").await;
    let carol = w.sign_up("carol").await;
    let (file, status) = w.send(&alice, &[&bob], VIEW_ONLY).await.unwrap();
    assert!(status.rules.view_only && status.rules.allow_share_requests);

    // Saving is refused before anything is used up; viewing is released.
    let save = ReleaseSession::new();
    assert_eq!(
        denied(w.ask(&bob, &file, &save).await),
        DenyReason::ViewOnly
    );
    let view = ReleaseSession::new();
    let released = w
        .ask_for(&bob, &file, &view, ReleaseMode::View)
        .await
        .unwrap();
    assert!(matches!(
        released,
        PersonalReleaseResponse::Released {
            view_only: true,
            ..
        }
    ));
    assert_eq!(w.finish_open(&bob, &file, &view, released).await, SECRET);

    // Bob asks to keep it: pending, one email to Alice (no name, no link),
    // and asking again neither duplicates the request nor the email.
    assert_eq!(
        share(&w, &bob, &status, false).await.unwrap().state,
        ShareState::NotRequested
    );
    let asked = share(&w, &bob, &status, true).await.unwrap();
    assert_eq!(asked.state, ShareState::Pending);
    assert!(asked.expires_at.is_some());
    assert_eq!(
        share(&w, &bob, &status, true).await.unwrap().state,
        ShareState::Pending
    );
    let mail = w.mail.sent();
    assert_eq!(mail.len(), 1);
    assert_eq!(mail[0].to, "alice@example.test");
    assert!(mail[0].subject.contains("bob@example.test"));
    assert!(!mail[0].body.contains("note.txt") && !mail[0].body.contains("http"));

    // Alice's Requests shows it as a share request; only she can decide.
    let pending = requests(&w, &alice).await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].kind, RequestKind::Share);
    assert!(requests(&w, &bob).await.is_empty());
    assert!(decide(&w, &bob, &pending[0], "approve").await.is_err());
    // Still no saving while pending.
    assert_eq!(
        denied(w.ask(&bob, &file, &ReleaseSession::new()).await),
        DenyReason::ViewOnly
    );

    // A decline stands: Bob can't ask again right away.
    decide(&w, &alice, &pending[0], "decline").await.unwrap();
    assert_eq!(
        share(&w, &bob, &status, false).await.unwrap().state,
        ShareState::Declined
    );
    assert_eq!(
        share(&w, &bob, &status, true).await.unwrap().state,
        ShareState::Declined
    );
    assert_eq!(
        denied(w.ask(&bob, &file, &ReleaseSession::new()).await),
        DenyReason::ViewOnly
    );
    assert!(requests(&w, &alice).await.is_empty());

    // Another file: approved, so Bob can save it. Carol, who isn't a recipient, can't even ask.
    let (file2, status2) = w.send(&alice, &[&bob], VIEW_ONLY).await.unwrap();
    assert!(share(&w, &carol, &status2, true).await.is_err());
    assert!(share(&w, &carol, &status2, false).await.is_err());
    share(&w, &bob, &status2, true).await.unwrap();
    let pending = requests(&w, &alice).await;
    decide(&w, &alice, &pending[0], "approve").await.unwrap();
    let ok = share(&w, &bob, &status2, false).await.unwrap();
    assert_eq!(ok.state, ShareState::Approved);
    assert!(ok.expires_at.unwrap() > now());
    let session = ReleaseSession::new();
    let released = w.ask(&bob, &file2, &session).await.unwrap();
    assert!(matches!(
        released,
        PersonalReleaseResponse::Released {
            view_only: true,
            ..
        }
    ));
    assert_eq!(
        w.finish_open(&bob, &file2, &session, released).await,
        SECRET
    );
    // Approval for one file says nothing about another.
    assert_eq!(
        denied(w.ask(&bob, &file, &ReleaseSession::new()).await),
        DenyReason::ViewOnly
    );
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn view_only_rules_are_the_senders_to_change() {
    let w = world!();
    let alice = w.sign_up("alice").await;
    let bob = w.sign_up("bob").await;
    let no_asking = FileRules {
        allow_share_requests: false,
        ..VIEW_ONLY
    };
    let (file, status) = w.send(&alice, &[&bob], no_asking).await.unwrap();

    // Without "let them ask", there is nothing to ask.
    assert_eq!(
        share(&w, &bob, &status, false).await.unwrap().state,
        ShareState::Forbidden
    );
    assert_eq!(
        denied(share(&w, &bob, &status, true).await),
        DenyReason::NotAuthorized
    );
    assert!(requests(&w, &alice).await.is_empty());
    assert_eq!(
        denied(w.ask(&bob, &file, &ReleaseSession::new()).await),
        DenyReason::ViewOnly
    );

    // Alice allows asking, then lifts view-only altogether.
    let u = UpdateFileRequest {
        allow_share_requests: Some(true),
        ..Default::default()
    };
    assert!(
        update(&w, &alice, &status, &u)
            .await
            .unwrap()
            .rules
            .allow_share_requests
    );
    assert_eq!(
        share(&w, &bob, &status, false).await.unwrap().state,
        ShareState::NotRequested
    );
    let u = UpdateFileRequest {
        view_only: Some(false),
        ..Default::default()
    };
    let now_open = update(&w, &alice, &status, &u).await.unwrap();
    assert!(!now_open.rules.view_only);
    // "Let them ask" means nothing for a file that isn't view-only.
    assert!(!now_open.rules.allow_share_requests);
    assert_eq!(
        share(&w, &bob, &status, false).await.unwrap().state,
        ShareState::Unrestricted
    );
    assert_eq!(
        share(&w, &bob, &status, true).await.unwrap().state,
        ShareState::Unrestricted
    );
    assert!(requests(&w, &alice).await.is_empty());
    let session = ReleaseSession::new();
    let released = w.ask(&bob, &file, &session).await.unwrap();
    assert!(matches!(
        released,
        PersonalReleaseResponse::Released {
            view_only: false,
            ..
        }
    ));

    // Only the sender can change the rules.
    let u = UpdateFileRequest {
        view_only: Some(true),
        ..Default::default()
    };
    assert!(update(&w, &bob, &status, &u).await.is_err());
    // A file that was never view-only: "let them ask" is dropped at registration.
    let loose = FileRules {
        view_only: false,
        allow_share_requests: true,
        ..NO_APPROVAL
    };
    let (_, st) = w.send(&alice, &[&bob], loose).await.unwrap();
    assert!(!st.rules.allow_share_requests);
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn share_requests_and_open_requests_stay_apart() {
    let w = world!();
    let alice = w.sign_up("alice").await;
    let bob = w.sign_up("bob").await;
    let ask_first = FileRules {
        require_approval: true,
        ..VIEW_ONLY
    };
    let (file, status) = w.send(&alice, &[&bob], ask_first).await.unwrap();

    // Viewing still needs the sender's approval to open.
    let view = ReleaseSession::new();
    let first = w
        .ask_for(&bob, &file, &view, ReleaseMode::View)
        .await
        .unwrap();
    assert!(matches!(first, PersonalReleaseResponse::Pending { .. }));
    share(&w, &bob, &status, true).await.unwrap();
    let pending = requests(&w, &alice).await;
    assert_eq!(pending.len(), 2);
    let share_req = pending
        .iter()
        .find(|r| r.kind == RequestKind::Share)
        .unwrap();
    let open_req = pending
        .iter()
        .find(|r| r.kind == RequestKind::Open)
        .unwrap();

    // Approving the share request doesn't open the file...
    decide(&w, &alice, share_req, "approve").await.unwrap();
    let again = w
        .ask_for(&bob, &file, &view, ReleaseMode::View)
        .await
        .unwrap();
    assert!(matches!(again, PersonalReleaseResponse::Pending { .. }));
    // ...and approving the open request doesn't allow saving.
    decide(&w, &alice, open_req, "approve").await.unwrap();
    let released = w
        .ask_for(&bob, &file, &view, ReleaseMode::View)
        .await
        .unwrap();
    assert!(matches!(released, PersonalReleaseResponse::Released { .. }));
    w.cleanup().await.unwrap();
}
