//! Personal accounts through `svx_client::Client`: sign up with the dev
//! "Google", send by email, open with the sender's live approval, one-time
//! files, backup and restore, key reset. Skipped without
//! `SVX_TEST_DATABASE_URL`.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use svx_client::account::LoginMethod;
use svx_client::config::Paths;
use svx_client::defaults::ServiceTarget;
use svx_client::keystore::MemoryStore;
use svx_client::personal::{self, KeyChoice, SendOptions, SignUpOptions};
use svx_client::{Client, ClientError, Output, Step};
use svx_protocol::DenyReason;
use svx_protocol::personal::{FileRules, RecipientState, UpdateFileRequest};
use svx_testkit::*;

macro_rules! world {
    () => {
        match World::new().await {
            Some(w) => w,
            None => return,
        }
    };
}

fn target(w: &World) -> ServiceTarget {
    ServiceTarget {
        service_url: w.service_url.clone(),
        registry_key: w.registry_key_hex(),
        dev: true,
    }
}

fn paths(dir: &Path, name: &str) -> Paths {
    Paths {
        config: dir.join(format!("{name}.toml")),
        session: dir.join(format!("{name}.session.json")),
    }
}

async fn sign_up_as(
    w: &World,
    dir: &Path,
    device: &str,
    who: &str,
    keys: KeyChoice,
) -> svx_client::Result<Client> {
    let (c, info) = personal::sign_up(
        &paths(dir, device),
        Arc::new(MemoryStore::default()),
        SignUpOptions {
            target: target(w),
            issuer: None,
            keys,
            default_output_dir: Some(dir.join(format!("{device}-out"))),
            replace: false,
        },
        LoginMethod::Dev(who.to_owned()),
    )
    .await?;
    assert_eq!(info.email, format!("{who}@example.test"));
    Ok(c)
}

fn out(dir: &Path, name: &str) -> Option<Output> {
    Some(Output::Dir {
        dir: dir.join(name),
        overwrite: false,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_approve_open_once() {
    let w = world!();
    let d = tempfile::tempdir().unwrap();
    let alice = sign_up_as(&w, d.path(), "alice", "alice", KeyChoice::New)
        .await
        .unwrap();
    let bob = Arc::new(
        sign_up_as(&w, d.path(), "bob", "bob", KeyChoice::New)
            .await
            .unwrap(),
    );
    assert!(bob.cfg.is_personal());
    let found = alice.lookup("BOB@example.test").await.unwrap();
    assert_eq!(found.email, "bob@example.test");
    assert!(matches!(
        alice.lookup("nobody@example.test").await,
        Err(ClientError::Invalid(m)) if m.contains("doesn't have an SVX account")
    ));

    let input = d.path().join("trip-photos.txt");
    std::fs::write(&input, SECRET).unwrap();
    let sent = alice
        .send(SendOptions {
            input: input.clone(),
            output: None,
            overwrite: false,
            to: vec!["bob@example.test".into()],
            rules: FileRules::default(),
            expires_at: None,
            name: None,
        })
        .await
        .unwrap();
    assert_eq!(sent.path, d.path().join("trip-photos.svx"));
    assert_eq!(sent.recipients[0].account, bob.cfg.org_id);

    // Bob opens; it waits for Alice.
    let steps = Arc::new(Mutex::new(Vec::new()));
    let (b, s, file) = (bob.clone(), steps.clone(), sent.path.clone());
    let dir = d.path().to_path_buf();
    let opening = tokio::spawn(async move {
        let never = AtomicBool::new(false);
        let mut progress = |step: Step| s.lock().unwrap().push(step);
        b.open_personal(&file, out(&dir, "bob-1"), &mut progress, &never)
            .await
    });
    let req = loop {
        let r = alice.requests().await.unwrap();
        if let Some(r) = r.into_iter().next() {
            break r;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(req.requester_email.as_deref(), Some("bob@example.test"));
    alice.approve(&hex::encode(req.request_id)).await.unwrap();
    let opened = opening.await.unwrap().unwrap();
    let path = opened.path.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), SECRET);
    assert_eq!(path.file_name().unwrap(), "trip-photos.txt");
    let steps = steps.lock().unwrap().clone();
    assert!(steps.contains(&Step::AwaitingApproval {
        sender: "alice@example.test".into()
    }));
    assert_eq!(steps.last(), Some(&Step::Decrypting));

    // One-time: never again, even through the generic open.
    let never = AtomicBool::new(false);
    let again = bob
        .open_personal(&sent.path, out(d.path(), "bob-2"), &mut |_| {}, &never)
        .await;
    assert!(matches!(
        again,
        Err(ClientError::Denied(DenyReason::AlreadyOpened))
    ));

    let h = alice.history().await.unwrap();
    assert_eq!(h.sent[0].recipients[0].state, RecipientState::Opened);
    let h = bob.history().await.unwrap();
    assert_eq!(
        h.received[0].sender_email.as_deref(),
        Some("alice@example.test")
    );

    // Carol isn't a recipient: refused before asking anyone.
    let carol = sign_up_as(&w, d.path(), "carol", "carol", KeyChoice::New)
        .await
        .unwrap();
    let r = carol
        .open_personal(&sent.path, out(d.path(), "carol"), &mut |_| {}, &never)
        .await;
    assert!(matches!(r, Err(ClientError::NotRecipient { .. })), "{r:?}");
    w.cleanup().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rules_cancel_and_revoke() {
    let w = world!();
    let d = tempfile::tempdir().unwrap();
    let alice = sign_up_as(&w, d.path(), "alice", "alice", KeyChoice::New)
        .await
        .unwrap();
    let bob = sign_up_as(&w, d.path(), "bob", "bob", KeyChoice::New)
        .await
        .unwrap();
    let carol = sign_up_as(&w, d.path(), "carol", "carol", KeyChoice::New)
        .await
        .unwrap();
    let folder = d.path().join("project");
    std::fs::create_dir(&folder).unwrap();
    std::fs::write(folder.join("plan.txt"), SECRET).unwrap();
    let sent = alice
        .send(SendOptions {
            input: folder,
            output: None,
            overwrite: false,
            to: vec!["bob@example.test".into(), "carol@example.test".into()],
            rules: FileRules {
                require_approval: false,
                one_time: false,
                expires_at: None,
            },
            expires_at: Some(now() + 3600),
            name: None,
        })
        .await
        .unwrap();
    assert_eq!(sent.recipients.len(), 2);

    // No approval needed: both open (a folder, extracted), Carol twice.
    let never = AtomicBool::new(false);
    let o = bob
        .open_personal(&sent.path, out(d.path(), "b"), &mut |_| {}, &never)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(o.path.unwrap().join("plan.txt")).unwrap(),
        SECRET
    );
    for n in ["c1", "c2"] {
        carol
            .open_personal(&sent.path, out(d.path(), n), &mut |_| {}, &never)
            .await
            .unwrap();
    }

    // Approval switched on later: Carol waits, then cancels.
    let id = sent.artifact_id.clone();
    alice
        .update_file(
            &id,
            &UpdateFileRequest {
                require_approval: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let cancel = AtomicBool::new(false);
    let mut progress = |s: Step| {
        if matches!(s, Step::AwaitingApproval { .. }) {
            cancel.store(true, Ordering::Relaxed);
        }
    };
    let r = carol
        .open_personal(&sent.path, out(d.path(), "c3"), &mut progress, &cancel)
        .await;
    assert!(matches!(r, Err(ClientError::Cancelled)), "{r:?}");

    // Alice revokes Bob only, then declines Carol.
    let st = alice
        .update_file(
            &id,
            &UpdateFileRequest {
                revoke_recipients: vec![bob.cfg.org_id.clone()],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(st.rules.require_approval);
    let r = bob
        .open_personal(&sent.path, out(d.path(), "b2"), &mut |_| {}, &never)
        .await;
    assert!(matches!(
        r,
        Err(ClientError::Denied(DenyReason::ExpiredOrRevoked))
    ));
    let req = alice.requests().await.unwrap().remove(0);
    alice.decline(&hex::encode(req.request_id)).await.unwrap();
    let r = carol
        .open_personal(&sent.path, out(d.path(), "c4"), &mut |_| {}, &never)
        .await;
    assert!(
        matches!(r, Err(ClientError::Denied(DenyReason::Declined))),
        "{r:?}"
    );
    // Bob can't change Alice's file.
    assert!(bob.file_status(&id).await.is_err());
    w.cleanup().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backup_restore_and_reset() {
    let w = world!();
    let d = tempfile::tempdir().unwrap();
    let alice = sign_up_as(&w, d.path(), "laptop", "alice", KeyChoice::New)
        .await
        .unwrap();
    let bob = sign_up_as(&w, d.path(), "bob", "bob", KeyChoice::New)
        .await
        .unwrap();
    let backup = d.path().join("alice.svxbackup");
    assert!(alice.save_backup(&backup, "short").is_err());
    alice.save_backup(&backup, "correct horse battery").unwrap();
    assert!(
        alice.save_backup(&backup, "correct horse battery").is_err(),
        "never overwrites"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&backup).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert!(matches!(
        personal::read_backup(&backup, "wrong horse battery"),
        Err(ClientError::Invalid(_))
    ));

    // A file for Alice, sent while she has her first keys.
    let input = d.path().join("note.txt");
    std::fs::write(&input, SECRET).unwrap();
    let rules = FileRules {
        require_approval: false,
        one_time: false,
        expires_at: None,
    };
    let send = |output: &str| SendOptions {
        input: input.clone(),
        output: Some(d.path().join(output)),
        overwrite: false,
        to: vec!["alice@example.test".into()],
        rules,
        expires_at: None,
        name: None,
    };
    let first = bob.send(send("first.svx")).await.unwrap();

    // A new computer without the backup: told to restore or reset.
    let r = sign_up_as(&w, d.path(), "desktop", "alice", KeyChoice::New).await;
    assert!(
        matches!(r, Err(ClientError::AccountExists)),
        "{:?}",
        r.err()
    );

    // Restoring the backup works, and opens the file.
    let keys = personal::read_backup(&backup, "correct horse battery").unwrap();
    let desktop = sign_up_as(
        &w,
        d.path(),
        "desktop2",
        "alice",
        KeyChoice::Restore(Box::new(keys)),
    )
    .await
    .unwrap();
    assert_eq!(desktop.cfg.org_id, alice.cfg.org_id);
    let never = AtomicBool::new(false);
    desktop
        .open_personal(&first.path, out(d.path(), "d"), &mut |_| {}, &never)
        .await
        .unwrap();
    // Someone else can't use Alice's backup for their account.
    let keys = personal::read_backup(&backup, "correct horse battery").unwrap();
    let r = sign_up_as(
        &w,
        d.path(),
        "carol",
        "carol",
        KeyChoice::Restore(Box::new(keys)),
    )
    .await;
    assert!(matches!(r, Err(ClientError::Invalid(_))), "{:?}", r.err());

    // Reset: new keys; the old devices stop working and old files can't open.
    let reset = sign_up_as(&w, d.path(), "phone", "alice", KeyChoice::Reset)
        .await
        .unwrap();
    assert!(matches!(
        alice.account().await,
        Err(ClientError::Denied(DenyReason::NotAuthorized))
    ));
    let r = reset
        .open_personal(&first.path, out(d.path(), "p1"), &mut |_| {}, &never)
        .await;
    assert!(matches!(r, Err(ClientError::Rejected(_))), "{r:?}");
    let second = bob.send(send("second.svx")).await.unwrap();
    reset
        .open_personal(&second.path, out(d.path(), "p2"), &mut |_| {}, &never)
        .await
        .unwrap();
    assert_eq!(reset.account().await.unwrap().email, "alice@example.test");

    // Signing out removes the keys and the configuration.
    reset.sign_out().unwrap();
    assert!(!d.path().join("phone.toml").exists());
    w.cleanup().await.unwrap();
}

/// A headless "browser": signs in as `user` at the dev IdP and follows its
/// redirect to the service's relay callback, as a real browser would.
fn relay_browser(w: &World, user: &'static str) -> svx_client::login::Opener {
    let http = w.client.http().clone();
    Arc::new(move |u: &url::Url| {
        let mut u = u.clone();
        u.query_pairs_mut().append_pair("login_hint", user);
        let http = http.clone();
        tokio::spawn(async move {
            let r = http.get(u.as_str()).send().await.unwrap();
            let to = r.headers()["location"].to_str().unwrap().to_owned();
            let page = http.get(&to).send().await.unwrap().text().await.unwrap();
            assert!(page.contains("signed in"), "{page}");
        });
        Ok(())
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn apple_style_sign_in_is_relayed_by_the_service() {
    let w = world!();
    let d = tempfile::tempdir().unwrap();
    let t = target(&w);
    let providers = personal::providers(&t).await.unwrap();
    let apple = providers.iter().find(|p| p.name == "Apple").unwrap();
    assert!(apple.relay);
    // The relayed provider's client secret is never published.
    assert!(apple.client_secret.is_none());
    let (c, info) = personal::sign_up(
        &paths(d.path(), "mac"),
        Arc::new(MemoryStore::default()),
        SignUpOptions {
            target: t,
            issuer: Some(apple.issuer.clone()),
            keys: KeyChoice::New,
            default_output_dir: None,
            replace: false,
        },
        LoginMethod::Browser(relay_browser(&w, "alice")),
    )
    .await
    .unwrap();
    assert_eq!(info.email, "alice@privaterelay.example.test");
    assert_eq!(c.account().await.unwrap().provider, w.relay_idp.issuer());
    w.cleanup().await.unwrap();
}
