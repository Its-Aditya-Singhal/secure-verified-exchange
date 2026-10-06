//! Announcements, the shared email allowance and the operator's logs.

use svx_server::admin_ops::{self, LogFilter};
use svx_server::announce::{self, Draft};
use svx_server::limits::{ANNOUNCE_CEILING, MailKind, take_email};
use svx_server::notify::{Attachment, MemoryNotifier};
use svx_testkit::*;

macro_rules! world {
    () => {
        match World::with_options(&WorldOptions::default()).await {
            Some(w) => w,
            None => return,
        }
    };
}

fn draft(files: Vec<Attachment>) -> Draft {
    Draft {
        subject: "SVX 0.2 is here".into(),
        body: "Hello,\n\nFolders now open faster.".into(),
        files,
    }
    .check()
    .unwrap()
}

/// Pretend `n` emails went out in the last 24 hours.
async fn used(w: &World, n: i64) {
    sqlx::query(
        "INSERT INTO email_sends (at, kind) SELECT $1, 'notice' FROM generate_series(1, $2::int)",
    )
    .bind(svx_protocol::unix_now())
    .bind(n as i32)
    .execute(&w.db)
    .await
    .unwrap();
}

async fn states(w: &World, id: i64) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT org_id, state FROM announcement_recipients WHERE announcement_id = $1 ORDER BY org_id",
    )
    .bind(id)
    .fetch_all(&w.db)
    .await
    .unwrap()
}

#[tokio::test]
async fn an_announcement_goes_to_each_chosen_person_alone_with_its_files() {
    let w = world!();
    let alice = w.sign_up("alice").await;
    let bob = w.sign_up("bob").await;
    let carol = w.sign_up("carol").await;
    let eve = w
        .sign_up_email(
            "eve.mail@example.test",
            "orbit-lantern-cobalt-thistle-93",
            ("Eve", "Example"),
        )
        .await;
    admin_ops::suspend(&w.db, &carol.account, None)
        .await
        .unwrap();
    assert!(
        admin_ops::set_announcements_off(&w.db, &eve.account, true)
            .await
            .unwrap()
    );
    let before = w.mail.sent().len();

    let file = Attachment {
        name: "../notes \"v2\".pdf".into(),
        content_type: "application/pdf".into(),
        data: b"%PDF-1.4 fictional".to_vec(),
    };
    let everyone = [&alice, &bob, &carol, &eve].map(|p| p.account.clone());
    let c = announce::create(&w.db, draft(vec![file]), &everyone, false)
        .await
        .unwrap();
    assert_eq!((c.recipients, c.skipped, c.left_out, c.today), (2, 2, 0, 2));

    let mail = MemoryNotifier::default();
    assert_eq!(announce::send_pending(&w.db, &mail, 20).await.unwrap(), 2);
    let sent = mail.sent();
    let mut to: Vec<_> = sent.iter().map(|e| e.to.clone()).collect();
    to.sort();
    let mut want = vec![alice.email.clone(), bob.email.clone()];
    want.sort();
    assert_eq!(to, want, "one email per person, nobody else in it");
    for (e, files) in sent.iter().zip(mail.sent_files()) {
        assert_eq!(e.subject, "SVX 0.2 is here");
        assert!(
            e.body
                .starts_with("Hello,\n\nFolders now open faster.\n\n--\n")
        );
        assert!(e.body.contains("Reply \"unsubscribe\""));
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "notes v2.pdf");
        assert_eq!(files[0].data, b"%PDF-1.4 fictional");
    }
    // Nothing went through the service's own notifier.
    assert_eq!(w.mail.sent().len(), before);

    // Done: the files are gone, the history says so, and it's in the log.
    let list = announce::list(&w.db, 10).await.unwrap();
    assert_eq!(list[0].status, "done");
    assert_eq!((list[0].sent, list[0].pending, list[0].files), (2, 0, 0));
    let (all, ann) = svx_server::limits::emails_last_day(&w.db).await.unwrap();
    assert_eq!(ann, 2);
    assert!(all >= 2);
    let log = admin_ops::logs(
        &w.db,
        &LogFilter {
            event: Some("announcement".into()),
            limit: 10,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(log.len(), 1);
    assert!(log[0].reason.as_deref().unwrap().contains("to 2 people"));

    // Erasing an account removes it from announcement lists too.
    assert!(admin_ops::erase(&w.db, &bob.account).await.unwrap());
    assert_eq!(states(&w, c.id).await.len(), 1);
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn announcements_leave_room_for_sign_up_codes_and_can_wait_for_tomorrow() {
    let w = world!();
    let people = [
        w.sign_up("alice").await,
        w.sign_up("bob").await,
        w.sign_up("carol").await,
    ];
    let ids: Vec<String> = people.iter().map(|p| p.account.clone()).collect();
    used(&w, ANNOUNCE_CEILING - 2).await;

    // Not queued: only those who fit today are added.
    let c = announce::create(&w.db, draft(vec![]), &ids, false)
        .await
        .unwrap();
    assert_eq!((c.recipients, c.left_out, c.today), (2, 1, 2));
    let mail = MemoryNotifier::default();
    assert_eq!(announce::send_pending(&w.db, &mail, 20).await.unwrap(), 2);
    // At the ceiling: no more announcements, but codes still go out.
    assert!(
        announce::create(&w.db, draft(vec![]), &ids, false)
            .await
            .is_err()
    );
    assert!(
        !take_email(&w.db, MailKind::Test, ANNOUNCE_CEILING)
            .await
            .unwrap()
    );
    assert!(take_email(&w.db, MailKind::Code, 480).await.unwrap());

    // Queued: everyone is added and waits.
    let q = announce::create(&w.db, draft(vec![]), &ids, true)
        .await
        .unwrap();
    assert_eq!((q.recipients, q.left_out, q.today), (3, 0, 0));
    assert_eq!(announce::send_pending(&w.db, &mail, 20).await.unwrap(), 0);
    assert!(states(&w, q.id).await.iter().all(|(_, s)| s == "pending"));
    // A day later the allowance is back and they go out.
    sqlx::query("UPDATE email_sends SET at = at - 90000")
        .execute(&w.db)
        .await
        .unwrap();
    assert_eq!(announce::send_pending(&w.db, &mail, 20).await.unwrap(), 3);
    assert!(states(&w, q.id).await.iter().all(|(_, s)| s == "sent"));
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn a_stopped_announcement_sends_nothing_more_and_late_opt_outs_are_skipped() {
    let w = world!();
    let alice = w.sign_up("alice").await;
    let bob = w.sign_up("bob").await;
    let ids = vec![alice.account.clone(), bob.account.clone()];
    let file = Attachment {
        name: "notes.txt".into(),
        content_type: "text/plain".into(),
        data: b"fictional".to_vec(),
    };

    // Bob unsubscribes after it was written, before his turn.
    let a = announce::create(&w.db, draft(vec![file.clone()]), &ids, true)
        .await
        .unwrap();
    admin_ops::set_announcements_off(&w.db, &bob.account, true)
        .await
        .unwrap();
    let mail = MemoryNotifier::default();
    assert_eq!(announce::send_pending(&w.db, &mail, 20).await.unwrap(), 1);
    assert_eq!(mail.sent()[0].to, alice.email);
    let st = states(&w, a.id).await;
    assert!(st.contains(&(bob.account.clone(), "skipped".into())));

    // Stopped before anything went out.
    let b = announce::create(
        &w.db,
        draft(vec![file]),
        std::slice::from_ref(&alice.account),
        true,
    )
    .await
    .unwrap();
    assert!(announce::stop(&w.db, b.id).await.unwrap());
    assert!(!announce::stop(&w.db, b.id).await.unwrap());
    assert_eq!(announce::send_pending(&w.db, &mail, 20).await.unwrap(), 0);
    assert_eq!(states(&w, b.id).await[0].1, "stopped");
    let s = announce::list(&w.db, 10).await.unwrap();
    let b_sum = s.iter().find(|x| x.id == b.id).unwrap();
    assert_eq!((b_sum.status.as_str(), b_sum.files), ("stopped", 0));
    w.cleanup().await.unwrap();
}

#[tokio::test]
async fn the_logs_show_accounts_and_operator_actions_with_filters() {
    let w = world!();
    let alice = w.sign_up("alice").await;
    let bob = w.sign_up("bob").await;
    let rules = svx_protocol::personal::FileRules {
        require_approval: false,
        one_time: false,
        expires_at: None,
        view_only: false,
        allow_share_requests: false,
    };
    let (file, _) = w.send(&alice, &[&bob], rules).await.unwrap();
    assert_eq!(w.open_personal(&bob, &file).await.unwrap(), SECRET);
    admin_ops::suspend(&w.db, &alice.account, Some("testing"))
        .await
        .unwrap();

    let all = admin_ops::logs(
        &w.db,
        &LogFilter {
            limit: 100,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(all.windows(2).all(|p| p[0].at >= p[1].at), "newest first");
    let admin = all.iter().find(|e| e.source == "admin").unwrap();
    assert_eq!(admin.event, "suspended");
    assert_eq!(admin.email.as_deref(), Some(alice.email.as_str()));
    assert_eq!(admin.reason.as_deref(), Some("testing"));
    assert!(
        all.iter().any(|e| e.event == "decryption_authorized"
            && e.email.as_deref() == Some(bob.email.as_str()))
    );

    let bobs = admin_ops::logs(
        &w.db,
        &LogFilter {
            search: Some(bob.email.to_uppercase()),
            limit: 100,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(!bobs.is_empty());
    assert!(
        bobs.iter()
            .all(|e| e.email.as_deref() == Some(bob.email.as_str())
                || e.subject.as_deref().is_some_and(|s| s.contains(&bob.email)))
    );

    let problems = admin_ops::logs(
        &w.db,
        &LogFilter {
            problems_only: true,
            limit: 100,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        problems
            .iter()
            .all(|e| admin_ops::PROBLEM_EVENTS.contains(&e.event.as_str()))
    );
    assert!(problems.iter().any(|e| e.event == "account_suspended"));

    // Paging.
    let first = admin_ops::logs(
        &w.db,
        &LogFilter {
            limit: 2,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let second = admin_ops::logs(
        &w.db,
        &LogFilter {
            limit: 2,
            offset: 2,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(first.len(), 2);
    assert_eq!(second[0].at, all[2].at);
    w.cleanup().await.unwrap();
}
