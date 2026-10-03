//! Personal accounts: Alice and Bob sign up with the dev "Google", send by
//! email address, and the sender stays in control after sending. Every
//! step goes through `svx_client::personal`, as the desktop app does.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use svx_client::account::LoginMethod;
use svx_client::config::Paths;
use svx_client::defaults::ServiceTarget;
use svx_client::keystore::MemoryStore;
use svx_client::personal::{self, KeyChoice, SendOptions, SignUpOptions};
use svx_client::{Client, ClientError, Output, Step};
use svx_protocol::personal::{FileRules, UpdateFileRequest, sign_request};
use svx_testkit::World;

use crate::ui::Ui;

const NOTE: &str = "FICTIONAL DEMO DATA: Alice's notes for the Example Corp offsite.\n";

async fn sign_up(w: &World, dir: &Path, who: &str) -> svx_client::Result<Client> {
    let (c, _) = personal::sign_up(
        &Paths {
            config: dir.join(format!("{who}/config.toml")),
            session: dir.join(format!("{who}/session.json")),
        },
        Arc::new(MemoryStore::default()),
        SignUpOptions {
            target: ServiceTarget {
                service_url: w.service_url.clone(),
                registry_key: w.registry_key_hex(),
                dev: true,
            },
            issuer: None,
            keys: KeyChoice::New,
            default_output_dir: Some(dir.join(format!("{who}/opened"))),
            replace: false,
        },
        LoginMethod::Dev(who.into()),
    )
    .await?;
    Ok(c)
}

fn out(dir: &Path, name: &str) -> Option<Output> {
    Some(Output::Dir {
        dir: dir.join(name),
        overwrite: false,
    })
}

fn kind(r: &svx_client::Result<impl Sized>) -> String {
    match r {
        Ok(_) => "opened".into(),
        Err(e) => match e.deny_reason() {
            Some(d) => format!("{} ({d})", e.kind().as_str()),
            None => e.kind().as_str().into(),
        },
    }
}

/// `who` opens `file`, waiting for the sender; `decide` runs meanwhile
/// once the request reaches the sender.
async fn open_while(
    who: &Client,
    sender: &Client,
    file: &Path,
    dir: &Path,
    name: &str,
    approve: bool,
) -> (svx_client::Result<svx_client::OpenOutcome>, Vec<Step>) {
    // Never hang the demo: stop waiting after 30 seconds.
    let stop = AtomicBool::new(false);
    let mut steps = Vec::new();
    let opening = async {
        let mut progress = |s: Step| steps.push(s);
        let r = who
            .open_personal(file, out(dir, name), &mut progress, &stop)
            .await;
        stop.store(true, Ordering::Relaxed);
        r
    };
    let deciding = async {
        for _ in 0..150 {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let mine = sender
                .requests()
                .await
                .ok()
                .and_then(|list| list.into_iter().find(|r| r.requester == who.cfg.org_id));
            if let Some(r) = mine {
                let id = hex::encode(r.request_id);
                let _ = if approve {
                    sender.approve(&id).await
                } else {
                    sender.decline(&id).await
                };
                return;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        stop.store(true, Ordering::Relaxed);
    };
    let (r, ()) = tokio::join!(opening, deciding);
    (r, steps)
}

pub async fn run(w: &World, dir: &Path, ui: &Ui) -> Result<()> {
    let dir = dir.join("personal");
    std::fs::create_dir_all(&dir)?;

    ui.scenario(
        "11",
        "Alice and Bob sign up with Google; Alice sends Bob a file by email",
    );
    ui.say("Each app makes its own keys in the keychain; the service only gets public keys,");
    ui.say("bound to the sign-in. Alice types bob@example.test: no keys to paste.");
    let alice = sign_up(w, &dir, "alice")
        .await
        .context("Alice signing up")?;
    let bob = sign_up(w, &dir, "bob").await.context("Bob signing up")?;
    let carol = sign_up(w, &dir, "carol")
        .await
        .context("Carol signing up")?;
    let input = dir.join("offsite-notes.txt");
    std::fs::write(&input, NOTE)?;
    let send = |to: &[&str], output: &str| SendOptions {
        input: input.clone(),
        output: Some(dir.join(output)),
        overwrite: false,
        to: to.iter().map(|s| s.to_string()).collect(),
        rules: FileRules::default(),
        expires_at: None,
        name: None,
    };
    let sent = alice.send(send(&["bob@example.test"], "notes.svx")).await?;
    ui.sys(format!(
        "Sent {} to {} (ask before each open, one-time)",
        sent.path.display(),
        sent.recipients[0].email
    ));
    ui.say("Bob opens it. The service asks Alice, in her app and by email; she approves.");
    let (r, steps) = open_while(&bob, &alice, &sent.path, &dir, "bob-1", true).await;
    let waited = steps
        .iter()
        .any(|s| matches!(s, Step::AwaitingApproval { .. }));
    let same = r
        .as_ref()
        .ok()
        .and_then(|o| o.path.as_ref())
        .is_some_and(|p| std::fs::read_to_string(p).is_ok_and(|t| t == NOTE));
    let mail = w.mail.sent();
    let clean_mail = mail.len() == 1
        && mail[0].to == "alice@example.test"
        && !mail[0].body.contains("offsite-notes")
        && !mail[0].body.contains("http");
    if let Some(m) = mail.first() {
        ui.sys(format!("Email to {}: {}", m.to, m.subject));
    }
    ui.check(
        "11",
        "Bob opens Alice's file after her approval",
        "waits, approved, content matches, email without file name or link",
        waited && same && clean_mail,
        format!(
            "{}{}, {} email(s)",
            kind(&r),
            if waited { " after waiting" } else { "" },
            mail.len()
        ),
    );

    ui.scenario("12", "Bob tries to open the same one-time file again");
    let never = AtomicBool::new(false);
    let r = bob
        .open_personal(&sent.path, out(&dir, "bob-2"), &mut |_| {}, &never)
        .await;
    ui.check(
        "12",
        "One-time file opened twice",
        "denied (already_opened)",
        matches!(
            &r,
            Err(ClientError::Denied(svx_protocol::DenyReason::AlreadyOpened))
        ),
        kind(&r),
    );

    ui.scenario("13", "Alice revokes Carol while Carol waits for approval");
    let both = alice
        .send(send(
            &["bob@example.test", "carol@example.test"],
            "notes-2.svx",
        ))
        .await?;
    let cancel = AtomicBool::new(false);
    let mut stop = |s: Step| {
        if matches!(s, Step::AwaitingApproval { .. }) {
            cancel.store(true, Ordering::Relaxed);
        }
    };
    let waiting = carol
        .open_personal(&both.path, out(&dir, "carol-1"), &mut stop, &cancel)
        .await;
    alice
        .update_file(
            &both.artifact_id,
            &UpdateFileRequest {
                revoke_recipients: vec![carol.cfg.org_id.clone()],
                ..Default::default()
            },
        )
        .await?;
    let r = carol
        .open_personal(&both.path, out(&dir, "carol-2"), &mut |_| {}, &never)
        .await;
    ui.check(
        "13",
        "Carol after being revoked",
        "denied (expired_or_revoked)",
        matches!(waiting, Err(ClientError::Cancelled))
            && matches!(
                &r,
                Err(ClientError::Denied(
                    svx_protocol::DenyReason::ExpiredOrRevoked
                ))
            ),
        kind(&r),
    );

    ui.scenario("14", "Alice declines Bob's request for the second file");
    let (r, _) = open_while(&bob, &alice, &both.path, &dir, "bob-3", false).await;
    ui.check(
        "14",
        "Bob after Alice declines",
        "denied (declined)",
        matches!(
            &r,
            Err(ClientError::Denied(svx_protocol::DenyReason::Declined))
        ),
        kind(&r),
    );

    ui.scenario("15", "Eve: no confirmed email, and not a recipient");
    let eve = sign_up(w, &dir, "eve").await;
    ui.say("Eve's sign-in has no confirmed email, so she can't get an account; and Carol,");
    ui.say("who has one, can't open a file that wasn't sent to her.");
    let r = carol
        .open_personal(&sent.path, out(&dir, "carol-3"), &mut |_| {}, &never)
        .await;
    ui.check(
        "15",
        "Eve signs up; Carol opens Bob's file",
        "both refused",
        eve.is_err() && matches!(&r, Err(ClientError::NotRecipient { .. })),
        format!(
            "Eve {}, Carol {}",
            eve.err()
                .map_or("signed up".into(), |e| e.kind().as_str().to_owned()),
            kind(&r)
        ),
    );

    ui.scenario("16", "An attacker replays one of Alice's signed requests");
    ui.say("Each request is signed with the device key and carries a fresh nonce.");
    let a = &alice.cfg;
    let key = svx_client::keystore::load_signing(
        alice.secrets.as_ref(),
        &svx_client::keystore::KeyRef::parse(&a.account.as_ref().expect("personal").signing_key)?,
    )?
    .1;
    let auth = sign_request(
        &key,
        &a.org_id,
        "GET",
        "/v1/me/history",
        b"",
        svx_testkit::now(),
    )?;
    let send_raw = || {
        let mut req = w
            .client
            .http()
            .get(format!("{}/v1/me/history", w.service_url));
        for (k, v) in auth.headers() {
            req = req.header(k, v);
        }
        req.send()
    };
    let first = send_raw().await?.status().as_u16();
    let replay = send_raw().await?.status().as_u16();
    ui.check(
        "16",
        "Replayed signed request",
        "first accepted, replay refused (401)",
        first == 200 && replay == 401,
        format!("first {first}, replay {replay}"),
    );
    Ok(())
}
