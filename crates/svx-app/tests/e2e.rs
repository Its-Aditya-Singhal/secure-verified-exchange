//! The desktop command layer against a real managed service, key agent, dev
//! IdPs and Postgres (the stack `svx-demo serve` runs). Skipped without
//! `SVX_TEST_DATABASE_URL`.

use std::path::Path;

use svx_app::{App, Progress, SendRequest, SetupForm};
use svx_client::login::print_url;
use svx_testkit::*;

macro_rules! world {
    () => {
        match World::new().await {
            Some(w) => w,
            None => return,
        }
    };
}

fn form(w: &World, org: &str, out: &Path) -> SetupForm {
    SetupForm {
        service_url: w.service_url.clone(),
        registry_key: format!("  {}\n", w.registry_key_hex()),
        org_id: org.into(),
        idp_client_id: w.idp(org).client_id().into(),
        dev: true,
        default_output_dir: Some(out.to_path_buf()),
    }
}

async fn configured(w: &World, org: &str, dir: &Path) -> App {
    let app = App::new(Some(&dir.join(format!("{org}/config.toml")))).unwrap();
    assert!(!app.state().configured);
    let preview = app
        .setup_verify(form(w, org, &dir.join(format!("{org}-out"))))
        .await
        .unwrap();
    assert_eq!(preview.org_id, org);
    app.setup_save(form(w, org, &dir.join(format!("{org}-out"))), false)
        .await
        .unwrap();
    let s = app.state();
    assert!(s.configured, "{:?}", s.config_error);
    assert_eq!(s.org_id.as_deref(), Some(org));
    app
}

fn dev(user: &str) -> svx_client::account::LoginMethod {
    App::login_method(Some(user.into()), print_url())
}

fn send_req(key: &Path, input: &Path) -> SendRequest {
    SendRequest {
        input: input.to_path_buf(),
        output: None,
        recipient: EXAMPLE.into(),
        policy: POLICY.into(),
        expires_at: Some(now() + 86_400),
        classification: Some("TLP:AMBER".into()),
        description: Some("  ".into()),
        signing_key: key.display().to_string(),
        register: true,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn desktop_commands_end_to_end() {
    let w = world!();
    let d = tempfile::tempdir().unwrap();
    let dir = d.path();
    let acme = configured(&w, ACME, dir).await;
    let example = configured(&w, EXAMPLE, dir).await;
    let key = w.write_acme_sign_key(dir);

    // Setup refuses to silently replace a configuration.
    let e = acme
        .setup_save(form(&w, ACME, dir), false)
        .await
        .unwrap_err();
    assert_eq!(e.kind, "config");
    // Import reads an existing config back into the form.
    let f = acme
        .read_config_file(&dir.join(format!("{ACME}/config.toml")))
        .unwrap();
    assert_eq!(f.org_id, ACME);

    // Recipient lookup is verified against the registry.
    let r = acme.recipient(EXAMPLE).await.unwrap();
    assert!(r.can_receive);
    assert!(!acme.recipient("acme-security").await.unwrap().can_receive);
    assert!(acme.recipient("ghost-org").await.is_err());

    // Carol sends a file and a folder (registration needs her session).
    let e = acme
        .send(send_req(&key, &dir.join("missing.txt")))
        .await
        .unwrap_err();
    assert_ne!(e.kind, "other");
    assert!(acme.whoami().await.unwrap().is_none());
    let me = acme.login(dev("carol")).await.unwrap();
    assert_eq!(me.sub, "carol");
    let file = dir.join("report.txt");
    std::fs::write(&file, SECRET).unwrap();
    let sent = acme.send(send_req(&key, &file)).await.unwrap();
    assert!(sent.registered);
    assert!(acme.produced(&sent.path).is_ok());
    let prefs = acme.state().prefs;
    assert_eq!(prefs.recent_recipients, vec![EXAMPLE.to_string()]);
    assert_eq!(prefs.last_policy.as_deref(), Some(POLICY));
    let folder = dir.join("evidence");
    std::fs::create_dir_all(folder.join("logs")).unwrap();
    std::fs::write(folder.join("logs/a.log"), b"log").unwrap();
    let sent_folder = acme.send(send_req(&key, &folder)).await.unwrap();

    // Status before any login.
    let s = example.status(&sent.path).await.unwrap();
    assert!(s.for_you && !s.expired);
    assert!(s.post_quantum, "new files are post-quantum");
    assert_eq!(s.suite_id, 0x0004, "new files are SVX-2");
    assert!(sent.protection.starts_with("maximum"));
    assert_eq!(s.sender_org, ACME);
    assert!(!acme.status(&sent.path).await.unwrap().for_you);

    // Alice: approved, with the full timeline.
    let mut steps: Vec<Progress> = Vec::new();
    let o = example
        .open(&sent.path, None, dev("alice"), &mut |p| steps.push(p))
        .await
        .unwrap();
    assert_eq!(
        steps.iter().map(|p| p.index).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5, 6, 7]
    );
    assert_eq!(std::fs::read(&o.path).unwrap(), SECRET);
    assert_eq!(o.name, "report.txt");
    assert!(o.can_open && !o.is_folder);
    assert_eq!(o.classification.as_deref(), Some("TLP:AMBER"));
    assert!(example.openable(&o.path).is_ok());

    // Opening again: output_exists with the path, then another folder works.
    let e = example
        .open(&sent.path, None, dev("alice"), &mut |_| {})
        .await
        .unwrap_err();
    assert_eq!(e.kind, "output_exists");
    assert_eq!(e.path.as_deref(), Some(o.path.as_path()));
    let again = example
        .open(
            &sent.path,
            Some(dir.join("elsewhere")),
            dev("alice"),
            &mut |_| {},
        )
        .await
        .unwrap();
    assert_eq!(again.path, dir.join("elsewhere/report.txt"));

    // Folder.
    let of = example
        .open(&sent_folder.path, None, dev("alice"), &mut |_| {})
        .await
        .unwrap();
    assert!(of.is_folder && !of.can_open);
    assert_eq!(std::fs::read(of.path.join("logs/a.log")).unwrap(), b"log");
    assert!(example.produced(&of.path).is_ok());
    assert!(example.openable(&of.path).is_err());

    // Bob: denied, not authorized; nothing new written.
    let bob_out = dir.join("bob-out");
    let mut bob_steps = Vec::new();
    let e = example
        .open(&sent.path, Some(bob_out.clone()), dev("bob"), &mut |p| {
            bob_steps.push(p.step)
        })
        .await
        .unwrap_err();
    assert_eq!(
        (e.kind.as_str(), e.deny_reason.as_deref()),
        ("denied", Some("not_authorized"))
    );
    assert!(!bob_steps.contains(&"access_approved"));
    assert!(!bob_out.exists() || std::fs::read_dir(&bob_out).unwrap().count() == 0);

    // Tampered copy: rejected before login.
    let mut bytes = std::fs::read(&sent.path).unwrap();
    let n = bytes.len();
    bytes[n - 100] ^= 1;
    let tampered = dir.join("tampered.svx");
    std::fs::write(&tampered, bytes).unwrap();
    let mut t_steps = Vec::new();
    let e = example
        .open(&tampered, None, dev("alice"), &mut |p| t_steps.push(p.step))
        .await
        .unwrap_err();
    assert_eq!(e.kind, "rejected");
    assert!(!t_steps.contains(&"authenticating"));

    // Not for this org.
    let e = acme
        .open(&sent.path, None, dev("carol"), &mut |_| {})
        .await
        .unwrap_err();
    assert_eq!(e.kind, "not_recipient");

    // Admin: Example Corp's admin revokes, then Alice is denied.
    assert_eq!(
        example.revoke(&o.artifact_id).await.unwrap_err().kind,
        "not_logged_in"
    );
    example.login(dev("example-admin")).await.unwrap();
    assert!(example.policies().await.unwrap().contains_key(POLICY));
    let id = example.revoke(sent.path.to_str().unwrap()).await.unwrap();
    assert_eq!(id, sent.artifact_id);
    let e = example
        .open(
            &sent.path,
            Some(dir.join("late")),
            dev("alice"),
            &mut |_| {},
        )
        .await
        .unwrap_err();
    assert_eq!(e.deny_reason.as_deref(), Some("expired_or_revoked"));
    let page = example.audit(50).await.unwrap();
    assert!(page.chain_valid);
    assert!(page.entries.iter().any(|e| e.event == "artifact_revoked"));
    assert!(example.logout().unwrap());
    assert!(example.whoami().await.unwrap().is_none());

    w.cleanup().await.unwrap();
}

/// Phase 5b: a new organization signs up in the app, its admin creates a
/// keychain signing key, edits a policy, exports the audit trail, and a
/// file signed with the keychain key opens at Example Corp.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn onboarding_keys_policies_and_audit_export() {
    use std::sync::Arc;
    use svx_client::keystore::MemoryStore;
    use svx_client::onboard::OnboardRequest;
    use svx_protocol::Policy;

    let w = world!();
    let d = tempfile::tempdir().unwrap();
    let dir = d.path();
    let idp = World::spawn_idp("svx-example-labs", &[("dana", &["it"])]).await;
    let store = Arc::new(MemoryStore::default());
    let labs = App::with_secret_store(Some(&dir.join("labs/config.toml")), store.clone()).unwrap();

    let pending = labs
        .onboard_register(OnboardRequest {
            service_url: w.service_url.clone(),
            registry_key: w.registry_key_hex(),
            org_id: "example-labs".into(),
            display_name: "Example Labs".into(),
            domain: "example-labs.example".into(),
            idp_issuer: idp.issuer().into(),
            idp_client_id: idp.client_id().into(),
            group_claim: None,
            key_agent_url: None,
            dev: true,
            default_output_dir: None,
        })
        .await
        .unwrap();
    // The registration survives a restart of the app.
    let labs = App::with_secret_store(Some(&dir.join("labs/config.toml")), store.clone()).unwrap();
    assert_eq!(labs.state().prefs.pending_org.as_ref(), Some(&pending));
    w.dns.set(&pending.txt_name, &pending.txt_value);
    let (preview, me) = labs.onboard_complete(dev("dana"), false).await.unwrap();
    assert_eq!(preview.org_id, "example-labs");
    assert_eq!(me.sub, "dana");
    let s = labs.state();
    assert!(s.configured && s.prefs.pending_org.is_none());

    // Keys: a keychain signing key becomes this computer's key.
    let k = labs.create_signing_key().await.unwrap();
    assert_eq!(
        labs.state().prefs.signing_key.as_deref(),
        Some(k.key_ref.as_str())
    );
    let o = labs.admin_overview().await.unwrap();
    assert_eq!(o.this_computer_key.as_deref(), Some(k.key_id.as_str()));
    assert!(o.agent.is_none());
    assert_eq!(o.org.admins[0].subject, "dana");

    // Example Corp's admin edits its policy so Example Labs' file is allowed.
    let example = configured(&w, EXAMPLE, dir).await;
    example.login(dev("example-admin")).await.unwrap();
    let ov = example.admin_overview().await.unwrap();
    let agent = ov.agent.unwrap();
    assert!(agent.reachable, "{:?}", agent.error);
    assert!(
        agent
            .key_ids
            .contains(&hex::encode(w.example_kem.public_key().key_id()))
    );
    example
        .set_policy(
            "partners",
            Policy {
                allow_groups: vec!["incident-response".into()],
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Dana sends with the keychain key; Alice opens it.
    let input = dir.join("labs-note.txt");
    std::fs::write(&input, b"FICTIONAL lab results").unwrap();
    let mut req = send_req(Path::new("unused"), &input);
    req.signing_key = k.key_ref.clone();
    req.policy = "partners".into();
    req.register = false;
    let sent = labs.send(req).await.unwrap();
    let r = example
        .open(&sent.path, None, dev("alice"), &mut |_: Progress| {})
        .await
        .unwrap();
    assert_eq!(std::fs::read(&r.path).unwrap(), b"FICTIONAL lab results");

    // Audit export: CSV with a header and the policy change.
    let csv = dir.join("audit.csv");
    let n = example
        .export_audit_csv(&csv, Some("policy_changed".into()))
        .await
        .unwrap();
    assert!(n >= 1);
    let text = std::fs::read_to_string(&csv).unwrap();
    assert!(text.starts_with("seq,time_utc,event"));
    assert!(text.contains("policy partners"));
    assert!(example.produced(&csv).is_ok());
}

fn personal_app(w: &World, dir: &Path, name: &str) -> App {
    App::with_secret_store(
        Some(&dir.join(format!("{name}/config.toml"))),
        std::sync::Arc::new(svx_client::keystore::MemoryStore::default()),
    )
    .unwrap()
    .with_service_target(svx_client::defaults::ServiceTarget {
        service_url: w.service_url.clone(),
        registry_key: w.registry_key_hex(),
        dev: true,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn personal_accounts_in_the_app() {
    let w = world!();
    let d = tempfile::tempdir().unwrap();
    let dir = d.path();
    let alice = personal_app(&w, dir, "alice");
    let bob = std::sync::Arc::new(personal_app(&w, dir, "bob"));

    let p = alice.providers().await.unwrap();
    assert_eq!(p.providers[0].name, "Google");
    let issuer = Some(p.providers[0].issuer.clone());
    let a = alice
        .sign_up(issuer.clone(), false, dev("alice"), false)
        .await
        .unwrap();
    assert_eq!(a.email, "alice@example.test");
    bob.sign_up(issuer.clone(), false, dev("bob"), false)
        .await
        .unwrap();
    let s = alice.state();
    assert!(s.configured && s.personal);
    assert_eq!(s.email.as_deref(), Some("alice@example.test"));
    assert_eq!(alice.account().await.unwrap().account, a.account);
    assert_eq!(
        alice.lookup("bob@example.test").await.unwrap().email,
        "bob@example.test"
    );

    let input = dir.join("holiday-plan.txt");
    std::fs::write(&input, SECRET).unwrap();
    let sent = alice
        .send_personal(svx_app::PersonalSendRequest {
            input: input.clone(),
            to: vec!["bob@example.test".into()],
            require_approval: true,
            one_time: true,
            expires_at: None,
        })
        .await
        .unwrap();
    assert!(alice.produced(&sent.path).is_ok());

    // Bob checks the file, then opens it; it waits for Alice.
    let st = bob.status(&sent.path).await.unwrap();
    assert!(st.for_you);
    assert_eq!(st.sender_name, "alice@example.test");
    let (b, path) = (bob.clone(), sent.path.clone());
    let out = dir.join("bob-out");
    let opening = tokio::spawn(async move {
        let mut steps = Vec::new();
        let r = b
            .open(&path, Some(out), dev("unused"), &mut |p: Progress| {
                steps.push(p)
            })
            .await;
        (r, steps)
    });
    let req = loop {
        let r = alice.requests().await.unwrap();
        if let Some(r) = r.into_iter().next() {
            break r;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    };
    assert_eq!(req.file_name.as_deref(), Some("holiday-plan.txt"));
    alice
        .approve(&hex::encode(req.request.request_id))
        .await
        .unwrap();
    let (r, steps) = opening.await.unwrap();
    let r = r.unwrap();
    assert_eq!(std::fs::read(&r.path).unwrap(), SECRET);
    assert!(steps.iter().any(
        |p| p.step == "awaiting_approval" && p.sender.as_deref() == Some("alice@example.test")
    ));

    // History shows names on both sides; the file page changes rules.
    let h = alice.history().await.unwrap();
    assert_eq!(h.sent[0].file_name.as_deref(), Some("holiday-plan.txt"));
    let h = bob.history().await.unwrap();
    assert_eq!(h.received[0].file_name.as_deref(), Some("holiday-plan.txt"));
    let f = alice
        .update_file(
            &sent.artifact_id,
            svx_protocol::personal::UpdateFileRequest {
                revoke: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(f.file.revoked_at.is_some());
    assert!(alice.file("../etc/passwd").await.is_err());

    // Cancelling when nothing waits does nothing.
    bob.cancel_open();

    // Backup, then sign out.
    let backup = dir.join("alice.svxbackup");
    alice.save_backup(&backup, "correct horse battery").unwrap();
    alice.sign_out().unwrap();
    assert!(!alice.state().configured);
    let restored = alice
        .restore(
            &backup,
            "correct horse battery",
            issuer,
            dev("alice"),
            false,
        )
        .await
        .unwrap();
    assert_eq!(restored.account, a.account);
    w.cleanup().await.unwrap();
}
