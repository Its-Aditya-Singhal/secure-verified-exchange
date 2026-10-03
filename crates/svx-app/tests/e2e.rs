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
        signing_key: key.to_path_buf(),
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
    assert!(s.post_quantum, "new files are post-quantum hybrid");
    assert!(sent.protection.starts_with("post-quantum hybrid"));
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
