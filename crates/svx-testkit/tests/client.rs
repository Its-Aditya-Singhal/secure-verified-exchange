//! `svx_client::Client` against a real managed service, key agent, dev IdPs
//! and Postgres. Skipped without `SVX_TEST_DATABASE_URL`.

use std::path::Path;

use svx_client::account::LoginMethod;
use svx_client::config::Paths;
use svx_client::setup::{self, SetupRequest};
use svx_client::{Client, ClientError, PackOptions};
use svx_testkit::*;

macro_rules! world {
    () => {
        match World::new().await {
            Some(w) => w,
            None => return,
        }
    };
}

fn client(w: &World, org: &str, dir: &Path) -> Client {
    let paths = Paths {
        config: dir.join(format!("{org}.toml")),
        session: dir.join(format!("{org}.session.json")),
    };
    Client::with_config(paths, w.client_config(org)).unwrap()
}

async fn open_as(
    c: &Client,
    artifact: &Path,
    out: &Path,
    user: &str,
) -> svx_client::Result<svx_client::OpenOutcome> {
    let output = svx_client::Output::Dir {
        dir: out.to_path_buf(),
        overwrite: false,
    };
    c.open(
        artifact,
        Some(output),
        LoginMethod::Dev(user.into()),
        &mut |_| {},
    )
    .await
}

fn request(w: &World, org: &str) -> SetupRequest {
    SetupRequest {
        service_url: w.service_url.clone(),
        registry_key: w.registry_key_hex(),
        org_id: org.into(),
        idp_client_id: w.idp(org).client_id().into(),
        dev: true,
        default_output_dir: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn setup_verifies_against_the_pin() {
    let w = world!();
    let dir = tempfile::tempdir().unwrap();

    let p = setup::verify(request(&w, EXAMPLE)).await.unwrap();
    assert_eq!(p.service_id, SERVICE_ID);
    assert_eq!(p.idp_issuer, w.example_idp.issuer());
    assert!(p.can_receive);
    // The pin is the fingerprint; the full hybrid key is saved beside it.
    assert_eq!(p.config.registry_key, w.registry_key_hex());
    assert_eq!(p.config.registry_public, w.registry_public_hex());
    assert_eq!(p.config.registry_key().unwrap(), w.registry_key());
    let paths = Paths {
        config: dir.path().join("c.toml"),
        session: dir.path().join("s.json"),
    };
    setup::write(&paths, &p.config, false).unwrap();
    assert_eq!(
        svx_client::ClientConfig::load(&paths.config).unwrap(),
        p.config
    );
    // No silent replacement.
    assert!(matches!(
        setup::write(&paths, &p.config, false),
        Err(ClientError::Config(_))
    ));

    // Another registry's fingerprint: refused before any record is trusted.
    let mut wrong = request(&w, EXAMPLE);
    wrong.registry_key = hex::encode(
        svx_core::crypto::SigningKey::generate_max(&mut svx_core::crypto::os_rng())
            .verifying_key()
            .fingerprint(),
    );
    let e = setup::verify(wrong).await.unwrap_err().to_string();
    assert!(e.contains("fingerprint"), "{e}");
    // The raw Ed25519-era key in place of a fingerprint: refused too.
    let mut old = request(&w, EXAMPLE);
    old.registry_key = hex::encode([7u8; 32]);
    assert!(setup::verify(old).await.is_err());
    assert!(setup::verify(request(&w, "ghost-org")).await.is_err());
    let mut insecure = request(&w, EXAMPLE);
    insecure.dev = false;
    assert!(matches!(
        setup::verify(insecure).await,
        Err(ClientError::Config(_))
    ));
    w.cleanup().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_folder_round_trips_and_bob_gets_nothing() {
    let w = world!();
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("evidence");
    std::fs::create_dir_all(src.join("logs/2026")).unwrap();
    std::fs::create_dir_all(src.join("empty")).unwrap();
    std::fs::write(src.join("summary.txt"), SECRET).unwrap();
    std::fs::write(src.join("logs/2026/auth.log"), vec![b'x'; 300_000]).unwrap();

    let acme = client(&w, ACME, dir.path());
    let packed = acme
        .pack(PackOptions {
            input: src.clone(),
            output: None,
            overwrite: false,
            signing_key: w.write_acme_sign_key(dir.path()).into(),
            recipient: EXAMPLE.into(),
            policy: POLICY.into(),
            expires_at: None,
            classification: Some("TLP:AMBER".into()),
            description: None,
            name: None,
            register: false,
        })
        .await
        .unwrap();
    assert_eq!(packed.path, dir.path().join("evidence.svx"));

    let example = client(&w, EXAMPLE, dir.path());
    let status = example.status(&packed.path).await.unwrap();
    assert!(status.for_you);

    // Bob is denied and nothing is written.
    let bob_out = dir.path().join("bob");
    let e = open_as(&example, &packed.path, &bob_out, "bob")
        .await
        .unwrap_err();
    assert_eq!(e.deny_reason(), Some("not_authorized"));
    assert!(!bob_out.exists() || std::fs::read_dir(&bob_out).unwrap().count() == 0);

    // Alice gets the same tree back as a folder.
    let out = dir.path().join("alice");
    let o = open_as(&example, &packed.path, &out, "alice")
        .await
        .unwrap();
    assert!(o.is_folder());
    let got = o.path.unwrap();
    assert_eq!(got, out.join("evidence"));
    assert_eq!(std::fs::read(got.join("summary.txt")).unwrap(), SECRET);
    assert_eq!(
        std::fs::read(got.join("logs/2026/auth.log")).unwrap().len(),
        300_000
    );
    assert!(got.join("empty").is_dir());
    // Only the folder: no zip, no partial files.
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 1);

    // Opening again never replaces the folder.
    let e = open_as(&example, &packed.path, &out, "alice")
        .await
        .unwrap_err();
    assert!(matches!(e, ClientError::OutputExists(_)), "{e:?}");
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 1);
    w.cleanup().await.unwrap();
}

// ----- Administration (Phase 5b) -----

use std::sync::Arc;

use svx_client::admin::AuditQuery;
use svx_client::keystore::{KeyRef, MemoryStore};
use svx_client::onboard::{self, OnboardRequest};
use svx_protocol::admin::UpdateOrgRequest;
use svx_protocol::{DenyReason, KeyKindWire, KeyStatus, Policy};

fn pack_opts(input: &Path, key: KeyRef) -> PackOptions {
    PackOptions {
        input: input.to_path_buf(),
        output: None,
        overwrite: false,
        signing_key: key,
        recipient: EXAMPLE.into(),
        policy: POLICY.into(),
        expires_at: Some(now() + 3600),
        classification: None,
        description: None,
        name: None,
        register: false,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admins_settings_policies_and_audit() {
    let w = world!();
    let dir = tempfile::tempdir().unwrap();
    let ex = client(&w, EXAMPLE, dir.path());

    // Not signed in, then signed in but not an administrator.
    assert!(matches!(
        ex.org_overview().await,
        Err(ClientError::NotLoggedIn)
    ));
    ex.login(LoginMethod::Dev("bob".into())).await.unwrap();
    assert!(matches!(
        ex.org_overview().await,
        Err(ClientError::Denied(DenyReason::NotAuthorized))
    ));

    ex.login(LoginMethod::Dev("example-admin".into()))
        .await
        .unwrap();
    let o = ex.org_overview().await.unwrap();
    assert_eq!(o.org_id, EXAMPLE);
    assert_eq!(o.admins.len(), 1);
    let kinds: Vec<_> = o.keys.iter().map(|k| (k.kind, k.status)).collect();
    assert!(kinds.contains(&(KeyKindWire::MlKem1024P384, KeyStatus::Active)));
    assert!(kinds.contains(&(KeyKindWire::X25519, KeyStatus::Retired)));

    // Administrators: add, remove; the last one stays.
    ex.add_admin("alice").await.unwrap();
    assert_eq!(ex.org_overview().await.unwrap().admins.len(), 2);
    ex.remove_admin("alice").await.unwrap();
    match ex.remove_admin("example-admin").await {
        Err(ClientError::Invalid(m)) => assert!(m.contains("last administrator"), "{m}"),
        r => panic!("expected a refusal, got {r:?}"),
    }

    // Settings.
    ex.update_org(&UpdateOrgRequest {
        display_name: Some("Example Corp (EU)".into()),
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(
        ex.org_overview().await.unwrap().display_name,
        "Example Corp (EU)"
    );
    assert!(matches!(
        ex.update_org(&UpdateOrgRequest {
            key_agent_url: Some("ftp://agent.example".into()),
            ..Default::default()
        })
        .await,
        Err(ClientError::Invalid(_))
    ));

    // Policies: create and delete.
    let p = Policy {
        allow_groups: vec!["staff".into()],
        ..Default::default()
    };
    ex.set_policy("temporary", &p).await.unwrap();
    assert!(ex.policies().await.unwrap().contains_key("temporary"));
    ex.delete_policy("temporary").await.unwrap();
    assert!(!ex.policies().await.unwrap().contains_key("temporary"));
    assert!(ex.delete_policy("temporary").await.is_err());

    // Audit: filter and page.
    let changes = ex
        .audit_page(&AuditQuery {
            limit: 50,
            event: Some("policy_changed".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(changes.entries.len() >= 3);
    assert!(changes.entries.iter().all(|e| e.event == "policy_changed"));
    assert!(changes.chain_valid);
    let newest = ex
        .audit_page(&AuditQuery {
            limit: 2,
            ..Default::default()
        })
        .await
        .unwrap();
    let older = ex
        .audit_page(&AuditQuery {
            limit: 2,
            before_seq: Some(newest.entries.last().unwrap().seq),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(older.chain_valid && newest.chain_valid);
    assert!(older.entries[0].seq < newest.entries.last().unwrap().seq);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keychain_signing_key_signs_files() {
    let w = world!();
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::default());
    let acme = client(&w, ACME, dir.path()).with_secret_store(store.clone());
    acme.login(LoginMethod::Dev("acme-admin".into()))
        .await
        .unwrap();
    let k = acme.create_signing_key().await.unwrap();
    let r = KeyRef::parse(&k.key_ref).unwrap();
    assert!(matches!(r, KeyRef::Keychain { .. }));
    let registered = acme.org_overview().await.unwrap();
    assert!(
        registered
            .keys
            .iter()
            .any(|e| hex::encode(e.key_id) == k.key_id
                && e.kind == KeyKindWire::Max
                && e.status == KeyStatus::Active)
    );

    let input = dir.path().join("notes.txt");
    std::fs::write(&input, b"FICTIONAL notes").unwrap();
    let sent = acme.pack(pack_opts(&input, r.clone())).await.unwrap();
    let ex = client(&w, EXAMPLE, dir.path());
    let got = open_as(&ex, &sent.path, &dir.path().join("out"), "alice")
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(got.path.unwrap()).unwrap(),
        b"FICTIONAL notes"
    );

    // Revoked keys stop signing new files that anyone accepts.
    acme.set_key_status(&k.key_id, KeyStatus::Revoked)
        .await
        .unwrap();
    std::fs::write(dir.path().join("later.txt"), b"x").unwrap();
    assert!(
        acme.pack(pack_opts(&dir.path().join("later.txt"), r))
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn encryption_key_rotation_waits_for_the_agent() {
    let w = world!();
    let dir = tempfile::tempdir().unwrap();
    let ex = client(&w, EXAMPLE, dir.path());
    ex.login(LoginMethod::Dev("example-admin".into()))
        .await
        .unwrap();
    let old = ex.org_overview().await.unwrap();
    let exported = ex.export_encryption_key(dir.path()).unwrap();
    assert!(exported.secret_file.is_file() && exported.public_file.is_file());

    // The running agent doesn't hold the new key yet: refused, nothing changes.
    match ex.activate_encryption_key(&exported.public_file).await {
        Err(ClientError::Config(m)) => assert!(m.contains("doesn't have key"), "{m}"),
        r => panic!("expected a refusal, got {r:?}"),
    }
    assert_eq!(ex.org_overview().await.unwrap().keys, old.keys);

    // Install the key on a (new) agent and point the registry at it.
    let (_, new_kem) = svx_core::keyfile::load_kem_secret(&exported.secret_file).unwrap();
    let mut kems = w.example_kems();
    kems.push(new_kem);
    let agent = w.spawn_agent(kems).await;
    ex.update_org(&UpdateOrgRequest {
        key_agent_url: Some(agent.clone()),
        ..Default::default()
    })
    .await
    .unwrap();
    ex.activate_encryption_key(&exported.public_file)
        .await
        .unwrap();
    let keys = ex.org_overview().await.unwrap().keys;
    let status = |id: &str| {
        keys.iter()
            .find(|k| hex::encode(k.key_id) == id)
            .map(|k| k.status)
    };
    assert_eq!(status(&exported.key_id), Some(KeyStatus::Active));
    let previous = hex::encode(w.example_kem.public_key().key_id());
    assert_eq!(status(&previous), Some(KeyStatus::Retired));

    // New files are sealed to the new key and open through the new agent.
    let acme = client(&w, ACME, dir.path());
    let input = dir.path().join("rotated.txt");
    std::fs::write(&input, b"FICTIONAL after rotation").unwrap();
    let key = KeyRef::File(w.write_acme_sign_key(dir.path()));
    let sent = acme.pack(pack_opts(&input, key)).await.unwrap();
    let info = svx_client::info::inspect(&sent.path).unwrap();
    assert!(info.envelopes.iter().any(|e| e.key_id == exported.key_id));
    let got = open_as(&ex, &sent.path, &dir.path().join("out"), "alice")
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(got.path.unwrap()).unwrap(),
        b"FICTIONAL after rotation"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_organization_signs_up() {
    let w = world!();
    let dir = tempfile::tempdir().unwrap();
    let idp = World::spawn_idp("svx-example-labs", &[("dana", &["it"])]).await;
    let paths = Paths {
        config: dir.path().join("labs.toml"),
        session: dir.path().join("session.json"),
    };
    let req = OnboardRequest {
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
    };
    // A wrong registry pin is caught before anything is sent.
    let mut wrong = req.clone();
    wrong.registry_key = hex::encode([7u8; 32]);
    assert!(onboard::register(wrong).await.is_err());

    let pending = onboard::register(req).await.unwrap();
    assert_eq!(pending.txt_name, "_svx-challenge.example-labs.example");

    // Without the DNS record: refused, and no configuration is written.
    let r = onboard::complete(&paths, &pending, LoginMethod::Dev("dana".into()), false).await;
    match r {
        Err(ClientError::Invalid(m)) => assert!(m.contains("DNS"), "{m}"),
        r => panic!("expected a DNS refusal, got {r:?}"),
    }
    assert!(!paths.config.exists());

    w.dns.set(&pending.txt_name, &pending.txt_value);
    let (preview, me) = onboard::complete(&paths, &pending, LoginMethod::Dev("dana".into()), false)
        .await
        .unwrap();
    assert_eq!(preview.org_id, "example-labs");
    assert!(!preview.can_receive);
    assert_eq!(me.sub, "dana");
    assert!(paths.config.exists());

    // Dana is the first administrator.
    let labs = Client::load(Some(&paths.config)).unwrap();
    let o = labs.org_overview().await.unwrap();
    assert_eq!(o.admins[0].subject, "dana");
}
