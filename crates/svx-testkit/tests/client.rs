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

    let mut wrong = request(&w, EXAMPLE);
    wrong.registry_key = hex::encode(
        svx_core::crypto::SigningKey::generate(&mut svx_core::crypto::os_rng())
            .verifying_key()
            .to_bytes(),
    );
    assert!(setup::verify(wrong).await.is_err());
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
            signing_key: w.write_acme_sign_key(dir.path()),
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
