//! The real `svx` binary against a real managed service, key agent, dev IdPs
//! and Postgres (via `svx-testkit`). Skipped without `SVX_TEST_DATABASE_URL`.

use std::path::{Path, PathBuf};
use std::process::Output;

use assert_cmd::Command;
use svx_testkit::*;

macro_rules! world {
    () => {
        match World::new().await {
            Some(w) => w,
            None => return,
        }
    };
}

struct Cli {
    dir: tempfile::TempDir,
}

impl Cli {
    fn new() -> Self {
        Cli {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self, p: &str) -> PathBuf {
        self.dir.path().join(p)
    }

    /// Run `svx` with `--config <dir>/<cfg>.toml`. The test runtime is
    /// multi-threaded, so blocking here leaves the in-process services free.
    fn run(&self, cfg: &str, args: &[&str]) -> Output {
        let mut c = Command::cargo_bin("svx").unwrap();
        c.current_dir(self.dir.path())
            .env_remove("SVX_CONFIG")
            .arg("--config")
            .arg(self.path(&format!("{cfg}.toml")))
            .args(args);
        tokio::task::block_in_place(|| c.output().unwrap())
    }

    fn init(&self, w: &World, cfg: &str, org: &str) {
        let idp = w.idp(org);
        let o = self.run(
            cfg,
            &[
                "init",
                "--service",
                &w.service_url,
                "--registry-key",
                &w.registry_key_hex(),
                "--org",
                org,
                "--client-id",
                idp.client_id(),
                "--dev",
            ],
        );
        assert_ok(&o);
    }
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn assert_ok(o: &Output) {
    assert!(o.status.success(), "command failed:\n{}", text(o));
}

fn assert_code(o: &Output, code: i32, needle: &str) {
    assert_eq!(o.status.code(), Some(code), "unexpected exit:\n{}", text(o));
    assert!(
        text(o).contains(needle),
        "missing {needle:?} in:\n{}",
        text(o)
    );
}

fn leftovers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".svx-partial-"))
        .collect()
}

/// Acme packs `secret.txt` for Example Corp through the CLI.
fn pack(cli: &Cli, w: &World, extra: &[&str]) -> PathBuf {
    std::fs::write(cli.path("secret.txt"), SECRET).unwrap();
    let key = w.write_acme_sign_key(cli.dir.path());
    let mut args = vec![
        "pack",
        "secret.txt",
        "--sign-key",
        key.to_str().unwrap(),
        "--recipient",
        EXAMPLE,
        "--policy",
        POLICY,
        "--expires",
        "2099-01-01T00:00:00Z",
        "--classification",
        "TLP:AMBER",
    ];
    args.extend_from_slice(extra);
    let o = cli.run("acme", &args);
    assert_ok(&o);
    assert!(text(&o).contains("Recipient:   example-corp"));
    cli.path("secret.svx")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn init_pins_the_registry_key() {
    let w = world!();
    let cli = Cli::new();
    cli.init(&w, "example", EXAMPLE);
    let cfg = std::fs::read_to_string(cli.path("example.toml")).unwrap();
    assert!(cfg.contains(&w.registry_key_hex()));
    assert!(cfg.contains(w.example_idp.issuer()));

    // A wrong pin is refused and nothing is written.
    let wrong = hex::encode(
        svx_core::crypto::SigningKey::generate(&mut svx_core::crypto::os_rng())
            .verifying_key()
            .to_bytes(),
    );
    let o = cli.run(
        "wrong",
        &[
            "init",
            "--service",
            &w.service_url,
            "--registry-key",
            &wrong,
            "--org",
            EXAMPLE,
            "--client-id",
            "svx-example",
            "--dev",
        ],
    );
    assert!(!o.status.success());
    assert!(!cli.path("wrong.toml").exists());
    // Unknown organization.
    let o = cli.run(
        "ghost",
        &[
            "init",
            "--service",
            &w.service_url,
            "--registry-key",
            &w.registry_key_hex(),
            "--org",
            "ghost-org",
            "--client-id",
            "x",
            "--dev",
        ],
    );
    assert!(!o.status.success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn alice_opens_bob_is_denied() {
    let w = world!();
    let cli = Cli::new();
    cli.init(&w, "acme", ACME);
    cli.init(&w, "example", EXAMPLE);
    // Sender logs in so the artifact can be registered.
    assert_ok(&cli.run("acme", &["login", "--dev-user", "carol"]));
    let file = pack(&cli, &w, &["--register"]);
    let f = file.to_str().unwrap();

    // Anyone can check the artifact against the registry.
    let o = cli.run("example", &["status", f]);
    assert_ok(&o);
    assert!(text(&o).contains("For you:    yes"));

    // Alice.
    let out = cli.path("alice-out");
    let o = cli.run(
        "example",
        &[
            "open",
            f,
            "-o",
            out.to_str().unwrap(),
            "--dev-user",
            "alice",
        ],
    );
    assert_ok(&o);
    let t = text(&o);
    for step in [
        "Signature valid (sender: acme-security)",
        "Checking authorization",
        "Access approved",
        "Decrypting locally",
        "TLP:AMBER",
    ] {
        assert!(t.contains(step), "missing {step:?}:\n{t}");
    }
    let opened = out.join("secret.txt");
    assert_eq!(std::fs::read(&opened).unwrap(), SECRET);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&opened).unwrap().permissions().mode() & 0o077,
            0
        );
    }
    // Opening again does not clobber.
    let o = cli.run(
        "example",
        &[
            "open",
            f,
            "-o",
            out.to_str().unwrap(),
            "--dev-user",
            "alice",
        ],
    );
    assert_code(&o, 2, "already exists");
    assert!(leftovers(&out).is_empty());

    // Streaming to a pipe.
    let o = cli.run("example", &["open", f, "--stdout", "--dev-user", "alice"]);
    assert_ok(&o);
    assert_eq!(o.stdout, SECRET);

    // Bob: authenticated, not authorized; nothing written.
    let bob_out = cli.path("bob-out");
    let o = cli.run(
        "example",
        &[
            "open",
            f,
            "-o",
            bob_out.to_str().unwrap(),
            "--dev-user",
            "bob",
        ],
    );
    assert_code(&o, 1, "not authorized");
    assert!(!bob_out.join("secret.txt").exists());
    assert!(!bob_out.exists() || leftovers(&bob_out).is_empty());

    // Carol at Acme is not the recipient: refused before any login.
    let o = cli.run("acme", &["open", f, "--dev-user", "carol"]);
    assert_code(&o, 1, "addressed to example-corp");
    assert!(!text(&o).contains("Authenticating"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampered_and_expired_are_refused_before_login() {
    let w = world!();
    let cli = Cli::new();
    cli.init(&w, "acme", ACME);
    cli.init(&w, "example", EXAMPLE);
    let file = pack(&cli, &w, &[]);
    let mut bytes = std::fs::read(&file).unwrap();
    let n = bytes.len();
    bytes[n / 2] ^= 1;
    std::fs::write(cli.path("tampered.svx"), &bytes).unwrap();
    let o = cli.run("example", &["open", "tampered.svx", "--dev-user", "alice"]);
    assert_code(&o, 1, "REJECTED");
    assert!(!text(&o).contains("Authenticating"));
    let o = cli.run("example", &["status", "tampered.svx"]);
    assert_code(&o, 1, "REJECTED");

    // Expired (signed expiry in the past).
    let expired = w.pack_with(&w.acme_sign, now() - 100, Some(now() - 10), POLICY);
    std::fs::write(cli.path("expired.svx"), expired).unwrap();
    let o = cli.run("example", &["open", "expired.svx", "--dev-user", "alice"]);
    assert_code(&o, 1, "expired");
    assert!(!text(&o).contains("Authenticating"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_login_policy_revoke_audit() {
    let w = world!();
    let cli = Cli::new();
    cli.init(&w, "acme", ACME);
    cli.init(&w, "example", EXAMPLE);
    let file = pack(&cli, &w, &[]);
    let f = file.to_str().unwrap();

    // Admin commands need a session.
    let o = cli.run("example", &["policy", "list"]);
    assert_code(&o, 2, "not logged in");

    assert_ok(&cli.run("example", &["login", "--dev-user", "example-admin"]));
    let o = cli.run("example", &["whoami"]);
    assert_ok(&o);
    assert!(text(&o).contains("example-admin"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(cli.path("session.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(m & 0o077, 0);
    }

    // Policies: list, add one that also allows bob, show it.
    let o = cli.run("example", &["policy", "list"]);
    assert_ok(&o);
    assert!(text(&o).contains("incident-response"));
    std::fs::write(cli.path("p.json"), r#"{"allow_users":["bob"]}"#).unwrap();
    assert_ok(&cli.run(
        "example",
        &["policy", "set", "bob-only", "--file", "p.json"],
    ));
    let o = cli.run("example", &["policy", "show", "bob-only"]);
    assert_ok(&o);
    assert!(text(&o).contains("bob"));
    std::fs::write(cli.path("bad.json"), r#"{"allow_users":[]}"#).unwrap();
    assert!(
        !cli.run("example", &["policy", "set", "x", "--file", "bad.json"])
            .status
            .success()
    );

    // Alice opens, then the recipient admin revokes, then Alice is denied.
    assert_ok(&cli.run("example", &["open", f, "-o", "a1", "--dev-user", "alice"]));
    let o = cli.run("example", &["revoke", f]);
    assert_ok(&o);
    let o = cli.run("example", &["open", f, "-o", "a2", "--dev-user", "alice"]);
    assert_code(&o, 1, "expired or revoked");

    // Audit shows the story and the chain verifies.
    let o = cli.run("example", &["audit", "--limit", "200"]);
    assert_ok(&o);
    let t = text(&o);
    for ev in [
        "decryption_authorized",
        "artifact_revoked",
        "revoked_artifact_access",
        "policy_changed",
    ] {
        assert!(t.contains(ev), "missing {ev}:\n{t}");
    }
    assert!(t.contains("Hash chain: valid"));

    // Non-admins cannot administer.
    assert_ok(&cli.run("example", &["logout"]));
    assert_ok(&cli.run("example", &["login", "--dev-user", "bob"]));
    let o = cli.run("example", &["revoke", f]);
    assert!(!o.status.success());

    // Registry lookup.
    let o = cli.run("example", &["organizations", "show", ACME]);
    assert_ok(&o);
    assert!(text(&o).contains("ed25519"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn service_unavailable_fails_closed() {
    let w = world!();
    let cli = Cli::new();
    cli.init(&w, "acme", ACME);
    let file = pack(&cli, &w, &[]);
    // Point Example Corp's config at a port where nothing listens.
    let cfg = svx_client::ClientConfig {
        service_url: "http://127.0.0.1:9".into(),
        registry_key: w.registry_key_hex(),
        registry_public: w.registry_public_hex(),
        org_id: EXAMPLE.into(),
        idp_issuer: w.example_idp.issuer().into(),
        idp_client_id: "svx-example".into(),
        group_claim: "groups".into(),
        dev: true,
        default_output_dir: None,
    };
    cfg.save(&cli.path("down.toml")).unwrap();
    let out = cli.path("down-out");
    let o = cli.run(
        "down",
        &[
            "open",
            file.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--dev-user",
            "alice",
        ],
    );
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(!out.join("secret.txt").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dev_user_requires_dev_config() {
    let w = world!();
    let cli = Cli::new();
    cli.init(&w, "example", EXAMPLE);
    let p = cli.path("example.toml");
    let s = std::fs::read_to_string(&p)
        .unwrap()
        .replace("dev = true", "dev = false");
    std::fs::write(&p, s).unwrap();
    // With dev off, the loopback http service URL itself is refused.
    let o = cli.run("example", &["login", "--dev-user", "alice"]);
    assert_code(&o, 2, "https");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refused_open_creates_no_output_directory() {
    let w = world!();
    let cli = Cli::new();
    cli.init(&w, "acme", ACME);
    cli.init(&w, "example", EXAMPLE);
    let file = pack(&cli, &w, &[]);
    let out = cli.path("never-created");
    let o = cli.run(
        "example",
        &[
            "open",
            file.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--dev-user",
            "bob",
        ],
    );
    assert_code(&o, 1, "not authorized");
    assert!(!out.exists(), "output directory created for a denied open");
    let o = cli.run(
        "example",
        &[
            "open",
            file.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--dev-user",
            "alice",
        ],
    );
    assert_ok(&o);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}
