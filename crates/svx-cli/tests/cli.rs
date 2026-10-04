use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

fn svx(dir: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("svx").unwrap();
    c.current_dir(dir);
    c
}

#[test]
fn pack_inspect_verify_tamper() {
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    for (kind, owner, out) in [
        ("sign", "acme-security", "acme"),
        ("kem", "example-corp", "example"),
        ("kem", "svx.example", "service"),
        ("sign", "mallory", "mallory"),
    ] {
        svx(d)
            .args(["keygen", "--kind", kind, "--owner", owner, "--out", out])
            .assert()
            .success();
    }
    std::fs::write(d.join("secret.txt"), b"fictional test data").unwrap();

    svx(d)
        .args([
            "pack",
            "secret.txt",
            "--sign-key",
            "acme.sign.key",
            "--recipient-key",
            "example.kem.pub",
            "--service-key",
            "service.kem.pub",
            "--policy",
            "incident-response",
            "--expires",
            "2099-01-01T00:00:00Z",
        ])
        .assert()
        .success()
        .stdout(contains("Recipient:   example-corp"));

    // Never prints secret key material.
    let sk = std::fs::read_to_string(d.join("acme.sign.key")).unwrap();
    let sk_hex: serde_json::Value = serde_json::from_str(&sk).unwrap();
    let out = svx(d).args(["inspect", "secret.svx"]).output().unwrap();
    assert!(!String::from_utf8_lossy(&out.stdout).contains(sk_hex["key"].as_str().unwrap()));
    assert!(String::from_utf8_lossy(&out.stdout).contains("UNVERIFIED"));

    svx(d)
        .args(["verify", "secret.svx", "--trust", "acme.sign.pub"])
        .assert()
        .success()
        .stdout(contains("VALID"));

    // Wrong trust anchor.
    svx(d)
        .args(["verify", "secret.svx", "--trust", "mallory.sign.pub"])
        .assert()
        .code(1)
        .stdout(contains("REJECTED"));

    // Tampered.
    let mut b = std::fs::read(d.join("secret.svx")).unwrap();
    let last = b.len() - 1;
    b[last] ^= 1;
    std::fs::write(d.join("tampered.svx"), &b).unwrap();
    svx(d)
        .args(["verify", "tampered.svx", "--trust", "acme.sign.pub"])
        .assert()
        .code(1)
        .stdout(contains("REJECTED"));

    // Refuses to overwrite; refuses past expiry.
    svx(d)
        .args([
            "pack",
            "secret.txt",
            "--sign-key",
            "acme.sign.key",
            "--recipient-key",
            "example.kem.pub",
            "--service-key",
            "service.kem.pub",
            "--policy",
            "p",
        ])
        .assert()
        .failure();
    svx(d)
        .args([
            "pack",
            "secret.txt",
            "--sign-key",
            "acme.sign.key",
            "--recipient-key",
            "example.kem.pub",
            "--service-key",
            "service.kem.pub",
            "--policy",
            "p",
            "--expires",
            "2000-01-01T00:00:00Z",
            "-o",
            "old.svx",
        ])
        .assert()
        .failure()
        .stderr(contains("past"));
    assert!(!d.join("old.svx").exists());
}

#[test]
fn keygen_kinds_and_classical_keys_cannot_pack() {
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path();
    for (kind, owner, out) in [
        ("sign", "acme-security", "acme"),
        ("kem", "example-corp", "example"),
        ("kem", "svx.example", "service"),
    ] {
        svx(d)
            .args(["keygen", "--kind", kind, "--owner", owner, "--out", out])
            .assert()
            .success()
            .stdout(contains(if kind == "sign" {
                "Fingerprint: "
            } else {
                "Key ID: "
            }));
    }
    let kind = |f: &str| {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(d.join(f)).unwrap()).unwrap();
        v["type"].as_str().unwrap().to_owned()
    };
    assert_eq!(kind("acme.sign.pub"), "ed25519-mldsa87-slhdsa-public");
    assert_eq!(kind("example.kem.pub"), "mlkem1024-p384-public");
    // `svx keygen` makes only SVX-2 keys; write an older hybrid one (as
    // earlier versions did) to check that it can't make new files.
    svx_core::keyfile::write_signing_pair(
        &d.join("registry"),
        &svx_core::format::Identifier::new("acme-security").unwrap(),
        &svx_core::crypto::SigningKey::generate_hybrid(&mut svx_core::crypto::os_rng()),
    )
    .unwrap();
    assert_eq!(kind("registry.sign.pub"), "ed25519-mldsa65-public");

    std::fs::write(d.join("a.txt"), b"fictional").unwrap();
    svx(d)
        .args([
            "pack",
            "a.txt",
            "--sign-key",
            "registry.sign.key",
            "--recipient-key",
            "example.kem.pub",
            "--service-key",
            "service.kem.pub",
            "--policy",
            "p",
        ])
        .assert()
        .failure()
        .stderr(contains("SVX-2"));
    assert!(!d.join("a.svx").exists());
    // The default keys make an SVX-2 file.
    svx(d)
        .args([
            "pack",
            "a.txt",
            "--sign-key",
            "acme.sign.key",
            "--recipient-key",
            "example.kem.pub",
            "--service-key",
            "service.kem.pub",
            "--policy",
            "p",
        ])
        .assert()
        .success()
        .stdout(contains("maximum"));
    svx(d)
        .args(["inspect", "a.svx"])
        .assert()
        .success()
        .stdout(contains("suite 0x0004"));
}

#[cfg(unix)]
#[test]
fn secret_keys_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    svx(tmp.path())
        .args([
            "keygen",
            "--kind",
            "kem",
            "--owner",
            "example-corp",
            "--out",
            "k",
        ])
        .assert()
        .success();
    let mode = std::fs::metadata(tmp.path().join("k.kem.key"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "secret key readable by group/other");
}

/// A view-only file says so in `inspect`, in text and JSON; an ordinary one doesn't.
#[test]
fn inspect_shows_view_only() {
    let tmp = tempfile::tempdir().unwrap();
    let vectors = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors/v1");
    let flagged = vectors.join("max-valid-view-only.svx");
    let plain = vectors.join("max-valid-basic.svx");
    svx(tmp.path())
        .arg("inspect")
        .arg(&flagged)
        .assert()
        .success()
        .stdout(contains("View only:  yes"));
    svx(tmp.path())
        .arg("inspect")
        .arg(&flagged)
        .arg("--json")
        .assert()
        .success()
        .stdout(contains("\"view_only\": true"));
    svx(tmp.path())
        .arg("inspect")
        .arg(&plain)
        .assert()
        .success()
        .stdout(predicates::str::contains("View only").not());
}
