//! Compatibility: the committed vectors in `test-vectors/v1` (made by earlier
//! builds, not regenerated here) must still behave exactly as their JSON
//! says with the current reader. Together with the "vectors reproducible"
//! check this pins the file format: a change that breaks old files, or that
//! changes the bytes of a suite, fails here.

use std::io::Cursor;
use std::path::PathBuf;

use serde_json::Value;
use sha2::{Digest, Sha256};
use svx_core::crypto::Share;
use svx_core::verify;
use svx_testvectors::TestKeys;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors/v1")
}

fn share(v: &Value) -> Share {
    let mut b = [0u8; 32];
    hex::decode_to_slice(v.as_str().unwrap(), &mut b).unwrap();
    Share::from_bytes(b)
}

#[test]
fn every_committed_vector_behaves_as_recorded() {
    let keys = TestKeys::new();
    let trust = keys.trust();
    let (mut accepted, mut rejected) = (0, 0);
    let mut names: Vec<_> = std::fs::read_dir(dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .filter(|p| !p.file_name().unwrap().to_string_lossy().starts_with("keys"))
        .collect();
    names.sort();
    for json in names {
        let v: Value = serde_json::from_slice(&std::fs::read(&json).unwrap()).unwrap();
        let name = v["name"].as_str().unwrap();
        let bytes = std::fs::read(dir().join(v["file"].as_str().unwrap())).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            v["file_sha256"].as_str().unwrap(),
            "{name}: the file doesn't match its recorded hash"
        );
        match v["expected_result"].as_str().unwrap() {
            "accept" => {
                accepted += 1;
                let verified = verify(Cursor::new(&bytes), &trust)
                    .unwrap_or_else(|e| panic!("{name}: must verify, got {e}"));
                assert_eq!(
                    hex::encode(verified.header_hash().as_bytes()),
                    v["header_hash"].as_str().unwrap(),
                    "{name}: header hash"
                );
                assert_eq!(
                    hex::encode(verified.payload_commitment()),
                    v["payload_commitment"].as_str().unwrap(),
                    "{name}: payload commitment"
                );
                let shares = &v["shares_test_only"];
                let mut out = Vec::new();
                verified
                    .decrypt(
                        Cursor::new(&bytes),
                        &share(&shares["service"]),
                        &share(shares.get("recipient_org").unwrap_or(&shares["recipient"])),
                        &mut out,
                    )
                    .unwrap_or_else(|e| panic!("{name}: must decrypt, got {e}"));
                assert_eq!(
                    hex::encode(&out),
                    v["plaintext_hex"].as_str().unwrap(),
                    "{name}: plaintext"
                );
            }
            "reject" => {
                rejected += 1;
                assert!(
                    verify(Cursor::new(&bytes), &trust).is_err(),
                    "{name}: must be refused"
                );
                if v["reject_stage"] == "verify" {
                    svx_core::inspect(Cursor::new(&bytes))
                        .unwrap_or_else(|e| panic!("{name}: parses, only verify refuses ({e})"));
                }
            }
            other => panic!("{name}: unknown expected_result {other}"),
        }
    }
    // The set can grow, never shrink: a removed vector is a removed promise.
    assert!(accepted >= 10, "only {accepted} valid vectors found");
    assert!(rejected >= 27, "only {rejected} invalid vectors found");
}
