//! Conformance: the committed vectors must (a) be reproduced byte-for-byte
//! by the generator and (b) be accepted/rejected as their metadata says.

use std::io::Cursor;
use std::path::PathBuf;

use svx_core::format::EnvelopeRole;
use svx_testvectors::{TestKeys, generate};

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors/v1")
}

#[test]
fn committed_vectors_are_reproducible() {
    for (name, bytes) in generate() {
        let on_disk = std::fs::read(dir().join(&name))
            .unwrap_or_else(|e| panic!("{name}: {e} (run `cargo run -p svx-testvectors`)"));
        assert!(
            on_disk == bytes,
            "{name} differs from generator output; regenerate and review the diff"
        );
    }
}

#[test]
fn committed_vectors_behave_as_declared() {
    let keys = TestKeys::new();
    let trust = keys.trust();
    let mut checked = 0;
    for entry in std::fs::read_dir(dir()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") || path.ends_with("keys.json")
        {
            continue;
        }
        let meta: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let svx = std::fs::read(dir().join(meta["file"].as_str().unwrap())).unwrap();
        let name = meta["name"].as_str().unwrap();
        match meta["expected_result"].as_str().unwrap() {
            "accept" => {
                let v = svx_core::verify(Cursor::new(&svx), &trust)
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(hex::encode(v.header_hash().as_bytes()), meta["header_hash"]);
                assert_eq!(
                    hex::encode(v.payload_commitment()),
                    meta["payload_commitment"]
                );
                let s = v
                    .unwrap_share(EnvelopeRole::Service, &keys.service_kem)
                    .unwrap();
                let r = v
                    .unwrap_share(EnvelopeRole::RecipientOrg, &keys.example_kem)
                    .unwrap();
                assert_eq!(
                    hex::encode(s.as_bytes()),
                    meta["shares_test_only"]["service"]
                );
                let mut pt = Vec::new();
                v.decrypt(Cursor::new(&svx), &s, &r, &mut pt).unwrap();
                assert_eq!(hex::encode(&pt), meta["plaintext_hex"], "{name}");
            }
            "reject" => {
                let parsed = svx_core::format::parse(&svx);
                let verified = svx_core::verify(Cursor::new(&svx), &trust);
                assert!(verified.is_err(), "{name} was accepted");
                match meta["reject_stage"].as_str().unwrap() {
                    "parse" => assert!(parsed.is_err(), "{name} should fail to parse"),
                    "verify" => {
                        assert!(parsed.is_ok(), "{name} should parse but fail verification")
                    }
                    other => panic!("unknown stage {other}"),
                }
            }
            other => panic!("unknown expected_result {other}"),
        }
        checked += 1;
    }
    assert!(checked >= 15, "only {checked} vectors found");
}
