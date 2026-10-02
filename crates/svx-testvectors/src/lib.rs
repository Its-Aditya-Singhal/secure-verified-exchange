//! Deterministic SVX 1.0 test vectors.
//!
//! All keys here are derived from public labels and are **for testing only**.
//! Randomness comes from ChaCha20Rng seeded with SHA-256 of the vector name,
//! so regenerating produces byte-identical files.

use std::io::Cursor;

use chacha20::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use svx_core::crypto::{KemSecretKey, SigningKey};
use svx_core::format::{EnvelopeRole, Identifier};
use svx_core::{Manifest, PackRequest, TrustStore};

pub const CREATED_AT: i64 = 1_790_000_000; // 2026-09-21T14:13:20Z
pub const EXPIRES_AT: i64 = 1_790_604_800; // +7 days

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// The fixed, published, test-only key set.
pub struct TestKeys {
    pub acme_sign: SigningKey,
    pub mallory_sign: SigningKey,
    pub example_kem: KemSecretKey,
    pub service_kem: KemSecretKey,
}

impl TestKeys {
    pub fn new() -> Self {
        TestKeys {
            acme_sign: SigningKey::from_bytes(&sha(
                b"SVX-1 TEST VECTOR ONLY: acme-security ed25519",
            )),
            mallory_sign: SigningKey::from_bytes(&sha(b"SVX-1 TEST VECTOR ONLY: mallory ed25519")),
            example_kem: KemSecretKey::derive(b"SVX-1 TEST VECTOR ONLY: example-corp x25519"),
            service_kem: KemSecretKey::derive(b"SVX-1 TEST VECTOR ONLY: svx.example x25519"),
        }
    }

    pub fn trust(&self) -> TrustStore {
        let mut t = TrustStore::new();
        t.add(id("acme-security"), self.acme_sign.verifying_key());
        t
    }

    fn json(&self) -> Value {
        json!({
            "WARNING": "TEST ONLY. These keys are public. Never use them for real data.",
            "acme-security": {
                "ed25519_secret": hex::encode(*self.acme_sign.to_bytes()),
                "ed25519_public": hex::encode(self.acme_sign.verifying_key().to_bytes()),
                "key_id": hex::encode(self.acme_sign.verifying_key().key_id()),
            },
            "example-corp": {
                "x25519_secret": hex::encode(*self.example_kem.to_bytes()),
                "x25519_public": hex::encode(self.example_kem.public_key().to_bytes()),
                "key_id": hex::encode(self.example_kem.public_key().key_id()),
            },
            "svx.example": {
                "x25519_secret": hex::encode(*self.service_kem.to_bytes()),
                "x25519_public": hex::encode(self.service_kem.public_key().to_bytes()),
                "key_id": hex::encode(self.service_kem.public_key().key_id()),
            },
            "mallory (untrusted)": {
                "ed25519_public": hex::encode(self.mallory_sign.verifying_key().to_bytes()),
                "key_id": hex::encode(self.mallory_sign.verifying_key().key_id()),
            },
        })
    }
}

impl Default for TestKeys {
    fn default() -> Self {
        Self::new()
    }
}

fn id(s: &str) -> Identifier {
    Identifier::new(s).expect("valid identifier")
}

struct ValidSpec {
    name: &'static str,
    description: &'static str,
    plaintext: Vec<u8>,
    chunk_size: u32,
}

fn build(
    keys: &TestKeys,
    signer: &SigningKey,
    name: &str,
    plaintext: &[u8],
    chunk_size: u32,
) -> Vec<u8> {
    let mut manifest = Manifest::single_file("secret.txt", plaintext.len() as u64);
    manifest.classification = Some("TLP:AMBER".into());
    manifest.description = Some("Fictional SVX test vector".into());
    let req = PackRequest {
        sender_org: id("acme-security"),
        signing_key: signer,
        recipient_org: id("example-corp"),
        recipient_key: keys.example_kem.public_key(),
        service_id: id("svx.example"),
        service_key: keys.service_kem.public_key(),
        policy_ref: id("incident-response"),
        created_at: CREATED_AT,
        expires_at: Some(EXPIRES_AT),
        chunk_size: Some(chunk_size),
        manifest,
    };
    let mut rng = ChaCha20Rng::from_seed(sha(name.as_bytes()));
    let mut out = Vec::new();
    svx_core::pack(&req, plaintext, &mut out, &mut rng).expect("pack test vector");
    out
}

/// A generated file: relative path and contents.
pub type File = (String, Vec<u8>);

fn pretty(v: &Value) -> Vec<u8> {
    let mut s = serde_json::to_string_pretty(v).expect("json");
    s.push('\n');
    s.into_bytes()
}

/// Generate every vector. Paths are relative to the vector directory.
pub fn generate() -> Vec<File> {
    let keys = TestKeys::new();
    let trust = keys.trust();
    let mut files = vec![("keys.json".to_string(), pretty(&keys.json()))];

    let text = b"FICTIONAL TEST DATA - indicator 203.0.113.7 seen on host test-01.example. \
This is not a real secret and exists only to exercise SVX implementations.\n";
    let specs = [
        ValidSpec {
            name: "valid-basic",
            description: "Multi-chunk payload with a short final chunk.",
            plaintext: text.to_vec(),
            chunk_size: 64,
        },
        ValidSpec {
            name: "valid-exact-multiple",
            description: "Payload length is an exact multiple of the chunk size: no empty trailing chunk.",
            plaintext: vec![0x53; 128],
            chunk_size: 64,
        },
        ValidSpec {
            name: "valid-empty",
            description: "Empty payload: a single empty final chunk.",
            plaintext: Vec::new(),
            chunk_size: 64,
        },
    ];

    let mut basic = Vec::new();
    for s in &specs {
        let svx = build(&keys, &keys.acme_sign, s.name, &s.plaintext, s.chunk_size);
        let v = svx_core::verify(Cursor::new(&svx), &trust).expect("vector verifies");
        let svc = v
            .unwrap_share(EnvelopeRole::Service, &keys.service_kem)
            .expect("service share");
        let org = v
            .unwrap_share(EnvelopeRole::RecipientOrg, &keys.example_kem)
            .expect("org share");
        let mut pt = Vec::new();
        let manifest = v
            .decrypt(Cursor::new(&svx), &svc, &org, &mut pt)
            .expect("vector decrypts");
        assert_eq!(pt, s.plaintext);
        let c = svx_core::format::parse(&svx).expect("parse");

        let meta = json!({
            "name": s.name,
            "description": s.description,
            "expected_result": "accept",
            "file": format!("{}.svx", s.name),
            "file_sha256": hex::encode(sha(&svx)),
            "rng_seed": format!("SHA-256(\"{}\")", s.name),
            "trusted_senders": ["acme-security"],
            "header": {
                "format_version": "1.0",
                "suite_id": c.prelude.suite_id,
                "artifact_id": hex::encode(c.header.artifact_id),
                "created_at": c.header.created_at,
                "expires_at": c.header.expires_at,
                "sender_org": c.header.sender_org.as_str(),
                "sender_key_id": hex::encode(c.header.sender_key_id),
                "recipient_org": c.header.recipient_org.as_str(),
                "service_id": c.header.service_id.as_str(),
                "policy_ref": c.header.policy_ref.as_str(),
                "chunk_size": c.header.chunk_size,
                "nonce_prefix": hex::encode(c.header.nonce_prefix),
                "key_commitment": hex::encode(c.header.key_commitment),
            },
            "header_region_len": c.header_region.len(),
            "header_hash": hex::encode(v.header_hash().as_bytes()),
            "chunk_count": v.chunk_count,
            "payload_commitment": hex::encode(v.payload_commitment()),
            "signature": hex::encode(&c.trailer.signature),
            "shares_test_only": {
                "service": hex::encode(svc.as_bytes()),
                "recipient_org": hex::encode(org.as_bytes()),
            },
            "manifest": serde_json::to_value(&manifest).expect("manifest json"),
            "plaintext_hex": hex::encode(&pt),
        });
        files.push((format!("{}.json", s.name), pretty(&meta)));
        if s.name == "valid-basic" {
            basic = svx.clone();
        }
        files.push((format!("{}.svx", s.name), svx));
    }

    // Invalid vectors, all derived from valid-basic.
    let c = svx_core::format::parse(&basic).expect("parse basic");
    let hlen = c.header_region.len();
    let first_chunk_ct = hlen + 5;
    let sig_start = basic.len() - 64;

    let mut invalid: Vec<(&str, &str, &str, Vec<u8>)> = Vec::new();
    let mut mutate = |name, desc, stage, f: &dyn Fn(&mut Vec<u8>)| {
        let mut b = basic.clone();
        f(&mut b);
        invalid.push((name, desc, stage, b));
    };
    mutate(
        "invalid-bad-magic",
        "First magic byte changed.",
        "parse",
        &|b| b[0] = 0x88,
    );
    mutate(
        "invalid-major-version",
        "Format major version 2.",
        "parse",
        &|b| b[8] = 2,
    );
    mutate(
        "invalid-unsupported-suite",
        "Suite 0x0002 (not implemented): must not be downgraded or guessed.",
        "verify",
        &|b| b[10..12].copy_from_slice(&2u16.to_le_bytes()),
    );
    mutate(
        "invalid-header-len-huge",
        "header_len exceeds 1 MiB.",
        "parse",
        &|b| b[12..16].copy_from_slice(&u32::MAX.to_le_bytes()),
    );
    mutate(
        "invalid-header-tampered",
        "One bit flipped in the recipient organization ID.",
        "verify",
        &|b| {
            let pos = find(b, b"example-corp").expect("recipient id present");
            b[pos] ^= 0x01;
        },
    );
    mutate(
        "invalid-policy-tampered",
        "policy_ref changed from incident-response to incident-responsf.",
        "verify",
        &|b| {
            let pos = find(b, b"incident-response").expect("policy present");
            b[pos + 16] = b'f';
        },
    );
    mutate(
        "invalid-chunk-tampered",
        "One bit flipped in the first chunk ciphertext.",
        "verify",
        &|b| b[first_chunk_ct] ^= 0x01,
    );
    mutate(
        "invalid-signature-tampered",
        "One bit flipped in the signature.",
        "verify",
        &|b| b[sig_start] ^= 0x01,
    );
    mutate(
        "invalid-trailing-data",
        "Extra byte after the trailer.",
        "parse",
        &|b| b.push(0),
    );
    mutate(
        "invalid-truncated",
        "Final chunk and trailer removed.",
        "parse",
        &|b| b.truncate(first_chunk_ct + 64 + 16),
    );
    mutate(
        "invalid-unknown-critical-field",
        "ARTIFACT_ID tag replaced by unknown critical tag 0x80ff.",
        "parse",
        &|b| b[16..18].copy_from_slice(&0x80FFu16.to_le_bytes()),
    );

    // Reordered chunks (re-serialized, original signature).
    {
        let mut w = svx_core::format::Writer::new(Vec::new(), c.prelude.suite_id, &c.header)
            .expect("writer");
        let mut order: Vec<usize> = (0..c.chunks.len()).collect();
        order.swap(0, 1);
        for i in order {
            let (info, ct) = &c.chunks[i];
            w.write_chunk(info.is_final, ct).expect("chunk");
        }
        invalid.push((
            "invalid-chunks-reordered",
            "First two chunks swapped.",
            "verify",
            w.finish(&c.trailer).expect("finish"),
        ));
    }
    // Validly formed and signed, but by an untrusted key claiming to be acme-security.
    invalid.push((
        "invalid-untrusted-signer",
        "Signed by mallory's key while claiming sender acme-security.",
        "verify",
        build(
            &keys,
            &keys.mallory_sign,
            "invalid-untrusted-signer",
            text,
            64,
        ),
    ));

    for (name, desc, stage, bytes) in invalid {
        let meta = json!({
            "name": name,
            "description": desc,
            "expected_result": "reject",
            "reject_stage": stage,
            "derived_from": "valid-basic",
            "file": format!("{name}.svx"),
            "file_sha256": hex::encode(sha(&bytes)),
            "trusted_senders": ["acme-security"],
        });
        files.push((format!("{name}.json"), pretty(&meta)));
        files.push((format!("{name}.svx"), bytes));
    }
    files
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
