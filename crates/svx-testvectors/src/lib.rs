//! Deterministic SVX test vectors: SVX 1.0 (suite `0x0001`) and SVX 1.1
//! post-quantum hybrid (suite `0x0003`, files named `hybrid-*`).
//!
//! All keys here are derived from public labels and are **for testing only**.
//! Randomness comes from ChaCha20Rng seeded with SHA-256 of the vector name,
//! so regenerating produces byte-identical files.

use std::io::Cursor;

use chacha20::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use svx_core::crypto::{KemSecretKey, KeyKind, SigningKey, Suite};
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
    /// Hybrid (SVX-1H) counterparts.
    pub acme_sign_h: SigningKey,
    pub mallory_sign_h: SigningKey,
    pub example_kem_h: KemSecretKey,
    pub service_kem_h: KemSecretKey,
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
            acme_sign_h: SigningKey::hybrid_from_seeds(
                &sha(b"SVX-1H TEST VECTOR ONLY: acme-security ed25519"),
                &sha(b"SVX-1H TEST VECTOR ONLY: acme-security ml-dsa-65"),
            ),
            mallory_sign_h: SigningKey::hybrid_from_seeds(
                &sha(b"SVX-1H TEST VECTOR ONLY: mallory ed25519"),
                &sha(b"SVX-1H TEST VECTOR ONLY: mallory ml-dsa-65"),
            ),
            example_kem_h: KemSecretKey::derive_kind(
                KeyKind::XWingKem,
                b"SVX-1H TEST VECTOR ONLY: example-corp x-wing",
            )
            .expect("X-Wing key"),
            service_kem_h: KemSecretKey::derive_kind(
                KeyKind::XWingKem,
                b"SVX-1H TEST VECTOR ONLY: svx.example x-wing",
            )
            .expect("X-Wing key"),
        }
    }

    /// Acme's classical and hybrid signing keys are both trusted.
    pub fn trust(&self) -> TrustStore {
        let mut t = TrustStore::new();
        t.add(id("acme-security"), self.acme_sign.verifying_key());
        t.add(id("acme-security"), self.acme_sign_h.verifying_key());
        t
    }

    /// `(service, recipient org)` KEM secret keys for `suite`.
    pub fn kems(&self, suite: Suite) -> (&KemSecretKey, &KemSecretKey) {
        match suite {
            Suite::Svx1 => (&self.service_kem, &self.example_kem),
            Suite::Svx1H => (&self.service_kem_h, &self.example_kem_h),
        }
    }

    fn json_hybrid(&self) -> Value {
        let sign = |k: &SigningKey| {
            json!({
                "ed25519_mldsa65_secret": hex::encode(&*k.to_secret_bytes()),
                "ed25519_mldsa65_public": hex::encode(k.verifying_key().to_vec()),
                "key_id": hex::encode(k.verifying_key().key_id()),
            })
        };
        let kem = |k: &KemSecretKey| {
            json!({
                "xwing_secret": hex::encode(*k.to_bytes()),
                "xwing_public": hex::encode(k.public_key().to_vec()),
                "key_id": hex::encode(k.public_key().key_id()),
            })
        };
        json!({
            "WARNING": "TEST ONLY. These keys are public. Never use them for real data.",
            "note": "Suite 0x0003 (SVX-1H). Signing secrets are Ed25519 seed || ML-DSA-65 seed; X-Wing secrets are the 32-byte seed.",
            "acme-security": sign(&self.acme_sign_h),
            "example-corp": kem(&self.example_kem_h),
            "svx.example": kem(&self.service_kem_h),
            "mallory (untrusted)": {
                "ed25519_mldsa65_public": hex::encode(self.mallory_sign_h.verifying_key().to_vec()),
                "key_id": hex::encode(self.mallory_sign_h.verifying_key().key_id()),
            },
        })
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
                "x25519_public": hex::encode(self.example_kem.public_key().to_vec()),
                "key_id": hex::encode(self.example_kem.public_key().key_id()),
            },
            "svx.example": {
                "x25519_secret": hex::encode(*self.service_kem.to_bytes()),
                "x25519_public": hex::encode(self.service_kem.public_key().to_vec()),
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
    suite: Suite,
    keys: &TestKeys,
    signer: &SigningKey,
    name: &str,
    plaintext: &[u8],
    chunk_size: u32,
) -> Vec<u8> {
    let mut manifest = Manifest::single_file("secret.txt", plaintext.len() as u64);
    manifest.classification = Some("TLP:AMBER".into());
    manifest.description = Some("Fictional SVX test vector".into());
    let (service_kem, example_kem) = keys.kems(suite);
    let req = PackRequest {
        suite,
        sender_org: id("acme-security"),
        signing_key: signer,
        recipient_org: id("example-corp"),
        recipient_key: example_kem.public_key(),
        more_recipients: vec![],
        service_id: id("svx.example"),
        service_key: service_kem.public_key(),
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

    let basic = emit_valid(Suite::Svx1, &keys, &keys.acme_sign, "", &specs, &mut files);
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
            Suite::Svx1,
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

    hybrid(&keys, text, specs, &mut files);
    multi(&keys, text, &mut files);
    files
}

/// Generate, verify and record valid vectors for `suite`; returns the bytes
/// of the first one (the base for the invalid vectors).
fn emit_valid(
    suite: Suite,
    keys: &TestKeys,
    signer: &SigningKey,
    prefix: &str,
    specs: &[ValidSpec],
    files: &mut Vec<File>,
) -> Vec<u8> {
    let trust = keys.trust();
    let (service_kem, example_kem) = keys.kems(suite);
    let mut first = Vec::new();
    for s in specs {
        let name = format!("{prefix}{}", s.name);
        let svx = build(suite, keys, signer, &name, &s.plaintext, s.chunk_size);
        let v = svx_core::verify(Cursor::new(&svx), &trust).expect("vector verifies");
        assert_eq!(v.suite, suite);
        let svc = v
            .unwrap_share(EnvelopeRole::Service, service_kem)
            .expect("service share");
        let org = v
            .unwrap_share(EnvelopeRole::RecipientOrg, example_kem)
            .expect("org share");
        let mut pt = Vec::new();
        let manifest = v
            .decrypt(Cursor::new(&svx), &svc, &org, &mut pt)
            .expect("vector decrypts");
        assert_eq!(pt, s.plaintext);
        let c = svx_core::format::parse(&svx).expect("parse");

        let meta = json!({
            "name": name,
            "description": s.description,
            "expected_result": "accept",
            "file": format!("{name}.svx"),
            "file_sha256": hex::encode(sha(&svx)),
            "rng_seed": format!("SHA-256(\"{name}\")"),
            "trusted_senders": ["acme-security"],
            "header": {
                "format_version": format!("1.{}", c.prelude.minor),
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
        files.push((format!("{name}.json"), pretty(&meta)));
        if first.is_empty() {
            first = svx.clone();
        }
        files.push((format!("{name}.svx"), svx));
    }
    first
}

/// SVX 1.1 / suite 0x0003 vectors (`hybrid-*`).
fn hybrid(keys: &TestKeys, text: &[u8], specs: [ValidSpec; 3], files: &mut Vec<File>) {
    files.push(("keys-hybrid.json".to_string(), pretty(&keys.json_hybrid())));
    let basic = emit_valid(
        Suite::Svx1H,
        keys,
        &keys.acme_sign_h,
        "hybrid-",
        &specs,
        files,
    );
    let c = svx_core::format::parse(&basic).expect("parse hybrid basic");
    let sig_start = basic.len() - svx_core::crypto::HYBRID_SIG_LEN;
    let ml_start = sig_start + svx_core::crypto::ED25519_SIG_LEN;
    let first_chunk_ct = c.header_region.len() + 5;
    // First X-Wing encapsulated key: after its 0x800E field header, the
    // envelope count, role and key ID, and its u16 length.
    let env_field = find(&basic, &0x800Eu16.to_le_bytes()).expect("v2 envelopes");
    let first_enc = env_field + 2 + 4 + 1 + 1 + 16 + 2;

    let mut invalid: Vec<(&str, &str, &str, Vec<u8>)> = Vec::new();
    let mut mutate = |name, desc, stage, f: &dyn Fn(&mut Vec<u8>)| {
        let mut b = basic.clone();
        f(&mut b);
        invalid.push((name, desc, stage, b));
    };
    mutate(
        "hybrid-invalid-downgraded-suite",
        "Prelude suite changed from 0x0003 to 0x0001 (downgrade attempt): layout V2 is not allowed for suite 0x0001.",
        "parse",
        &|b| b[10..12].copy_from_slice(&1u16.to_le_bytes()),
    );
    mutate(
        "hybrid-invalid-ed25519-tampered",
        "One bit flipped in the Ed25519 half of the hybrid signature (the ML-DSA-65 half is intact).",
        "verify",
        &|b| b[sig_start] ^= 0x01,
    );
    mutate(
        "hybrid-invalid-mldsa-tampered",
        "One bit flipped in the ML-DSA-65 half of the hybrid signature (the Ed25519 half is intact).",
        "verify",
        &|b| b[ml_start + 7] ^= 0x01,
    );
    mutate(
        "hybrid-invalid-envelope-tampered",
        "One bit flipped in the first X-Wing encapsulated key.",
        "verify",
        &|b| b[first_enc + 500] ^= 0x01,
    );
    mutate(
        "hybrid-invalid-chunk-tampered",
        "One bit flipped in the first chunk ciphertext.",
        "verify",
        &|b| b[first_chunk_ct] ^= 0x01,
    );
    invalid.push((
        "hybrid-invalid-untrusted-signer",
        "Signed by mallory's hybrid key while claiming sender acme-security.",
        "verify",
        build(
            Suite::Svx1H,
            keys,
            &keys.mallory_sign_h,
            "hybrid-invalid-untrusted-signer",
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
            "derived_from": "hybrid-valid-basic",
            "file": format!("{name}.svx"),
            "file_sha256": hex::encode(sha(&bytes)),
            "trusted_senders": ["acme-security"],
        });
        files.push((format!("{name}.json"), pretty(&meta)));
        files.push((format!("{name}.svx"), bytes));
    }
}

/// SVX 1.2 vectors (`multi-*`): one artifact for two recipients.
fn multi(keys: &TestKeys, text: &[u8], files: &mut Vec<File>) {
    let name = "multi-valid-two-recipients";
    let second = KemSecretKey::derive_kind(
        KeyKind::XWingKem,
        b"SVX-1.2 TEST VECTOR ONLY: u.0000000000000b0b x-wing",
    )
    .expect("X-Wing key");
    let (service_kem, example_kem) = keys.kems(Suite::Svx1H);
    let mut manifest = Manifest::single_file("secret.txt", text.len() as u64);
    manifest.description = Some("Fictional SVX test vector".into());
    let req = PackRequest {
        suite: Suite::Svx1H,
        sender_org: id("acme-security"),
        signing_key: &keys.acme_sign_h,
        recipient_org: id("example-corp"),
        recipient_key: example_kem.public_key(),
        more_recipients: vec![(id("u.0000000000000b0b"), second.public_key())],
        service_id: id("svx.example"),
        service_key: service_kem.public_key(),
        policy_ref: id("personal"),
        created_at: CREATED_AT,
        expires_at: Some(EXPIRES_AT),
        chunk_size: Some(64),
        manifest,
    };
    let mut rng = ChaCha20Rng::from_seed(sha(name.as_bytes()));
    let mut svx = Vec::new();
    svx_core::pack(&req, text, &mut svx, &mut rng).expect("pack multi vector");

    // Both recipients decrypt with their own key; the service share is shared.
    let v = svx_core::verify(Cursor::new(&svx), &keys.trust()).expect("multi vector verifies");
    let svc = v
        .unwrap_share(EnvelopeRole::Service, service_kem)
        .expect("service share");
    let mut shares = Vec::new();
    for k in [example_kem, &second] {
        let r = v
            .unwrap_share(EnvelopeRole::RecipientOrg, k)
            .expect("recipient share");
        let mut pt = Vec::new();
        v.decrypt(Cursor::new(&svx), &svc, &r, &mut pt)
            .expect("multi vector decrypts");
        assert_eq!(pt, text);
        shares.push(hex::encode(r.as_bytes()));
    }
    assert_eq!(shares[0], shares[1], "one recipient share, sealed twice");
    let c = svx_core::format::parse(&svx).expect("parse multi");
    let meta = json!({
        "name": name,
        "description": "Two recipients (SVX 1.2 recipients list): each opens with its own X-Wing key.",
        "expected_result": "accept",
        "file": format!("{name}.svx"),
        "file_sha256": hex::encode(sha(&svx)),
        "rng_seed": format!("SHA-256(\"{name}\")"),
        "trusted_senders": ["acme-security"],
        "header_hash": hex::encode(v.header_hash().as_bytes()),
        "payload_commitment": hex::encode(v.payload_commitment()),
        "header": {
            "format_version": format!("1.{}", c.prelude.minor),
            "suite_id": c.prelude.suite_id,
            "recipients": c.header.all_recipients().iter().map(|r| r.as_str()).collect::<Vec<_>>(),
            "recipient_key_ids": c.header.envelopes.iter()
                .filter(|e| e.role == EnvelopeRole::RecipientOrg)
                .map(|e| hex::encode(e.key_id))
                .collect::<Vec<_>>(),
        },
        "second_recipient_test_only": {
            "xwing_secret": hex::encode(*second.to_bytes()),
            "key_id": hex::encode(second.public_key().key_id()),
        },
        "shares_test_only": {
            "service": hex::encode(svc.as_bytes()),
            "recipient": shares[0],
        },
        "plaintext_hex": hex::encode(text),
    });
    files.push((format!("{name}.json"), pretty(&meta)));
    files.push((format!("{name}.svx"), svx.clone()));

    // The recipients list is signed: renaming the second recipient breaks it.
    let bad_name = "multi-invalid-recipient-renamed";
    let mut bad = svx;
    let at = find(&bad, b"u.0000000000000b0b").expect("second recipient");
    bad[at + 17] = b'c';
    let meta = json!({
        "name": bad_name,
        "description": "The second entry of the signed recipients list changed (u.…b0b to u.…b0c).",
        "expected_result": "reject",
        "reject_stage": "verify",
        "derived_from": name,
        "file": format!("{bad_name}.svx"),
        "file_sha256": hex::encode(sha(&bad)),
        "trusted_senders": ["acme-security"],
    });
    files.push((format!("{bad_name}.json"), pretty(&meta)));
    files.push((format!("{bad_name}.svx"), bad));
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
