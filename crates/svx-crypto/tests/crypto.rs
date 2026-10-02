use chacha20::ChaCha20Rng;
use rand_core::SeedableRng;
use svx_crypto::*;
use svx_format::{EnvelopeRole, Identifier};

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([7; 32])
}

struct Ctx {
    artifact_id: [u8; 16],
    sender_org: Identifier,
    sender_key_id: [u8; 16],
    recipient_org: Identifier,
    service_id: Identifier,
}

impl Ctx {
    fn new() -> Self {
        Ctx {
            artifact_id: [1; 16],
            sender_org: Identifier::new("acme-security").unwrap(),
            sender_key_id: [2; 16],
            recipient_org: Identifier::new("example-corp").unwrap(),
            service_id: Identifier::new("svx.example").unwrap(),
        }
    }
    fn get(&self) -> EnvelopeContext<'_> {
        EnvelopeContext {
            artifact_id: &self.artifact_id,
            sender_org: &self.sender_org,
            sender_key_id: &self.sender_key_id,
            recipient_org: &self.recipient_org,
            service_id: &self.service_id,
        }
    }
}

#[test]
fn envelope_round_trip_and_binding() {
    let mut r = rng();
    let sk = KemSecretKey::generate(&mut r);
    let other = KemSecretKey::generate(&mut r);
    let share = Share::generate(&mut r);
    let c = Ctx::new();

    let (enc, ct) = seal_share(
        EnvelopeRole::Service,
        sk.public_key(),
        &c.get(),
        &share,
        &mut r,
    )
    .unwrap();
    assert_eq!(ct.len(), SEALED_SHARE_LEN);
    let opened = open_share(EnvelopeRole::Service, &sk, &c.get(), &enc, &ct).unwrap();
    assert_eq!(opened.as_bytes(), share.as_bytes());

    // Wrong role, wrong key, wrong context all fail.
    assert!(open_share(EnvelopeRole::RecipientOrg, &sk, &c.get(), &enc, &ct).is_err());
    assert!(open_share(EnvelopeRole::Service, &other, &c.get(), &enc, &ct).is_err());
    let mut c2 = Ctx::new();
    c2.artifact_id[0] ^= 1;
    assert!(open_share(EnvelopeRole::Service, &sk, &c2.get(), &enc, &ct).is_err());
    let mut c3 = Ctx::new();
    c3.sender_org = Identifier::new("mallory").unwrap();
    assert!(open_share(EnvelopeRole::Service, &sk, &c3.get(), &enc, &ct).is_err());
}

#[test]
fn both_shares_required() {
    let mut r = rng();
    let a = Share::generate(&mut r);
    let b = Share::generate(&mut r);
    let wrong = Share::generate(&mut r);
    let id = [9u8; 16];
    let k = ArtifactKeys::derive(&id, &a, &b);
    k.check_commitment(&k.key_commitment()).unwrap();
    for (x, y) in [(&a, &wrong), (&wrong, &b), (&b, &a)] {
        let k2 = ArtifactKeys::derive(&id, x, y);
        assert_eq!(
            k2.check_commitment(&k.key_commitment()),
            Err(CryptoError::KeyCommitmentMismatch)
        );
    }
}

#[test]
fn stream_detects_reorder_truncation_and_flag_flip() {
    let mut r = rng();
    let keys = ArtifactKeys::derive(&[0; 16], &Share::generate(&mut r), &Share::generate(&mut r));
    let hh = header_hash(b"header");
    let prefix = [4u8; 7];

    let mut enc = StreamEncryptor::new(&keys, prefix, &hh);
    let c0 = enc.encrypt_chunk(b"chunk zero", false).unwrap();
    let c1 = enc.encrypt_chunk(b"chunk one", false).unwrap();
    let c2 = enc.encrypt_chunk(b"end", true).unwrap();
    assert!(enc.encrypt_chunk(b"more", false).is_err());

    let mut dec = StreamDecryptor::new(&keys, prefix, &hh);
    assert_eq!(dec.decrypt_chunk(&c0, false).unwrap(), b"chunk zero");
    assert_eq!(dec.decrypt_chunk(&c1, false).unwrap(), b"chunk one");
    assert_eq!(dec.decrypt_chunk(&c2, true).unwrap(), b"end");
    dec.finish().unwrap();

    // Reordered
    let mut dec = StreamDecryptor::new(&keys, prefix, &hh);
    assert!(dec.decrypt_chunk(&c1, false).is_err());
    // Truncated: a non-final chunk presented as final
    let mut dec = StreamDecryptor::new(&keys, prefix, &hh);
    dec.decrypt_chunk(&c0, false).unwrap();
    assert!(dec.decrypt_chunk(&c1, true).is_err());
    // Truncated: stream stops early
    let mut dec = StreamDecryptor::new(&keys, prefix, &hh);
    dec.decrypt_chunk(&c0, false).unwrap();
    assert!(dec.finish().is_err());
    // Different header
    let mut dec = StreamDecryptor::new(&keys, prefix, &header_hash(b"headeR"));
    assert!(dec.decrypt_chunk(&c0, false).is_err());
}

#[test]
fn signature_round_trip_and_tamper() {
    let mut r = rng();
    let sk = SigningKey::generate(&mut r);
    let vk = sk.verifying_key();
    let hh = header_hash(b"h");
    let (alg, sig) = sign_transcript(&sk, &hh, 3, &[1; 32]);
    verify_transcript(&vk, &hh, 3, &[1; 32], alg, &sig).unwrap();
    assert!(verify_transcript(&vk, &hh, 4, &[1; 32], alg, &sig).is_err());
    assert!(verify_transcript(&vk, &hh, 3, &[2; 32], alg, &sig).is_err());
    assert!(verify_transcript(&vk, &hh, 3, &[1; 32], 2, &sig).is_err());
    let other = SigningKey::generate(&mut r).verifying_key();
    assert!(verify_transcript(&other, &hh, 3, &[1; 32], alg, &sig).is_err());
}

#[test]
fn manifest_round_trip() {
    let mut r = rng();
    let keys = ArtifactKeys::derive(&[0; 16], &Share::generate(&mut r), &Share::generate(&mut r));
    let ct = seal_manifest(&keys, &[0; 16], b"{}").unwrap();
    assert_eq!(open_manifest(&keys, &[0; 16], &ct).unwrap(), b"{}");
    assert!(open_manifest(&keys, &[1; 16], &ct).is_err());
}

#[test]
fn only_one_suite() {
    check_suite(SUITE_SVX1).unwrap();
    assert!(check_suite(0x0002).is_err());
    assert!(check_suite(0x0000).is_err());
}

#[test]
fn key_serialization_and_redaction() {
    let mut r = rng();
    let sk = KemSecretKey::generate(&mut r);
    let sk2 = KemSecretKey::from_bytes(&sk.to_bytes()).unwrap();
    assert_eq!(sk.public_key(), sk2.public_key());
    let sig = SigningKey::generate(&mut r);
    let sig2 = SigningKey::from_bytes(&sig.to_bytes());
    assert_eq!(sig.verifying_key(), sig2.verifying_key());
    let dbg = format!("{sk:?} {sig:?} {:?}", Share::generate(&mut r));
    assert!(!dbg.contains(&hex::encode(*sk.to_bytes())));
    assert!(dbg.contains("redacted"));
    // Weak Ed25519 key (identity point) rejected.
    let mut ident = [0u8; 32];
    ident[0] = 1;
    assert!(VerifyingKey::from_bytes(&ident).is_err());
}
