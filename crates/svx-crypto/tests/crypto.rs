use chacha20::ChaCha20Rng;
use rand_core::SeedableRng;
use svx_crypto::*;
use svx_format::{EnvelopeRole, Identifier};

const SUITES: [Suite; 2] = [Suite::Svx1, Suite::Svx1H];

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([7; 32])
}

fn kem(suite: Suite, r: &mut ChaCha20Rng) -> KemSecretKey {
    match suite {
        Suite::Svx1 => KemSecretKey::generate(r),
        Suite::Svx1H => KemSecretKey::generate_hybrid(r),
    }
}

fn signer(suite: Suite, r: &mut ChaCha20Rng) -> SigningKey {
    match suite {
        Suite::Svx1 => SigningKey::generate(r),
        Suite::Svx1H => SigningKey::generate_hybrid(r),
    }
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
    for suite in SUITES {
        let mut r = rng();
        let sk = kem(suite, &mut r);
        let other = kem(suite, &mut r);
        let share = Share::generate(&mut r);
        let c = Ctx::new();
        let svc = EnvelopeRole::Service;

        let (enc, ct) = seal_share(suite, svc, sk.public_key(), &c.get(), &share, &mut r).unwrap();
        assert_eq!(enc.len(), suite.enc_len());
        assert_eq!(ct.len(), SEALED_SHARE_LEN);
        let opened = open_share(suite, svc, &sk, &c.get(), &enc, &ct).unwrap();
        assert_eq!(opened.as_bytes(), share.as_bytes());

        // Wrong role, wrong key, wrong context all fail.
        let role = EnvelopeRole::RecipientOrg;
        assert!(open_share(suite, role, &sk, &c.get(), &enc, &ct).is_err());
        assert!(open_share(suite, svc, &other, &c.get(), &enc, &ct).is_err());
        let mut c2 = Ctx::new();
        c2.artifact_id[0] ^= 1;
        assert!(open_share(suite, svc, &sk, &c2.get(), &enc, &ct).is_err());
        let mut c3 = Ctx::new();
        c3.sender_org = Identifier::new("mallory").unwrap();
        assert!(open_share(suite, svc, &sk, &c3.get(), &enc, &ct).is_err());
        // Truncated or extended encapsulation.
        assert!(open_share(suite, svc, &sk, &c.get(), &enc[1..], &ct).is_err());
        let mut longer = enc.clone();
        longer.push(0);
        assert!(open_share(suite, svc, &sk, &c.get(), &longer, &ct).is_err());
        // Any flipped byte of the encapsulation fails (both KEM halves count).
        for i in [0, enc.len() / 2, enc.len() - 1] {
            let mut bad = enc.clone();
            bad[i] ^= 1;
            assert!(
                open_share(suite, svc, &sk, &c.get(), &bad, &ct).is_err(),
                "{suite:?} {i}"
            );
        }
    }
}

#[test]
fn envelope_keys_must_match_the_suite() {
    let mut r = rng();
    let classical = KemSecretKey::generate(&mut r);
    let hybrid = KemSecretKey::generate_hybrid(&mut r);
    let c = Ctx::new();
    let share = Share::generate(&mut r);
    let svc = EnvelopeRole::Service;
    // A writer can't seal a hybrid-suite envelope to a classical key, or vice versa.
    assert!(
        seal_share(
            Suite::Svx1H,
            svc,
            classical.public_key(),
            &c.get(),
            &share,
            &mut r
        )
        .is_err()
    );
    assert!(
        seal_share(
            Suite::Svx1,
            svc,
            hybrid.public_key(),
            &c.get(),
            &share,
            &mut r
        )
        .is_err()
    );
    // An SVX-1H envelope can't be opened as SVX-1 (labels and lengths differ).
    let (enc, ct) = seal_share(
        Suite::Svx1H,
        svc,
        hybrid.public_key(),
        &c.get(),
        &share,
        &mut r,
    )
    .unwrap();
    assert!(open_share(Suite::Svx1, svc, &hybrid, &c.get(), &enc, &ct).is_err());
}

#[test]
fn both_shares_required() {
    for suite in SUITES {
        let mut r = rng();
        let a = Share::generate(&mut r);
        let b = Share::generate(&mut r);
        let wrong = Share::generate(&mut r);
        let id = [9u8; 16];
        let k = ArtifactKeys::derive(suite, &id, &a, &b);
        k.check_commitment(&k.key_commitment()).unwrap();
        for (x, y) in [(&a, &wrong), (&wrong, &b), (&b, &a)] {
            let k2 = ArtifactKeys::derive(suite, &id, x, y);
            assert_eq!(
                k2.check_commitment(&k.key_commitment()),
                Err(CryptoError::KeyCommitmentMismatch)
            );
        }
    }
    // The same shares give different keys under different suites.
    let mut r = rng();
    let (a, b) = (Share::generate(&mut r), Share::generate(&mut r));
    let k1 = ArtifactKeys::derive(Suite::Svx1, &[0; 16], &a, &b);
    let k2 = ArtifactKeys::derive(Suite::Svx1H, &[0; 16], &a, &b);
    assert_ne!(k1.key_commitment(), k2.key_commitment());
}

#[test]
fn stream_detects_reorder_truncation_and_flag_flip() {
    let mut r = rng();
    let keys = ArtifactKeys::derive(
        Suite::Svx1,
        &[0; 16],
        &Share::generate(&mut r),
        &Share::generate(&mut r),
    );
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
    for suite in SUITES {
        let mut r = rng();
        let sk = signer(suite, &mut r);
        let vk = sk.verifying_key();
        let hh = header_hash(b"h");
        let (alg, sig) = sign_transcript(suite, &sk, &hh, 3, &[1; 32], &mut r).unwrap();
        assert_eq!(alg, suite.sig_alg());
        verify_transcript(suite, &vk, &hh, 3, &[1; 32], alg, &sig).unwrap();
        assert!(verify_transcript(suite, &vk, &hh, 4, &[1; 32], alg, &sig).is_err());
        assert!(verify_transcript(suite, &vk, &hh, 3, &[2; 32], alg, &sig).is_err());
        assert!(verify_transcript(suite, &vk, &hh, 3, &[1; 32], 0x0009, &sig).is_err());
        let other = signer(suite, &mut r).verifying_key();
        assert!(verify_transcript(suite, &other, &hh, 3, &[1; 32], alg, &sig).is_err());
        // Truncated / extended signatures.
        assert!(
            verify_transcript(suite, &vk, &hh, 3, &[1; 32], alg, &sig[..sig.len() - 1]).is_err()
        );
        let mut longer = sig.clone();
        longer.push(0);
        assert!(verify_transcript(suite, &vk, &hh, 3, &[1; 32], alg, &longer).is_err());
    }
}

#[test]
fn hybrid_signature_needs_both_halves() {
    let mut r = rng();
    let sk = SigningKey::generate_hybrid(&mut r);
    let vk = sk.verifying_key();
    let hh = header_hash(b"h");
    let s = Suite::Svx1H;
    let (alg, sig) = sign_transcript(s, &sk, &hh, 1, &[0; 32], &mut r).unwrap();
    assert_eq!(sig.len(), HYBRID_SIG_LEN);
    // Breaking only the Ed25519 half, or only the ML-DSA half, is not enough to pass.
    let mut ed_broken = sig.clone();
    ed_broken[10] ^= 1;
    assert!(verify_transcript(s, &vk, &hh, 1, &[0; 32], alg, &ed_broken).is_err());
    let mut ml_broken = sig.clone();
    ml_broken[ED25519_SIG_LEN + 100] ^= 1;
    assert!(verify_transcript(s, &vk, &hh, 1, &[0; 32], alg, &ml_broken).is_err());
    // Splicing a valid half from another signature over a different message fails.
    let (_, other) = sign_transcript(s, &sk, &hh, 2, &[0; 32], &mut r).unwrap();
    let mut spliced = sig[..ED25519_SIG_LEN].to_vec();
    spliced.extend_from_slice(&other[ED25519_SIG_LEN..]);
    assert!(verify_transcript(s, &vk, &hh, 1, &[0; 32], alg, &spliced).is_err());
    // Hedged signing: two signatures over the same message differ, both verify.
    let (_, again) = sign_transcript(s, &sk, &hh, 1, &[0; 32], &mut r).unwrap();
    assert_ne!(again, sig);
    verify_transcript(s, &vk, &hh, 1, &[0; 32], alg, &again).unwrap();
}

#[test]
fn signatures_do_not_cross_suites() {
    let mut r = rng();
    let classical = SigningKey::generate(&mut r);
    let hybrid = SigningKey::generate_hybrid(&mut r);
    let hh = header_hash(b"h");
    // A key can only sign under its own suite.
    assert!(sign_transcript(Suite::Svx1H, &classical, &hh, 1, &[0; 32], &mut r).is_err());
    assert!(sign_transcript(Suite::Svx1, &hybrid, &hh, 1, &[0; 32], &mut r).is_err());
    // An SVX-1 signature does not verify as SVX-1H, even with the Ed25519 half of
    // a hybrid key (the suite label differs and both halves are required).
    let (alg, sig) = sign_transcript(Suite::Svx1, &classical, &hh, 1, &[0; 32], &mut r).unwrap();
    let vk = classical.verifying_key();
    assert!(verify_transcript(Suite::Svx1H, &vk, &hh, 1, &[0; 32], alg, &sig).is_err());
    assert!(
        verify_transcript(
            Suite::Svx1H,
            &vk,
            &hh,
            1,
            &[0; 32],
            SIG_ALG_ED25519_MLDSA65,
            &sig
        )
        .is_err()
    );
    // The Ed25519 half of an SVX-1H signature is not a valid SVX-1 signature.
    let (_, hsig) = sign_transcript(Suite::Svx1H, &hybrid, &hh, 1, &[0; 32], &mut r).unwrap();
    let ed_only = VerifyingKey::from_bytes(&hybrid.verifying_key().to_bytes()).unwrap();
    assert!(
        verify_transcript(
            Suite::Svx1,
            &ed_only,
            &hh,
            1,
            &[0; 32],
            SIG_ALG_ED25519,
            &hsig[..64]
        )
        .is_err()
    );
}

#[test]
fn manifest_round_trip() {
    let mut r = rng();
    let keys = ArtifactKeys::derive(
        Suite::Svx1H,
        &[0; 16],
        &Share::generate(&mut r),
        &Share::generate(&mut r),
    );
    let ct = seal_manifest(&keys, &[0; 16], b"{}").unwrap();
    assert_eq!(open_manifest(&keys, &[0; 16], &ct).unwrap(), b"{}");
    assert!(open_manifest(&keys, &[1; 16], &ct).is_err());
}

#[test]
fn exactly_two_suites() {
    assert_eq!(check_suite(SUITE_SVX1).unwrap(), Suite::Svx1);
    assert_eq!(check_suite(SUITE_SVX1H).unwrap(), Suite::Svx1H);
    for bad in [0x0000, 0x0002, 0x0004, 0xffff] {
        assert!(check_suite(bad).is_err(), "{bad:#x}");
    }
}

#[test]
fn key_serialization_and_redaction() {
    let mut r = rng();
    for kind in [KeyKind::X25519Kem, KeyKind::XWingKem] {
        let sk = KemSecretKey::derive_kind(kind, &[3; 32]).unwrap();
        let sk2 = KemSecretKey::from_kind_bytes(kind, &sk.to_bytes()).unwrap();
        assert_eq!(sk.public_key(), sk2.public_key());
        let pk = KemPublicKey::from_kind_bytes(kind, &sk.public_key().to_vec()).unwrap();
        assert_eq!(&pk, sk.public_key());
        let dbg = format!("{sk:?}");
        assert!(!dbg.contains(&hex::encode(*sk.to_bytes())));
    }
    assert_eq!(
        KemSecretKey::generate_hybrid(&mut r)
            .public_key()
            .to_vec()
            .len(),
        XWING_PUBLIC_LEN
    );
    // Same 32 bytes as different kinds give different public keys and IDs.
    let x = KemSecretKey::from_kind_bytes(KeyKind::X25519Kem, &[5; 32]).unwrap();
    let w = KemSecretKey::from_kind_bytes(KeyKind::XWingKem, &[5; 32]).unwrap();
    assert_ne!(x.public_key().key_id(), w.public_key().key_id());

    for sig in [
        SigningKey::generate(&mut r),
        SigningKey::generate_hybrid(&mut r),
    ] {
        let sig2 = SigningKey::from_secret_bytes(sig.kind(), &sig.to_secret_bytes()).unwrap();
        assert_eq!(sig.verifying_key(), sig2.verifying_key());
        let vk = sig.verifying_key();
        let vk2 = VerifyingKey::from_kind_bytes(vk.kind(), &vk.to_vec()).unwrap();
        assert_eq!(vk, vk2);
        let dbg = format!("{sig:?}");
        assert!(!dbg.contains(&hex::encode(&sig.to_secret_bytes()[..32])));
    }
    assert_eq!(
        SigningKey::generate_hybrid(&mut r)
            .verifying_key()
            .to_vec()
            .len(),
        HYBRID_PUBLIC_LEN
    );
    assert!(format!("{:?}", Share::generate(&mut r)).contains("redacted"));
    // Weak Ed25519 key (identity point) rejected, alone or inside a hybrid key.
    let mut ident = [0u8; 32];
    ident[0] = 1;
    assert!(VerifyingKey::from_bytes(&ident).is_err());
    let mut hybrid = SigningKey::generate_hybrid(&mut r).verifying_key().to_vec();
    hybrid[..32].copy_from_slice(&ident);
    assert!(VerifyingKey::from_kind_bytes(KeyKind::HybridSigning, &hybrid).is_err());
    // Wrong lengths.
    assert!(VerifyingKey::from_kind_bytes(KeyKind::HybridSigning, &hybrid[1..]).is_err());
    assert!(KemPublicKey::from_kind_bytes(KeyKind::XWingKem, &[0; 32]).is_err());
    assert!(SigningKey::from_secret_bytes(KeyKind::HybridSigning, &[0; 32]).is_err());
}

#[test]
fn released_share_bound_to_client_key_txn_role_and_artifact() {
    for suite in SUITES {
        let mut r = rng();
        let client = kem(suite, &mut r);
        let other = kem(suite, &mut r);
        let share = Share::generate(&mut r);
        let (aid, txn) = ([1u8; 16], [2u8; 16]);
        let svc = EnvelopeRole::Service;
        let (enc, ct) =
            seal_released_share(svc, &share, client.public_key(), &aid, &txn, &mut r).unwrap();
        assert_eq!(enc.len(), suite.enc_len());
        let got = open_released_share(svc, &client, &aid, &txn, &enc, &ct).unwrap();
        assert_eq!(got.as_bytes(), share.as_bytes());
        assert!(open_released_share(svc, &other, &aid, &txn, &enc, &ct).is_err());
        let org = EnvelopeRole::RecipientOrg;
        assert!(open_released_share(org, &client, &aid, &txn, &enc, &ct).is_err());
        assert!(open_released_share(svc, &client, &[9; 16], &txn, &enc, &ct).is_err());
        assert!(open_released_share(svc, &client, &aid, &[9; 16], &enc, &ct).is_err());
    }
}

#[test]
fn nonce_binding_depends_on_key_and_txn() {
    for suite in SUITES {
        let mut r = rng();
        let a = kem(suite, &mut r);
        let b = kem(suite, &mut r);
        let n = nonce_binding(a.public_key(), &[0; 16]);
        assert_eq!(n.len(), 64);
        assert_ne!(n, nonce_binding(b.public_key(), &[0; 16]));
        assert_ne!(n, nonce_binding(a.public_key(), &[1; 16]));
    }
}

#[test]
fn context_signatures_are_domain_separated() {
    let mut r = rng();
    let sk = SigningKey::generate(&mut r);
    let vk = sk.verifying_key();
    let sig = sign_context(&sk, SignContext::ReleaseGrant, b"payload");
    verify_context(&vk, SignContext::ReleaseGrant, b"payload", &sig).unwrap();
    assert!(verify_context(&vk, SignContext::RegistryRecord, b"payload", &sig).is_err());
    assert!(verify_context(&vk, SignContext::ReleaseGrant, b"payloaD", &sig).is_err());
}
