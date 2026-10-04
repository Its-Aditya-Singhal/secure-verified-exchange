//! End-to-end behaviour of pack → verify → unwrap shares → decrypt, and the
//! failure modes from the threat model.

use std::io::Cursor;

use chacha20::ChaCha20Rng;
use rand_core::SeedableRng;
use svx_core::crypto::{KemSecretKey, SigningKey, Suite};
use svx_core::format::{EnvelopeRole, Identifier};
use svx_core::*;

struct World {
    suite: Suite,
    acme_sign: SigningKey,
    mallory_sign: SigningKey,
    example_kem: KemSecretKey,
    service_kem: KemSecretKey,
    trust: TrustStore,
    rng: ChaCha20Rng,
}

fn id(s: &str) -> Identifier {
    Identifier::new(s).unwrap()
}

impl World {
    /// Classical suite SVX-1.
    fn new() -> Self {
        Self::with_suite(Suite::Svx1)
    }

    /// Post-quantum hybrid suite SVX-1H.
    fn hybrid() -> Self {
        Self::with_suite(Suite::Svx1H)
    }

    /// Maximum-strength suite SVX-2 (what writers produce).
    fn max() -> Self {
        Self::with_suite(Suite::Svx2)
    }

    fn all() -> [World; 3] {
        [Self::new(), Self::hybrid(), Self::max()]
    }

    fn with_suite(suite: Suite) -> Self {
        let mut rng = ChaCha20Rng::from_seed([42; 32]);
        let signer = |rng: &mut ChaCha20Rng| match suite {
            Suite::Svx1 => SigningKey::generate(rng),
            Suite::Svx1H => SigningKey::generate_hybrid(rng),
            Suite::Svx2 => SigningKey::generate_max(rng),
        };
        let acme_sign = signer(&mut rng);
        let mallory_sign = signer(&mut rng);
        let example_kem = Self::kem_for(suite, &mut rng);
        let service_kem = Self::kem_for(suite, &mut rng);
        let mut trust = TrustStore::new();
        trust.add(id("acme-security"), acme_sign.verifying_key());
        World {
            suite,
            acme_sign,
            mallory_sign,
            example_kem,
            service_kem,
            trust,
            rng,
        }
    }

    fn kem_for(suite: Suite, rng: &mut ChaCha20Rng) -> KemSecretKey {
        match suite {
            Suite::Svx1 => KemSecretKey::generate(rng),
            Suite::Svx1H => KemSecretKey::generate_hybrid(rng),
            Suite::Svx2 => KemSecretKey::generate_max(rng),
        }
    }

    fn copy(k: &SigningKey) -> SigningKey {
        SigningKey::from_secret_bytes(k.kind(), &k.to_secret_bytes()).unwrap()
    }

    fn pack_with(&mut self, signer: &SigningKey, sender: &str, data: &[u8], chunk: u32) -> Vec<u8> {
        let mut manifest = Manifest::single_file("secret.txt", data.len() as u64);
        manifest.classification = Some("TLP:RED".into());
        let req = PackRequest {
            suite: self.suite,
            sender_org: id(sender),
            signing_key: signer,
            recipient_org: id("example-corp"),
            recipient_key: self.example_kem.public_key(),
            more_recipients: vec![],
            service_id: id("svx.example"),
            service_key: self.service_kem.public_key(),
            policy_ref: id("incident-response"),
            created_at: 1_790_000_000,
            expires_at: Some(1_790_604_800),
            chunk_size: Some(chunk),
            manifest,
            view_only: false,
        };
        let mut out = Vec::new();
        let summary = pack(&req, data, &mut out, &mut self.rng).unwrap();
        assert_eq!(summary.plaintext_len, data.len() as u64);
        out
    }

    fn pack(&mut self, data: &[u8]) -> Vec<u8> {
        let k = Self::copy(&self.acme_sign);
        self.pack_with(&k, "acme-security", data, 64)
    }

    fn open(&self, file: &[u8]) -> Result<(Manifest, Vec<u8>)> {
        let v = verify(Cursor::new(file), &self.trust)?;
        let s = v.unwrap_share(EnvelopeRole::Service, &self.service_kem)?;
        let r = v.unwrap_share(EnvelopeRole::RecipientOrg, &self.example_kem)?;
        let mut out = Vec::new();
        let m = v.decrypt(Cursor::new(file), &s, &r, &mut out)?;
        Ok((m, out))
    }
}

const SECRET: &[u8] =
    b"FICTIONAL TEST DATA: indicator 203.0.113.7 observed on host test-01. Not a real secret.";

#[test]
fn authorized_round_trip() {
    for mut w in World::all() {
        for len in [0usize, 1, 63, 64, 65, 128, 1000] {
            let data: Vec<u8> = SECRET.iter().copied().cycle().take(len).collect();
            let file = w.pack(&data);
            let (m, out) = w.open(&file).unwrap();
            assert_eq!(out, data, "len {len}");
            assert_eq!(m.files[0].name, "secret.txt");
            assert_eq!(m.classification.as_deref(), Some("TLP:RED"));
        }
    }
}

#[test]
fn intercepted_file_reveals_no_plaintext_or_private_metadata() {
    for mut w in World::all() {
        let file = w.pack(SECRET);
        let hay = String::from_utf8_lossy(&file);
        for needle in ["FICTIONAL", "203.0.113.7", "secret.txt", "TLP:RED"] {
            assert!(!hay.contains(needle), "{needle} visible in ciphertext");
        }
        // Only opaque routing identifiers are public.
        let (_, h) = inspect(Cursor::new(&file)).unwrap();
        assert_eq!(h.recipient_org.as_str(), "example-corp");
    }
}

#[test]
fn file_alone_is_insufficient_one_share_is_insufficient() {
    for mut w in World::all() {
        let file = w.pack(SECRET);
        let v = verify(Cursor::new(&file), &w.trust).unwrap();
        let svc = v
            .unwrap_share(EnvelopeRole::Service, &w.service_kem)
            .unwrap();
        let org = v
            .unwrap_share(EnvelopeRole::RecipientOrg, &w.example_kem)
            .unwrap();
        let guess = svx_core::crypto::Share::generate(&mut w.rng);

        // Service alone (compromised service) or org agent alone cannot decrypt.
        for (a, b) in [(&svc, &guess), (&guess, &org), (&org, &svc)] {
            let mut out = Vec::new();
            let err = v.decrypt(Cursor::new(&file), a, b, &mut out).unwrap_err();
            assert!(matches!(
                err,
                CoreError::Crypto(svx_core::crypto::CryptoError::KeyCommitmentMismatch)
            ));
            assert!(out.is_empty());
        }
        // Each party's key opens only its own envelope.
        assert!(
            v.unwrap_share(EnvelopeRole::Service, &w.example_kem)
                .is_err()
        );
        assert!(
            v.unwrap_share(EnvelopeRole::RecipientOrg, &w.service_kem)
                .is_err()
        );
        let eve = World::kem_for(w.suite, &mut w.rng);
        assert!(v.unwrap_share(EnvelopeRole::RecipientOrg, &eve).is_err());
    }
}

#[test]
fn any_single_byte_modification_is_rejected() {
    for mut w in World::all() {
        let file = w.pack(&SECRET[..80]);
        // Every byte, except inside SVX-2's 34 KB signature, where every
        // 61st byte and the last few are enough (each part is hit).
        let max = w.suite == Suite::Svx2;
        let sig_start = if max {
            file.len() - svx_core::crypto::MAX_SIG_LEN
        } else {
            file.len()
        };
        for i in
            (0..file.len()).filter(|&i| !max || i < sig_start || i % 61 == 0 || i + 8 >= file.len())
        {
            let mut t = file.clone();
            t[i] ^= 0x01;
            assert!(
                verify(Cursor::new(&t), &w.trust).is_err(),
                "flip at byte {i} accepted"
            );
        }
    }
}

#[test]
fn truncation_and_extension_rejected() {
    for mut w in World::all() {
        let file = w.pack(SECRET);
        for cut in [1, 10, 50, file.len() / 2, file.len() - 1] {
            assert!(verify(Cursor::new(&file[..cut]), &w.trust).is_err());
        }
        let mut ext = file.clone();
        ext.extend_from_slice(b"extra");
        assert!(verify(Cursor::new(&ext), &w.trust).is_err());
    }
}

#[test]
fn chunk_reorder_rejected() {
    for mut w in World::all() {
        let data = vec![0x41u8; 64 * 3 + 10];
        let file = w.pack(&data);
        let c = format::parse(&file).unwrap();
        // Swap the first two (equal-length) chunk records and re-serialize.
        let mut wtr = format::Writer::new(Vec::new(), c.prelude.suite_id, &c.header).unwrap();
        let order = [1usize, 0, 2, 3];
        for &i in &order {
            let (info, ct) = &c.chunks[i];
            wtr.write_chunk(info.is_final, ct).unwrap();
        }
        let swapped = wtr.finish(&c.trailer).unwrap();
        assert!(verify(Cursor::new(&swapped), &w.trust).is_err());
    }
}

#[test]
fn untrusted_or_impersonating_sender_rejected() {
    for mut w in World::all() {
        let mallory = World::copy(&w.mallory_sign);
        // Mallory signs with her own key but claims to be Acme.
        let forged = w.pack_with(&mallory, "acme-security", SECRET, 64);
        assert!(matches!(
            verify(Cursor::new(&forged), &w.trust),
            Err(CoreError::UntrustedSender { .. })
        ));
        // Mallory's key trusted for a different org is still not Acme.
        let mut t = w.trust.clone();
        t.add(id("mallory-inc"), mallory.verifying_key());
        assert!(matches!(
            verify(Cursor::new(&forged), &t),
            Err(CoreError::UntrustedSender { .. })
        ));
    }
}

#[test]
fn unsupported_suite_rejected_no_downgrade() {
    for mut w in World::all() {
        let mut file = w.pack(SECRET);
        file[10..12].copy_from_slice(&2u16.to_le_bytes());
        assert!(matches!(
            verify(Cursor::new(&file), &w.trust),
            Err(CoreError::Crypto(
                svx_core::crypto::CryptoError::UnsupportedSuite(2)
            ))
        ));
    }
}

#[test]
fn artifact_swapped_between_verify_and_decrypt() {
    for mut w in World::all() {
        let a = w.pack(SECRET);
        let b = w.pack(SECRET);
        let v = verify(Cursor::new(&a), &w.trust).unwrap();
        let s = v
            .unwrap_share(EnvelopeRole::Service, &w.service_kem)
            .unwrap();
        let r = v
            .unwrap_share(EnvelopeRole::RecipientOrg, &w.example_kem)
            .unwrap();
        let mut out = Vec::new();
        assert!(matches!(
            v.decrypt(Cursor::new(&b), &s, &r, &mut out),
            Err(CoreError::ArtifactChanged)
        ));
    }
}

#[test]
fn expiry_is_reported() {
    for mut w in World::all() {
        let file = w.pack(SECRET);
        let v = verify(Cursor::new(&file), &w.trust).unwrap();
        assert!(!v.is_expired(1_790_000_001));
        assert!(v.is_expired(1_790_604_800));
    }
}

#[test]
fn length_mismatch_rejected_on_pack() {
    for mut w in World::all() {
        let req = PackRequest {
            suite: w.suite,
            sender_org: id("acme-security"),
            signing_key: &w.acme_sign,
            recipient_org: id("example-corp"),
            recipient_key: w.example_kem.public_key(),
            more_recipients: vec![],
            service_id: id("svx.example"),
            service_key: w.service_kem.public_key(),
            policy_ref: id("incident-response"),
            created_at: 1_790_000_000,
            expires_at: None,
            chunk_size: None,
            manifest: Manifest::single_file("x.bin", 5),
            view_only: false,
        };
        assert!(matches!(
            pack(&req, &b"123"[..], Vec::new(), &mut w.rng),
            Err(CoreError::LengthMismatch)
        ));
    }
}

/// 1 GiB streaming round trip with bounded memory. Run with `--ignored`.
#[test]
#[ignore]
fn large_streaming_round_trip() {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut w = World::new();
    const LEN: u64 = 1 << 30;
    let req = PackRequest {
        suite: w.suite,
        sender_org: id("acme-security"),
        signing_key: &w.acme_sign,
        recipient_org: id("example-corp"),
        recipient_key: w.example_kem.public_key(),
        more_recipients: vec![],
        service_id: id("svx.example"),
        service_key: w.service_kem.public_key(),
        policy_ref: id("incident-response"),
        created_at: 1_790_000_000,
        expires_at: None,
        chunk_size: Some(1 << 20),
        manifest: Manifest::single_file("disk.img", LEN),
        view_only: false,
    };
    let mut file = tempfile::tempfile().unwrap();
    pack(&req, std::io::repeat(0x5A).take(LEN), &mut file, &mut w.rng).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    let v = verify(std::io::BufReader::new(&file), &w.trust).unwrap();
    let s = v
        .unwrap_share(EnvelopeRole::Service, &w.service_kem)
        .unwrap();
    let r = v
        .unwrap_share(EnvelopeRole::RecipientOrg, &w.example_kem)
        .unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();

    struct Check(u64);
    impl Write for Check {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            assert!(b.iter().all(|&x| x == 0x5A));
            self.0 += b.len() as u64;
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Check(0);
    v.decrypt(std::io::BufReader::new(&file), &s, &r, &mut sink)
        .unwrap();
    assert_eq!(sink.0, LEN);
}

#[test]
fn verify_head_without_payload() {
    for mut w in World::all() {
        let file = w.pack(SECRET);
        let v = verify(Cursor::new(&file), &w.trust).unwrap();
        let trailer = v.trailer.encode().unwrap();
        let head = verify_head(&v.header_region, &trailer, &w.trust).unwrap();
        assert_eq!(head.header_hash(), v.header_hash());
        // Service can unwrap its share from the head alone.
        head.unwrap_share(EnvelopeRole::Service, &w.service_kem)
            .unwrap();

        let mut bad_region = v.header_region.clone();
        let n = bad_region.len();
        bad_region[n - 1] ^= 1;
        assert!(verify_head(&bad_region, &trailer, &w.trust).is_err());
        let mut bad_trailer = trailer.clone();
        bad_trailer[10] ^= 1;
        assert!(verify_head(&v.header_region, &bad_trailer, &w.trust).is_err());
        assert!(verify_head(&v.header_region[..n - 1], &trailer, &w.trust).is_err());
        assert!(verify_head(&v.header_region, &trailer, &TrustStore::new()).is_err());
    }
}

#[test]
fn hybrid_cannot_be_downgraded_or_mixed() {
    let mut w = World::hybrid();
    let file = w.pack(SECRET);
    // Claiming the classical suite in the prelude is refused.
    let mut down = file.clone();
    down[10..12].copy_from_slice(&1u16.to_le_bytes());
    assert!(verify(Cursor::new(&down), &w.trust).is_err());
    let v = verify(Cursor::new(&file), &w.trust).unwrap();
    assert_eq!(v.suite, Suite::Svx1H);
    assert_eq!(v.prelude.minor, 1);

    // Keys of the wrong kind for the requested suite are refused before writing.
    let classical = World::new();
    let req = PackRequest {
        suite: Suite::Svx1H,
        sender_org: id("acme-security"),
        signing_key: &classical.acme_sign,
        recipient_org: id("example-corp"),
        recipient_key: w.example_kem.public_key(),
        more_recipients: vec![],
        service_id: id("svx.example"),
        service_key: w.service_kem.public_key(),
        policy_ref: id("incident-response"),
        created_at: 1_790_000_000,
        expires_at: None,
        chunk_size: None,
        manifest: Manifest::single_file("x.bin", 1),
        view_only: false,
    };
    assert!(matches!(
        pack(&req, &b"1"[..], Vec::new(), &mut w.rng),
        Err(CoreError::InvalidRequest(_))
    ));
    let req = PackRequest {
        signing_key: &w.acme_sign,
        recipient_key: classical.example_kem.public_key(),
        ..req
    };
    assert!(matches!(
        pack(&req, &b"1"[..], Vec::new(), &mut w.rng),
        Err(CoreError::InvalidRequest(_))
    ));

    // A classical key can't open a hybrid envelope, even with a matching key ID claim.
    assert!(
        v.unwrap_share(EnvelopeRole::Service, &classical.service_kem)
            .is_err()
    );
}

#[test]
fn hybrid_overhead_is_small() {
    let mut c = World::new();
    let mut h = World::hybrid();
    let extra = h.pack(SECRET).len() - c.pack(SECRET).len();
    // Two X-Wing envelopes (+2 x 1090 B) and the ML-DSA-65 signature (+3309 B).
    assert!(extra < 6_000, "{extra}");
}

#[test]
fn hybrid_key_files_round_trip() {
    let mut rng = ChaCha20Rng::from_seed([5; 32]);
    let dir = tempfile::tempdir().unwrap();
    let owner = id("acme-security");
    for (name, sk, kem) in [
        (
            "classical",
            SigningKey::generate(&mut rng),
            KemSecretKey::generate(&mut rng),
        ),
        (
            "hybrid",
            SigningKey::generate_hybrid(&mut rng),
            KemSecretKey::generate_hybrid(&mut rng),
        ),
        (
            "max",
            SigningKey::generate_max(&mut rng),
            KemSecretKey::generate_max(&mut rng),
        ),
    ] {
        let prefix = dir.path().join(name);
        keyfile::write_signing_pair(&prefix, &owner, &sk).unwrap();
        keyfile::write_kem_pair(&prefix, &owner, &kem).unwrap();
        let (o, sk2) =
            keyfile::load_signing_key(&dir.path().join(format!("{name}.sign.key"))).unwrap();
        assert_eq!(o, owner);
        assert_eq!(sk2.verifying_key(), sk.verifying_key());
        let (_, vk) =
            keyfile::load_verifying_key(&dir.path().join(format!("{name}.sign.pub"))).unwrap();
        assert_eq!(vk, sk.verifying_key());
        let (_, k2) =
            keyfile::load_kem_secret(&dir.path().join(format!("{name}.kem.key"))).unwrap();
        assert_eq!(k2.public_key(), kem.public_key());
        let (_, pk) =
            keyfile::load_kem_public(&dir.path().join(format!("{name}.kem.pub"))).unwrap();
        assert_eq!(&pk, kem.public_key());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(dir.path().join(format!("{name}.sign.key"))).unwrap();
            assert_eq!(m.permissions().mode() & 0o777, 0o600);
        }
    }
    // A public key file is not accepted as a secret key.
    assert!(keyfile::load_signing_key(&dir.path().join("hybrid.sign.pub")).is_err());
}

#[test]
fn several_recipients_each_open_with_their_own_key() {
    let mut w = World::hybrid();
    let bob = KemSecretKey::generate_hybrid(&mut w.rng);
    let carol = KemSecretKey::generate_hybrid(&mut w.rng);
    let eve = KemSecretKey::generate_hybrid(&mut w.rng);
    let signer = World::copy(&w.acme_sign);
    let req = PackRequest {
        suite: Suite::Svx1H,
        sender_org: id("acme-security"),
        signing_key: &signer,
        recipient_org: id("example-corp"),
        recipient_key: w.example_kem.public_key(),
        more_recipients: vec![
            (id("u.0000000000000b0b"), bob.public_key()),
            (id("u.00000000000ca401"), carol.public_key()),
        ],
        service_id: id("svx.example"),
        service_key: w.service_kem.public_key(),
        policy_ref: id("personal"),
        created_at: 1_790_000_000,
        expires_at: None,
        chunk_size: Some(64),
        manifest: Manifest::single_file("secret.txt", SECRET.len() as u64),
        view_only: false,
    };
    let mut file = Vec::new();
    pack(&req, SECRET, &mut file, &mut w.rng).unwrap();
    let v = verify(Cursor::new(&file), &w.trust).unwrap();
    assert_eq!(v.prelude.minor, 2);
    assert_eq!(v.header.all_recipients().len(), 3);
    let s = v
        .unwrap_share(EnvelopeRole::Service, &w.service_kem)
        .unwrap();
    for k in [&w.example_kem, &bob, &carol] {
        let r = v.unwrap_share(EnvelopeRole::RecipientOrg, k).unwrap();
        let mut out = Vec::new();
        v.decrypt(Cursor::new(&file), &s, &r, &mut out).unwrap();
        assert_eq!(out, SECRET);
    }
    // Someone not named has no envelope.
    assert!(matches!(
        v.unwrap_share(EnvelopeRole::RecipientOrg, &eve),
        Err(CoreError::WrongKey(_))
    ));
    // A key ring picks the right envelope.
    let ring = [eve, carol];
    assert!(
        v.unwrap_share_from(EnvelopeRole::RecipientOrg, &ring)
            .is_ok()
    );
}

#[test]
fn max_suite_properties() {
    let mut w = World::max();
    let file = w.pack(SECRET);
    let v = verify(Cursor::new(&file), &w.trust).unwrap();
    assert_eq!(v.suite, Suite::Svx2);
    assert_eq!(v.prelude.minor, format::FORMAT_MINOR_MAX);
    assert_eq!(v.payload_commitment().len(), 64);
    assert_eq!(v.trailer.signature.len(), svx_core::crypto::MAX_SIG_LEN);
    assert_eq!(v.trailer.sig_alg, svx_core::crypto::SIG_ALG_MAX);
    // Claiming an older suite in the prelude is refused.
    for old in [1u16, 3] {
        let mut down = file.clone();
        down[10..12].copy_from_slice(&old.to_le_bytes());
        assert!(verify(Cursor::new(&down), &w.trust).is_err(), "{old}");
    }
    // The head verifies on its own (what the service checks on release).
    let c = format::parse(&file).unwrap();
    let head = verify_head(&c.header_region, &c.trailer.encode().unwrap(), &w.trust).unwrap();
    assert_eq!(head.header_hash(), v.header_hash());
    // A hybrid (SVX-1H) envelope key can't open an SVX-2 envelope.
    let hybrid = World::hybrid();
    assert!(
        v.unwrap_share(EnvelopeRole::Service, &hybrid.service_kem)
            .is_err()
    );
    // Mixing an SVX-1H signing key into an SVX-2 artifact is refused.
    let req = PackRequest {
        suite: Suite::Svx2,
        sender_org: id("acme-security"),
        signing_key: &hybrid.acme_sign,
        recipient_org: id("example-corp"),
        recipient_key: w.example_kem.public_key(),
        more_recipients: vec![],
        service_id: id("svx.example"),
        service_key: w.service_kem.public_key(),
        policy_ref: id("incident-response"),
        created_at: 1_790_000_000,
        expires_at: None,
        chunk_size: None,
        manifest: Manifest::single_file("x.bin", 1),
        view_only: false,
    };
    assert!(matches!(
        pack(&req, &b"1"[..], Vec::new(), &mut w.rng),
        Err(CoreError::InvalidRequest(_))
    ));
}

#[test]
fn max_overhead() {
    let mut h = World::hybrid();
    let mut m = World::max();
    let extra = m.pack(SECRET).len() - h.pack(SECRET).len();
    // Bigger envelopes (2 x 545 B), the 64-byte commitment and the third
    // signature: about 32 KB more than SVX-1H.
    assert!((30_000..34_000).contains(&extra), "{extra}");
}

#[test]
fn max_several_recipients() {
    let mut w = World::max();
    let bob = KemSecretKey::generate_max(&mut w.rng);
    let signer = World::copy(&w.acme_sign);
    let req = PackRequest {
        suite: Suite::Svx2,
        sender_org: id("acme-security"),
        signing_key: &signer,
        recipient_org: id("example-corp"),
        recipient_key: w.example_kem.public_key(),
        more_recipients: vec![(id("u.0000000000000b0b"), bob.public_key())],
        service_id: id("svx.example"),
        service_key: w.service_kem.public_key(),
        policy_ref: id("personal"),
        created_at: 1_790_000_000,
        expires_at: None,
        chunk_size: Some(64),
        manifest: Manifest::single_file("secret.txt", SECRET.len() as u64),
        view_only: false,
    };
    let mut file = Vec::new();
    pack(&req, SECRET, &mut file, &mut w.rng).unwrap();
    let v = verify(Cursor::new(&file), &w.trust).unwrap();
    // Format 1.3 covers several recipients too.
    assert_eq!(v.prelude.minor, format::FORMAT_MINOR_MAX);
    let s = v
        .unwrap_share(EnvelopeRole::Service, &w.service_kem)
        .unwrap();
    for k in [&w.example_kem, &bob] {
        let r = v.unwrap_share(EnvelopeRole::RecipientOrg, k).unwrap();
        let mut out = Vec::new();
        v.decrypt(Cursor::new(&file), &s, &r, &mut out).unwrap();
        assert_eq!(out, SECRET);
    }
}
