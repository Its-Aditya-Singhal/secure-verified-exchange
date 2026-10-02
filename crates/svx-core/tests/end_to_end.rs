//! End-to-end behaviour of pack → verify → unwrap shares → decrypt, and the
//! failure modes from the threat model.

use std::io::Cursor;

use chacha20::ChaCha20Rng;
use rand_core::SeedableRng;
use svx_core::crypto::{KemSecretKey, SigningKey};
use svx_core::format::{EnvelopeRole, Identifier};
use svx_core::*;

struct World {
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
    fn new() -> Self {
        let mut rng = ChaCha20Rng::from_seed([42; 32]);
        let acme_sign = SigningKey::generate(&mut rng);
        let mallory_sign = SigningKey::generate(&mut rng);
        let example_kem = KemSecretKey::generate(&mut rng);
        let service_kem = KemSecretKey::generate(&mut rng);
        let mut trust = TrustStore::new();
        trust.add(id("acme-security"), acme_sign.verifying_key());
        World {
            acme_sign,
            mallory_sign,
            example_kem,
            service_kem,
            trust,
            rng,
        }
    }

    fn pack_with(&mut self, signer: &SigningKey, sender: &str, data: &[u8], chunk: u32) -> Vec<u8> {
        let mut manifest = Manifest::single_file("secret.txt", data.len() as u64);
        manifest.classification = Some("TLP:RED".into());
        let req = PackRequest {
            sender_org: id(sender),
            signing_key: signer,
            recipient_org: id("example-corp"),
            recipient_key: self.example_kem.public_key(),
            service_id: id("svx.example"),
            service_key: self.service_kem.public_key(),
            policy_ref: id("incident-response"),
            created_at: 1_790_000_000,
            expires_at: Some(1_790_604_800),
            chunk_size: Some(chunk),
            manifest,
        };
        let mut out = Vec::new();
        let summary = pack(&req, data, &mut out, &mut self.rng).unwrap();
        assert_eq!(summary.plaintext_len, data.len() as u64);
        out
    }

    fn pack(&mut self, data: &[u8]) -> Vec<u8> {
        let k = SigningKey::from_bytes(&self.acme_sign.to_bytes());
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
    let mut w = World::new();
    for len in [0usize, 1, 63, 64, 65, 128, 1000] {
        let data: Vec<u8> = SECRET.iter().copied().cycle().take(len).collect();
        let file = w.pack(&data);
        let (m, out) = w.open(&file).unwrap();
        assert_eq!(out, data, "len {len}");
        assert_eq!(m.files[0].name, "secret.txt");
        assert_eq!(m.classification.as_deref(), Some("TLP:RED"));
    }
}

#[test]
fn intercepted_file_reveals_no_plaintext_or_private_metadata() {
    let mut w = World::new();
    let file = w.pack(SECRET);
    let hay = String::from_utf8_lossy(&file);
    for needle in ["FICTIONAL", "203.0.113.7", "secret.txt", "TLP:RED"] {
        assert!(!hay.contains(needle), "{needle} visible in ciphertext");
    }
    // Only opaque routing identifiers are public.
    let (_, h) = inspect(Cursor::new(&file)).unwrap();
    assert_eq!(h.recipient_org.as_str(), "example-corp");
}

#[test]
fn file_alone_is_insufficient_one_share_is_insufficient() {
    let mut w = World::new();
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
    let eve = KemSecretKey::generate(&mut w.rng);
    assert!(v.unwrap_share(EnvelopeRole::RecipientOrg, &eve).is_err());
}

#[test]
fn any_single_byte_modification_is_rejected() {
    let mut w = World::new();
    let file = w.pack(&SECRET[..80]);
    for i in 0..file.len() {
        let mut t = file.clone();
        t[i] ^= 0x01;
        assert!(
            verify(Cursor::new(&t), &w.trust).is_err(),
            "flip at byte {i} accepted"
        );
    }
}

#[test]
fn truncation_and_extension_rejected() {
    let mut w = World::new();
    let file = w.pack(SECRET);
    for cut in [1, 10, 50, file.len() / 2, file.len() - 1] {
        assert!(verify(Cursor::new(&file[..cut]), &w.trust).is_err());
    }
    let mut ext = file.clone();
    ext.extend_from_slice(b"extra");
    assert!(verify(Cursor::new(&ext), &w.trust).is_err());
}

#[test]
fn chunk_reorder_rejected() {
    let mut w = World::new();
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

#[test]
fn untrusted_or_impersonating_sender_rejected() {
    let mut w = World::new();
    let mallory = SigningKey::from_bytes(&w.mallory_sign.to_bytes());
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

#[test]
fn unsupported_suite_rejected_no_downgrade() {
    let mut w = World::new();
    let mut file = w.pack(SECRET);
    file[10..12].copy_from_slice(&2u16.to_le_bytes());
    assert!(matches!(
        verify(Cursor::new(&file), &w.trust),
        Err(CoreError::Crypto(
            svx_core::crypto::CryptoError::UnsupportedSuite(2)
        ))
    ));
}

#[test]
fn artifact_swapped_between_verify_and_decrypt() {
    let mut w = World::new();
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

#[test]
fn expiry_is_reported() {
    let mut w = World::new();
    let file = w.pack(SECRET);
    let v = verify(Cursor::new(&file), &w.trust).unwrap();
    assert!(!v.is_expired(1_790_000_001));
    assert!(v.is_expired(1_790_604_800));
}

#[test]
fn length_mismatch_rejected_on_pack() {
    let mut w = World::new();
    let req = PackRequest {
        sender_org: id("acme-security"),
        signing_key: &w.acme_sign,
        recipient_org: id("example-corp"),
        recipient_key: w.example_kem.public_key(),
        service_id: id("svx.example"),
        service_key: w.service_kem.public_key(),
        policy_ref: id("incident-response"),
        created_at: 1_790_000_000,
        expires_at: None,
        chunk_size: None,
        manifest: Manifest::single_file("x.bin", 5),
    };
    assert!(matches!(
        pack(&req, &b"123"[..], Vec::new(), &mut w.rng),
        Err(CoreError::LengthMismatch)
    ));
}

/// 1 GiB streaming round trip with bounded memory. Run with `--ignored`.
#[test]
#[ignore]
fn large_streaming_round_trip() {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut w = World::new();
    const LEN: u64 = 1 << 30;
    let req = PackRequest {
        sender_org: id("acme-security"),
        signing_key: &w.acme_sign,
        recipient_org: id("example-corp"),
        recipient_key: w.example_kem.public_key(),
        service_id: id("svx.example"),
        service_key: w.service_kem.public_key(),
        policy_ref: id("incident-response"),
        created_at: 1_790_000_000,
        expires_at: None,
        chunk_size: Some(1 << 20),
        manifest: Manifest::single_file("disk.img", LEN),
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
