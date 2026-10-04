use proptest::prelude::*;
use svx_format::*;

fn sample_header() -> Header {
    Header {
        artifact_id: [1; 16],
        created_at: 1_790_000_000,
        expires_at: Some(1_790_600_000),
        sender_org: Identifier::new("acme-security").unwrap(),
        sender_key_id: [2; 16],
        recipient_org: Identifier::new("example-corp").unwrap(),
        recipients: vec![],
        service_id: Identifier::new("svx.example").unwrap(),
        policy_ref: Identifier::new("incident-response").unwrap(),
        chunk_size: 64,
        nonce_prefix: [3; 7],
        key_commitment: [4; 32],
        envelope_layout: EnvelopeLayout::V1,
        envelopes: vec![
            KeyEnvelope {
                role: EnvelopeRole::Service,
                key_id: [5; 16],
                encapped_key: vec![6; 32],
                ciphertext: vec![7; 48],
            },
            KeyEnvelope {
                role: EnvelopeRole::RecipientOrg,
                key_id: [8; 16],
                encapped_key: vec![9; 32],
                ciphertext: vec![10; 48],
            },
        ],
        encrypted_manifest: vec![11; 40],
        view_only: false,
        unknown: vec![],
    }
}

/// The same header in the SVX 1.1 hybrid layout (X-Wing-sized encapsulations).
fn hybrid_header() -> Header {
    let mut h = sample_header();
    h.envelope_layout = EnvelopeLayout::V2;
    for e in &mut h.envelopes {
        e.encapped_key = vec![e.encapped_key[0]; HYBRID_ENCAPPED_KEY_LEN];
    }
    h
}

/// Build a container with fake ciphertext of the given plaintext length.
fn build(header: &Header, pt_len: usize) -> Vec<u8> {
    build_suite(SUITE_ID_SVX1, header, pt_len)
}

fn build_suite(suite: u16, header: &Header, pt_len: usize) -> Vec<u8> {
    let mut w = Writer::new(Vec::new(), suite, header).unwrap();
    let cs = header.chunk_size as usize;
    let mut remaining = pt_len;
    let mut count = 0u64;
    loop {
        let n = remaining.min(cs);
        remaining -= n;
        let is_final = remaining == 0;
        w.write_chunk(is_final, &vec![0xAB; n + 16]).unwrap();
        count += 1;
        if is_final {
            break;
        }
    }
    let trailer = Trailer {
        chunk_count: count,
        payload_commitment: vec![0xCD; payload_commitment_len(suite)],
        sig_alg: 1,
        signature: vec![0xEF; 64],
    };
    w.finish(&trailer).unwrap()
}

#[test]
fn hybrid_layout_round_trip() {
    let h = hybrid_header();
    let bytes = build_suite(SUITE_ID_SVX1H, &h, 300);
    let c = parse(&bytes).unwrap();
    assert_eq!(c.prelude.suite_id, SUITE_ID_SVX1H);
    assert_eq!(c.prelude.minor, FORMAT_MINOR_HYBRID);
    assert_eq!(c.header, h);
    assert_eq!(c.header.envelopes[0].encapped_key.len(), 1120);
    // Classical files keep minor version 0 (v1 test vectors stay byte-identical).
    assert_eq!(
        parse(&build(&sample_header(), 10)).unwrap().prelude.minor,
        FORMAT_MINOR
    );
    // A large hybrid signature fits; one over the limit does not.
    let t = Trailer {
        chunk_count: 1,
        payload_commitment: vec![0; 32],
        sig_alg: 2,
        signature: vec![1; 64 + 3309],
    };
    assert!(t.encode().is_ok());
    let t = Trailer {
        signature: vec![1; limits::MAX_SIGNATURE_LEN + 1],
        ..t
    };
    assert!(t.encode().is_err());
}

/// The same header in the SVX 1.3 layout (MLKEM1024-P384-sized encapsulations).
fn max_header() -> Header {
    let mut h = hybrid_header();
    for e in &mut h.envelopes {
        e.encapped_key = vec![e.encapped_key[0]; MAX_ENCAPPED_KEY_LEN_SVX2];
    }
    h
}

#[test]
fn max_layout_round_trip() {
    let h = max_header();
    let bytes = build_suite(SUITE_ID_SVX2, &h, 300);
    let c = parse(&bytes).unwrap();
    assert_eq!(c.prelude.suite_id, SUITE_ID_SVX2);
    assert_eq!(c.prelude.minor, FORMAT_MINOR_MAX);
    assert_eq!(c.header, h);
    assert_eq!(c.trailer.payload_commitment, vec![0xCD; 64]);
    // A Max signature (Ed25519 + ML-DSA-87 + SLH-DSA-SHA2-256s) fits.
    let t = Trailer {
        chunk_count: 1,
        payload_commitment: vec![0; 64],
        sig_alg: 3,
        signature: vec![1; 64 + 4627 + 29792],
    };
    assert_eq!(
        Trailer::decode(SUITE_ID_SVX2, &t.encode().unwrap()).unwrap(),
        t
    );
    // The commitment length is fixed by the suite.
    assert!(Trailer::decode(SUITE_ID_SVX1H, &t.encode().unwrap()).is_err());
    let mut w = Writer::new(Vec::new(), SUITE_ID_SVX2, &h).unwrap();
    w.write_chunk(true, &[0; 16]).unwrap();
    let short = Trailer {
        chunk_count: 1,
        payload_commitment: vec![0; 32],
        sig_alg: 3,
        signature: vec![1; 64],
    };
    assert!(w.finish(&short).is_err());
    // SVX-2 needs layout V2 with 1665-byte encapsulations.
    assert!(Writer::new(Vec::new(), SUITE_ID_SVX2, &hybrid_header()).is_err());
    assert!(Writer::new(Vec::new(), SUITE_ID_SVX1H, &h).is_err());
    // A suite swapped in the prelude is refused by the reader.
    let mut bytes = build_suite(SUITE_ID_SVX2, &h, 10);
    bytes[10..12].copy_from_slice(&SUITE_ID_SVX1H.to_le_bytes());
    assert!(parse(&bytes).is_err());
}

#[test]
fn view_only_is_a_critical_svx2_field() {
    // Critical: a reader that doesn't know it refuses the file.
    assert_ne!(tags::VIEW_ONLY & tags::CRITICAL, 0);
    let mut h = max_header();
    h.view_only = true;
    let c = parse(&build_suite(SUITE_ID_SVX2, &h, 50)).unwrap();
    assert_eq!(c.prelude.minor, FORMAT_MINOR_VIEW_ONLY);
    assert!(c.header.view_only);
    assert_eq!(c.header, h);
    // Only suite SVX-2 can carry it.
    let mut old = hybrid_header();
    old.view_only = true;
    assert!(Writer::new(Vec::new(), SUITE_ID_SVX1H, &old).is_err());
    let mut v1 = sample_header();
    v1.view_only = true;
    assert!(Writer::new(Vec::new(), SUITE_ID_SVX1, &v1).is_err());
    // The value must be empty.
    // (It has the highest tag, so it is the last field.)
    let enc = h.encode().unwrap();
    let field = [0x10, 0x80, 0, 0, 0, 0];
    assert!(enc.ends_with(&field));
    Header::decode(&enc).unwrap();
    let mut bad = enc[..enc.len() - 6].to_vec();
    bad.extend([0x10, 0x80, 1, 0, 0, 0, 0xAA]);
    assert!(Header::decode(&bad).is_err());
    // Without the flag, nothing changes.
    let plain = parse(&build_suite(SUITE_ID_SVX2, &max_header(), 50)).unwrap();
    assert!(!plain.header.view_only);
    assert_eq!(plain.prelude.minor, FORMAT_MINOR_MAX);
}

#[test]
fn suite_and_envelope_layout_must_agree() {
    // Writers refuse mismatches.
    assert!(Writer::new(Vec::new(), SUITE_ID_SVX1H, &sample_header()).is_err());
    assert!(Writer::new(Vec::new(), SUITE_ID_SVX1, &hybrid_header()).is_err());
    let mut short = hybrid_header();
    short.envelopes[1].encapped_key.truncate(32);
    assert!(Writer::new(Vec::new(), SUITE_ID_SVX1H, &short).is_err());

    // Readers refuse a prelude whose suite was swapped (a downgrade attempt).
    let mut bytes = build_suite(SUITE_ID_SVX1H, &hybrid_header(), 10);
    bytes[10..12].copy_from_slice(&SUITE_ID_SVX1.to_le_bytes());
    assert!(parse(&bytes).is_err());
    let mut bytes = build(&sample_header(), 10);
    bytes[10..12].copy_from_slice(&SUITE_ID_SVX1H.to_le_bytes());
    assert!(parse(&bytes).is_err());
    // parse_header_region applies the same rule.
    let c = parse(&build_suite(SUITE_ID_SVX1H, &hybrid_header(), 10)).unwrap();
    let mut region = c.header_region.clone();
    parse_header_region(&region).unwrap();
    region[10..12].copy_from_slice(&SUITE_ID_SVX1.to_le_bytes());
    assert!(parse_header_region(&region).is_err());
}

#[test]
fn old_readers_cannot_misread_v2_envelopes() {
    // Tag 0x800E is critical: a 1.0 reader (which doesn't know it) must reject.
    assert_ne!(tags::KEY_ENVELOPES_V2 & tags::CRITICAL, 0);
    // V2 envelope with a zero or oversized encapsulation length is refused.
    let mut h = hybrid_header();
    h.envelopes[0].encapped_key.clear();
    assert!(h.encode().is_err());
    let mut h = hybrid_header();
    h.envelopes[0].encapped_key = vec![0; limits::MAX_ENCAPPED_KEY_LEN + 1];
    assert!(h.encode().is_err());
}

#[test]
fn round_trip() {
    let h = sample_header();
    let bytes = build(&h, 200);
    let c = parse(&bytes).unwrap();
    assert_eq!(c.header, h);
    assert_eq!(c.chunks.len(), 4);
    assert!(c.chunks.last().unwrap().0.is_final);
    assert_eq!(c.trailer.chunk_count, 4);
    assert_eq!(&bytes[..8], &MAGIC);
}

#[test]
fn exact_multiple_of_chunk_size_has_no_empty_tail() {
    let h = sample_header();
    let c = parse(&build(&h, 128)).unwrap();
    assert_eq!(c.chunks.len(), 2);
    assert_eq!(c.chunks[1].0.ct_len, 64 + 16);
}

#[test]
fn empty_payload() {
    let h = sample_header();
    let c = parse(&build(&h, 0)).unwrap();
    assert_eq!(c.chunks.len(), 1);
    assert_eq!(c.chunks[0].0.ct_len, 16);
}

#[test]
fn rejects_bad_magic_and_version() {
    let mut b = build(&sample_header(), 10);
    b[1] = b'X';
    assert!(matches!(parse(&b), Err(FormatError::BadMagic)));
    let mut b = build(&sample_header(), 10);
    b[8] = 2;
    assert!(matches!(
        parse(&b),
        Err(FormatError::UnsupportedVersion { major: 2, .. })
    ));
}

#[test]
fn rejects_truncation_everywhere() {
    let b = build(&sample_header(), 150);
    for cut in 0..b.len() {
        assert!(parse(&b[..cut]).is_err(), "truncated at {cut} parsed");
    }
}

#[test]
fn rejects_trailing_data() {
    let mut b = build(&sample_header(), 10);
    b.push(0);
    assert!(matches!(parse(&b), Err(FormatError::TrailingData)));
}

#[test]
fn rejects_unknown_critical_accepts_unknown_noncritical() {
    let mut h = sample_header();
    h.unknown.push(UnknownField {
        tag: 0x0100,
        value: b"future".to_vec(),
    });
    let c = parse(&build(&h, 10)).unwrap();
    assert_eq!(c.header.unknown.len(), 1);

    // Hand-craft a critical unknown field by patching a known tag.
    let bytes = build(&sample_header(), 10);
    let mut patched = bytes.clone();
    // First field tag is ARTIFACT_ID (0x8001) at offset 16.
    patched[16..18].copy_from_slice(&0x80FFu16.to_le_bytes());
    assert!(parse(&patched).is_err());
}

#[test]
fn rejects_oversized_header_len_without_allocating() {
    let mut b = build(&sample_header(), 10);
    b[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(parse(&b), Err(FormatError::LimitExceeded { .. })));
}

#[test]
fn rejects_duplicate_roles() {
    let mut h = sample_header();
    h.envelopes[1].role = EnvelopeRole::Service;
    assert!(h.encode().is_err());
}

#[test]
fn rejects_bad_expiry() {
    let mut h = sample_header();
    h.expires_at = Some(h.created_at);
    assert!(h.encode().is_err());
}

#[test]
fn writer_rejects_misuse() {
    let h = sample_header();
    let mut w = Writer::new(Vec::new(), 1, &h).unwrap();
    // short non-final chunk
    assert!(w.write_chunk(false, &[0; 20]).is_err());
    w.write_chunk(true, &[0; 20]).unwrap();
    assert!(w.write_chunk(true, &[0; 20]).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// The parser must never panic on arbitrary input.
    #[test]
    fn parse_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = parse(&data);
    }

    /// Nor on a valid container with arbitrary single-byte mutations.
    #[test]
    fn mutated_valid_never_panics(pos in any::<prop::sample::Index>(), val in any::<u8>(), len in 0usize..300) {
        let mut b = build(&sample_header(), len);
        let i = pos.index(b.len());
        b[i] = val;
        let _ = parse(&b);
    }

    #[test]
    fn round_trip_any_length(len in 0usize..2000) {
        let h = sample_header();
        let b = build(&h, len);
        let c = parse(&b).unwrap();
        let expected = if len == 0 { 1 } else { len.div_ceil(64) };
        prop_assert_eq!(c.chunks.len(), expected);
    }
}

/// A hybrid header with three recipients (SVX 1.2).
fn multi_header() -> Header {
    let mut h = hybrid_header();
    h.recipients = ["example-corp", "u.0123456789abcdef", "u.fedcba9876543210"]
        .iter()
        .map(|s| Identifier::new(s).unwrap())
        .collect();
    for (i, k) in [[12u8; 16], [13; 16]].into_iter().enumerate() {
        h.envelopes.push(KeyEnvelope {
            role: EnvelopeRole::RecipientOrg,
            key_id: k,
            encapped_key: vec![14 + i as u8; HYBRID_ENCAPPED_KEY_LEN],
            ciphertext: vec![16; 48],
        });
    }
    h
}

#[test]
fn multi_recipient_round_trip() {
    let h = multi_header();
    let bytes = build_suite(SUITE_ID_SVX1H, &h, 300);
    let c = parse(&bytes).unwrap();
    assert_eq!(c.prelude.minor, FORMAT_MINOR_RECIPIENTS);
    assert_eq!(c.header, h);
    assert_eq!(c.header.all_recipients().len(), 3);
    assert_eq!(
        c.header.recipient_envelope(&[13; 16]).unwrap().encapped_key[0],
        15
    );
    assert!(c.header.recipient_envelope(&[99; 16]).is_none());
    // Single-recipient headers keep the 1.1 layout and minor version.
    let single = hybrid_header();
    assert_eq!(
        single.all_recipients(),
        std::slice::from_ref(&single.recipient_org)
    );
    assert_eq!(
        parse(&build_suite(SUITE_ID_SVX1H, &single, 10))
            .unwrap()
            .prelude
            .minor,
        FORMAT_MINOR_HYBRID
    );
}

#[test]
fn multi_recipient_rules() {
    let refuse = |h: Header| {
        assert!(
            Writer::new(Vec::new(), SUITE_ID_SVX1H, &h).is_err(),
            "{:?}",
            h.recipients
        )
    };
    // The first recipient must be recipient_org.
    let mut h = multi_header();
    h.recipients.swap(0, 1);
    refuse(h);
    // Duplicate recipients.
    let mut h = multi_header();
    h.recipients[2] = h.recipients[1].clone();
    refuse(h);
    // A recipient without an envelope.
    let mut h = multi_header();
    h.envelopes.pop();
    refuse(h);
    // Two recipient envelopes for the same key.
    let mut h = multi_header();
    let k = h.envelopes[1].key_id;
    h.envelopes[2].key_id = k;
    refuse(h);
    // A second service envelope.
    let mut h = multi_header();
    h.envelopes[3].role = EnvelopeRole::Service;
    refuse(h);
    // A one-entry list (single recipients use the 1.1 layout).
    let mut h = hybrid_header();
    h.recipients = vec![h.recipient_org.clone()];
    refuse(h);
    // Classical suite: no recipients list.
    let mut h = sample_header();
    h.recipients = multi_header().recipients;
    h.envelopes.push(KeyEnvelope {
        role: EnvelopeRole::RecipientOrg,
        key_id: [12; 16],
        encapped_key: vec![1; 32],
        ciphertext: vec![1; 48],
    });
    assert!(Writer::new(Vec::new(), SUITE_ID_SVX1, &h).is_err());
    // Without the list, two recipient envelopes are still refused.
    let mut h = multi_header();
    h.recipients.clear();
    refuse(h);
}

#[test]
fn old_readers_refuse_multi_recipient_files() {
    // The recipients field is critical: a reader that doesn't know tag
    // 0x800F must refuse the file rather than pick one recipient.
    let bytes = build_suite(SUITE_ID_SVX1H, &multi_header(), 10);
    let needle = tags::RECIPIENTS.to_le_bytes();
    assert!(bytes.windows(2).any(|w| w == needle));
    assert_ne!(tags::RECIPIENTS & tags::CRITICAL, 0);
}
