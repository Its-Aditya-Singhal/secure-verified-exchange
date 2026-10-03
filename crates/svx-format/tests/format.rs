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
        payload_commitment: [0xCD; 32],
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
        payload_commitment: [0; 32],
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
