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
        envelopes: vec![
            KeyEnvelope {
                role: EnvelopeRole::Service,
                key_id: [5; 16],
                encapped_key: [6; 32],
                ciphertext: vec![7; 48],
            },
            KeyEnvelope {
                role: EnvelopeRole::RecipientOrg,
                key_id: [8; 16],
                encapped_key: [9; 32],
                ciphertext: vec![10; 48],
            },
        ],
        encrypted_manifest: vec![11; 40],
        unknown: vec![],
    }
}

/// Build a container with fake ciphertext of the given plaintext length.
fn build(header: &Header, pt_len: usize) -> Vec<u8> {
    let mut w = Writer::new(Vec::new(), 1, header).unwrap();
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
