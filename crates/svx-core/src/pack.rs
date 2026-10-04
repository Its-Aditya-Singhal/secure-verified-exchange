use std::io::{Read, Write};

use svx_crypto::{
    ArtifactKeys, CryptoRng, EnvelopeContext, KemPublicKey, PayloadHasher, Share, SigningKey,
    StreamEncryptor, Suite, header_hash, seal_manifest, seal_share, sign_transcript,
};
use svx_format::limits::{DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE};
use svx_format::{EnvelopeLayout, EnvelopeRole, Header, Identifier, KeyEnvelope, Trailer, Writer};

use crate::error::{CoreError, Result};
use crate::manifest::Manifest;

/// Everything needed to create an artifact. Public keys for the recipient
/// organization and the managed service come from the organization registry
/// (Phase 2) or local key files (Phase 1).
pub struct PackRequest<'a> {
    /// [`Suite::CURRENT`] (SVX-2) for new artifacts; older suites only for
    /// test vectors. The key kinds below must match it.
    pub suite: Suite,
    pub sender_org: Identifier,
    pub signing_key: &'a SigningKey,
    pub recipient_org: Identifier,
    pub recipient_key: &'a KemPublicKey,
    /// Further recipients (SVX 1.2 and later; not suite SVX-1). Each gets its own
    /// envelope sealing the same recipient share; empty for one recipient.
    pub more_recipients: Vec<(Identifier, &'a KemPublicKey)>,
    pub service_id: Identifier,
    pub service_key: &'a KemPublicKey,
    pub policy_ref: Identifier,
    /// Unix seconds, UTC.
    pub created_at: i64,
    /// Unix seconds, UTC.
    pub expires_at: Option<i64>,
    /// Plaintext bytes per chunk; `None` uses the default (64 KiB).
    pub chunk_size: Option<u32>,
    pub manifest: Manifest,
    /// Mark the artifact view-only (SVX 1.4; suite SVX-2 only). Signed into
    /// the header.
    pub view_only: bool,
}

/// Public facts about a newly created artifact (safe to log).
#[derive(Clone, Debug)]
pub struct PackSummary {
    pub suite: Suite,
    pub artifact_id: [u8; 16],
    pub chunk_count: u64,
    pub plaintext_len: u64,
}

/// Encrypt `input` and write a signed `.svx` container to `output`.
///
/// Memory use is O(chunk_size). The plaintext length must equal the size
/// declared in the manifest; otherwise an error is returned and the partial
/// output must be discarded.
pub fn pack<R: Read, W: Write>(
    req: &PackRequest<'_>,
    mut input: R,
    output: W,
    rng: &mut impl CryptoRng,
) -> Result<PackSummary> {
    let chunk_size = req.chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(CoreError::InvalidRequest(format!(
            "chunk size must be {MIN_CHUNK_SIZE}..={MAX_CHUNK_SIZE}"
        )));
    }
    let suite = req.suite;
    if req.signing_key.kind() != suite.signing_kind()
        || req.recipient_key.kind() != suite.kem_kind()
        || req.service_key.kind() != suite.kem_kind()
        || req
            .more_recipients
            .iter()
            .any(|(_, k)| k.kind() != suite.kem_kind())
    {
        return Err(CoreError::InvalidRequest(format!(
            "keys do not match suite {:#06x} ({})",
            suite.id(),
            suite.description()
        )));
    }
    let manifest_bytes = zeroize::Zeroizing::new(req.manifest.to_bytes()?);

    let mut artifact_id = [0u8; 16];
    rng.fill_bytes(&mut artifact_id);
    let mut nonce_prefix = [0u8; 7];
    rng.fill_bytes(&mut nonce_prefix);
    let service_share = Share::generate(rng);
    let recipient_share = Share::generate(rng);
    let keys = ArtifactKeys::derive(suite, &artifact_id, &service_share, &recipient_share);

    let sender_key_id = req.signing_key.verifying_key().key_id();
    let ctx = EnvelopeContext {
        artifact_id: &artifact_id,
        sender_org: &req.sender_org,
        sender_key_id: &sender_key_id,
        recipient_org: &req.recipient_org,
        service_id: &req.service_id,
    };
    let mut envelopes = Vec::with_capacity(2 + req.more_recipients.len());
    let recipient_keys = std::iter::once(req.recipient_key)
        .chain(req.more_recipients.iter().map(|(_, k)| *k))
        .map(|k| (EnvelopeRole::RecipientOrg, k, &recipient_share));
    for (role, pk, share) in
        std::iter::once((EnvelopeRole::Service, req.service_key, &service_share))
            .chain(recipient_keys)
    {
        let (encapped_key, ciphertext) = seal_share(suite, role, pk, &ctx, share, rng)?;
        envelopes.push(KeyEnvelope {
            role,
            key_id: pk.key_id(),
            encapped_key,
            ciphertext,
        });
    }
    drop(service_share);
    drop(recipient_share);

    let header = Header {
        artifact_id,
        created_at: req.created_at,
        expires_at: req.expires_at,
        sender_org: req.sender_org.clone(),
        sender_key_id,
        recipient_org: req.recipient_org.clone(),
        recipients: if req.more_recipients.is_empty() {
            Vec::new()
        } else {
            std::iter::once(req.recipient_org.clone())
                .chain(req.more_recipients.iter().map(|(id, _)| id.clone()))
                .collect()
        },
        service_id: req.service_id.clone(),
        policy_ref: req.policy_ref.clone(),
        chunk_size,
        nonce_prefix,
        key_commitment: keys.key_commitment(),
        envelope_layout: match suite {
            Suite::Svx1 => EnvelopeLayout::V1,
            Suite::Svx1H | Suite::Svx2 => EnvelopeLayout::V2,
        },
        envelopes,
        encrypted_manifest: seal_manifest(&keys, &artifact_id, &manifest_bytes)?,
        view_only: req.view_only,
        unknown: Vec::new(),
    };

    let mut writer = Writer::new(output, suite.id(), &header)?;
    let hh = header_hash(suite, writer.header_region());
    let mut enc = StreamEncryptor::new(&keys, nonce_prefix, &hh);
    let mut hasher = PayloadHasher::new(suite, &hh);

    // One chunk of look-ahead tells us whether the current chunk is final.
    let cs = chunk_size as usize;
    let mut cur = zeroize::Zeroizing::new(vec![0u8; cs]);
    let mut next = zeroize::Zeroizing::new(vec![0u8; cs]);
    let mut cur_len = read_full(&mut input, &mut cur)?;
    let mut total = 0u64;
    loop {
        let next_len = if cur_len == cs {
            read_full(&mut input, &mut next)?
        } else {
            0
        };
        let is_final = next_len == 0;
        let ct = enc.encrypt_chunk(&cur[..cur_len], is_final)?;
        let info = writer.write_chunk(is_final, &ct)?;
        hasher.update(&info, &ct);
        total += cur_len as u64;
        if is_final {
            break;
        }
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
    }

    if total != req.manifest.total_size() {
        return Err(CoreError::LengthMismatch);
    }

    let (chunk_count, payload_commitment) = hasher.finalize();
    let (sig_alg, signature) = sign_transcript(
        suite,
        req.signing_key,
        &hh,
        chunk_count,
        &payload_commitment,
        rng,
    )?;
    writer.finish(&Trailer {
        chunk_count,
        payload_commitment,
        sig_alg,
        signature,
    })?;

    Ok(PackSummary {
        suite,
        artifact_id,
        chunk_count,
        plaintext_len: total,
    })
}

/// Read until `buf` is full or EOF. Returns bytes read.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(n)
}
