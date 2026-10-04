use std::io::{Read, Write};

use svx_crypto::{
    ArtifactKeys, EnvelopeContext, HeaderHash, KemSecretKey, PayloadHasher, Share, StreamDecryptor,
    Suite, VerifyingKey, check_suite, header_hash, open_manifest, open_share, verify_transcript,
};
use svx_format::{EnvelopeLayout, EnvelopeRole, Header, KeyEnvelope, Prelude, Reader, Trailer};

use crate::error::{CoreError, Result};
use crate::manifest::Manifest;
use crate::trust::TrustStore;

/// Parse only the prelude and header. Nothing returned is authenticated;
/// use [`verify`] before relying on any of it.
pub fn inspect<R: Read>(input: R) -> Result<(Prelude, Header)> {
    let reader = Reader::new(input)?;
    Ok((*reader.prelude(), reader.header().clone()))
}

/// A verified header and trailer: structure, suite, sender trust and the
/// signature over `header_hash ‖ chunk_count ‖ payload_commitment` all check
/// out. The payload itself has *not* been read; this is what the managed
/// service verifies in a release request (the client has the payload and
/// verifies it fully with [`verify`]).
#[derive(Clone, Debug)]
pub struct VerifiedHead {
    pub prelude: Prelude,
    /// The verified cipher suite (from the prelude, bound by the header hash).
    pub suite: Suite,
    pub header: Header,
    pub header_region: Vec<u8>,
    pub trailer: Trailer,
    pub sender_key: VerifyingKey,
    header_hash: HeaderHash,
}

/// An artifact whose structure, sender, payload commitment and signature
/// have all been verified. Dereferences to its [`VerifiedHead`].
#[derive(Clone, Debug)]
pub struct VerifiedArtifact {
    head: VerifiedHead,
    pub chunk_count: u64,
    payload_commitment: Vec<u8>,
}

impl std::ops::Deref for VerifiedArtifact {
    type Target = VerifiedHead;
    fn deref(&self) -> &VerifiedHead {
        &self.head
    }
}

fn check_head(
    prelude: &Prelude,
    header: &Header,
    trust: &TrustStore,
) -> Result<(Suite, VerifyingKey)> {
    let suite = check_suite(prelude.suite_id)?;
    // The format layer already ties the suite to the envelope layout; check
    // again here so the suite used below can never disagree with the header.
    if suite_for_header(header) != suite {
        return Err(CoreError::InvalidRequest(
            "suite and envelope layout disagree".into(),
        ));
    }
    required_envelope(header, EnvelopeRole::Service)?;
    required_envelope(header, EnvelopeRole::RecipientOrg)?;
    let key = trust.resolve(&header.sender_org, &header.sender_key_id)?;
    Ok((suite, key.clone()))
}

/// The suite implied by a header's envelope layout. For an authentic header
/// the format layer guarantees this equals the prelude's suite (layout V1 ⇔
/// SVX-1; layout V2 with X-Wing encapsulations ⇔ SVX-1H, with
/// MLKEM1024-P384 encapsulations ⇔ SVX-2).
pub fn suite_for_header(h: &Header) -> Suite {
    match h.envelope_layout {
        EnvelopeLayout::V1 => Suite::Svx1,
        EnvelopeLayout::V2
            if h.envelopes
                .first()
                .is_some_and(|e| e.encapped_key.len() == svx_format::MAX_ENCAPPED_KEY_LEN_SVX2) =>
        {
            Suite::Svx2
        }
        EnvelopeLayout::V2 => Suite::Svx1H,
    }
}

/// Verify an artifact end to end without any decryption keys:
///
/// 1. strict structural parse (bounded),
/// 2. supported suite (no downgrade),
/// 3. required key envelopes present,
/// 4. sender `(org, key_id)` present in the trust store,
/// 5. payload commitment recomputed over every chunk and matched to the trailer,
/// 6. signature over the transcript: Ed25519 (SVX-1); Ed25519 **and**
///    ML-DSA-65 (SVX-1H); Ed25519 **and** ML-DSA-87 **and** SLH-DSA (SVX-2).
pub fn verify<R: Read>(input: R, trust: &TrustStore) -> Result<VerifiedArtifact> {
    let mut reader = Reader::new(input)?;
    let prelude = *reader.prelude();
    let header = reader.header().clone();
    // Resolve the sender before reading the payload so untrusted input fails fast.
    let (suite, sender_key) = check_head(&prelude, &header, trust)?;

    let header_region = reader.header_region().to_vec();
    let hh = header_hash(suite, &header_region);
    let mut hasher = PayloadHasher::new(suite, &hh);
    let mut buf = Vec::new();
    while let Some(info) = reader.next_chunk(&mut buf)? {
        hasher.update(&info, &buf);
    }
    let (trailer, _) = reader.finish()?;
    let (chunk_count, commitment) = hasher.finalize();
    if chunk_count != trailer.chunk_count || !ct_eq(&commitment, &trailer.payload_commitment) {
        return Err(CoreError::CommitmentMismatch);
    }
    verify_transcript(
        suite,
        &sender_key,
        &hh,
        chunk_count,
        &commitment,
        trailer.sig_alg,
        &trailer.signature,
    )?;

    Ok(VerifiedArtifact {
        head: VerifiedHead {
            prelude,
            suite,
            header,
            header_region,
            trailer,
            sender_key,
            header_hash: hh,
        },
        chunk_count,
        payload_commitment: commitment,
    })
}

/// Verify a header region and trailer without the payload. The signature
/// covers the payload commitment, so a valid result proves the sender signed
/// *some* payload with this header; only [`verify`] proves the payload you
/// hold is that one.
pub fn verify_head(
    header_region: &[u8],
    trailer: &[u8],
    trust: &TrustStore,
) -> Result<VerifiedHead> {
    let (prelude, header) = svx_format::parse_header_region(header_region)?;
    let (suite, sender_key) = check_head(&prelude, &header, trust)?;
    let trailer = Trailer::decode(prelude.suite_id, trailer)?;
    let hh = header_hash(suite, header_region);
    verify_transcript(
        suite,
        &sender_key,
        &hh,
        trailer.chunk_count,
        &trailer.payload_commitment,
        trailer.sig_alg,
        &trailer.signature,
    )?;
    Ok(VerifiedHead {
        prelude,
        suite,
        header,
        header_region: header_region.to_vec(),
        trailer,
        sender_key,
        header_hash: hh,
    })
}

fn required_envelope(h: &Header, role: EnvelopeRole) -> Result<&KeyEnvelope> {
    h.envelope(role)
        .ok_or(CoreError::MissingEnvelope(role_name(role)))
}

fn role_name(role: EnvelopeRole) -> &'static str {
    match role {
        EnvelopeRole::Service => "service",
        EnvelopeRole::RecipientOrg => "recipient organization",
    }
}

fn envelope_context(h: &Header) -> EnvelopeContext<'_> {
    EnvelopeContext {
        artifact_id: &h.artifact_id,
        sender_org: &h.sender_org,
        sender_key_id: &h.sender_key_id,
        recipient_org: &h.recipient_org,
        service_id: &h.service_id,
    }
}

/// Unwrap one key-share envelope from a header that the caller has
/// authenticated by other means (the recipient key agent authenticates the
/// header through the service's signed grant, which commits to its hash).
/// For a recipient, the envelope is the one sealed to `secret` (an artifact
/// may have several recipients).
pub fn unwrap_envelope(
    header: &Header,
    role: EnvelopeRole,
    secret: &KemSecretKey,
) -> Result<Share> {
    let key_id = secret.public_key().key_id();
    let env = match role {
        EnvelopeRole::RecipientOrg => {
            required_envelope(header, role)?;
            header
                .recipient_envelope(&key_id)
                .ok_or(CoreError::WrongKey(role_name(role)))?
        }
        EnvelopeRole::Service => required_envelope(header, role)?,
    };
    if env.key_id != key_id {
        return Err(CoreError::WrongKey(role_name(role)));
    }
    Ok(open_share(
        suite_for_header(header),
        role,
        secret,
        &envelope_context(header),
        &env.encapped_key,
        &env.ciphertext,
    )?)
}

impl VerifiedHead {
    pub fn header_hash(&self) -> &HeaderHash {
        &self.header_hash
    }

    /// Whether the signed expiry has passed at `now` (Unix seconds). The
    /// managed service is authoritative for expiry; clients check this too
    /// and fail closed.
    pub fn is_expired(&self, now: i64) -> bool {
        self.header.expires_at.is_some_and(|exp| now >= exp)
    }

    pub fn envelope_context(&self) -> EnvelopeContext<'_> {
        envelope_context(&self.header)
    }

    /// Unwrap one key share with the holder's KEM secret key. In Managed
    /// Mode this runs inside the managed service (role `Service`) or the
    /// recipient organization's key agent (role `RecipientOrg`), after
    /// authorization — never on an unauthenticated client.
    pub fn unwrap_share(&self, role: EnvelopeRole, secret: &KemSecretKey) -> Result<Share> {
        unwrap_envelope(&self.header, role, secret)
    }

    /// [`unwrap_share`](Self::unwrap_share) with a key ring (for example a
    /// classical key for older files and a hybrid key for new ones): the
    /// key is chosen by the envelope's key ID.
    pub fn unwrap_share_from(&self, role: EnvelopeRole, ring: &[KemSecretKey]) -> Result<Share> {
        required_envelope(&self.header, role)?;
        let secret = ring
            .iter()
            .find(|k| {
                let id = k.public_key().key_id();
                self.header
                    .envelopes
                    .iter()
                    .any(|e| e.role == role && e.key_id == id)
            })
            .ok_or(CoreError::WrongKey(role_name(role)))?;
        unwrap_envelope(&self.header, role, secret)
    }
}

impl VerifiedArtifact {
    pub fn head(&self) -> &VerifiedHead {
        &self.head
    }

    /// 32 bytes (SHA-256), or 64 (SHA-512) in suite SVX-2.
    pub fn payload_commitment(&self) -> &[u8] {
        &self.payload_commitment
    }

    /// Decrypt the payload into `out`, re-reading the container from `input`
    /// (which must be the same bytes that were verified).
    ///
    /// Every chunk is authenticated before it is written, and the header
    /// hash and payload commitment are re-checked against the verified
    /// values. On any error the caller MUST discard everything written to
    /// `out` (write to a private temporary file and only move it into place
    /// on success).
    pub fn decrypt<R: Read, W: Write>(
        &self,
        input: R,
        service_share: &Share,
        recipient_share: &Share,
        mut out: W,
    ) -> Result<Manifest> {
        let mut reader = Reader::new(input)?;
        let hh = header_hash(self.head.suite, reader.header_region());
        if hh != self.head.header_hash {
            return Err(CoreError::ArtifactChanged);
        }
        let h = &self.header;
        let keys = ArtifactKeys::derive(
            self.head.suite,
            &h.artifact_id,
            service_share,
            recipient_share,
        );
        keys.check_commitment(&h.key_commitment)?;
        let manifest_bytes =
            zeroize::Zeroizing::new(open_manifest(&keys, &h.artifact_id, &h.encrypted_manifest)?);
        let manifest = Manifest::from_bytes(&manifest_bytes)?;

        let mut dec = StreamDecryptor::new(&keys, h.nonce_prefix, &hh);
        let mut hasher = PayloadHasher::new(self.head.suite, &hh);
        let mut buf = Vec::new();
        let mut total = 0u64;
        while let Some(info) = reader.next_chunk(&mut buf)? {
            hasher.update(&info, &buf);
            let pt = zeroize::Zeroizing::new(dec.decrypt_chunk(&buf, info.is_final)?);
            total += pt.len() as u64;
            if total > manifest.total_size() {
                return Err(CoreError::LengthMismatch);
            }
            out.write_all(&pt)?;
        }
        dec.finish()?;
        let (trailer, _) = reader.finish()?;
        let (count, commitment) = hasher.finalize();
        if count != self.chunk_count
            || trailer.chunk_count != count
            || !ct_eq(&commitment, &self.payload_commitment)
        {
            return Err(CoreError::ArtifactChanged);
        }
        if total != manifest.total_size() {
            return Err(CoreError::LengthMismatch);
        }
        out.flush()?;
        Ok(manifest)
    }
}

/// Equality for hashes without data-dependent early exit. The values
/// compared here are public, but there is no reason to leak timing either.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
