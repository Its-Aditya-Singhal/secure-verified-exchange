use std::io::{Read, Write};

use svx_crypto::{
    ArtifactKeys, EnvelopeContext, HeaderHash, KemSecretKey, PayloadHasher, Share, StreamDecryptor,
    VerifyingKey, check_suite, header_hash, open_manifest, open_share, verify_transcript,
};
use svx_format::{EnvelopeRole, Header, KeyEnvelope, Prelude, Reader};

use crate::error::{CoreError, Result};
use crate::manifest::Manifest;
use crate::trust::TrustStore;

/// Parse only the prelude and header. Nothing returned is authenticated;
/// use [`verify`] before relying on any of it.
pub fn inspect<R: Read>(input: R) -> Result<(Prelude, Header)> {
    let reader = Reader::new(input)?;
    Ok((*reader.prelude(), reader.header().clone()))
}

/// An artifact whose structure, sender and signature have been verified.
#[derive(Clone, Debug)]
pub struct VerifiedArtifact {
    pub prelude: Prelude,
    pub header: Header,
    pub chunk_count: u64,
    pub sender_key: VerifyingKey,
    header_hash: HeaderHash,
    payload_commitment: [u8; 32],
}

/// Verify an artifact end to end without any decryption keys:
///
/// 1. strict structural parse (bounded),
/// 2. supported suite (no downgrade),
/// 3. required key envelopes present,
/// 4. sender `(org, key_id)` present in the trust store,
/// 5. payload commitment recomputed over every chunk and matched to the trailer,
/// 6. Ed25519 signature over the transcript.
pub fn verify<R: Read>(input: R, trust: &TrustStore) -> Result<VerifiedArtifact> {
    let mut reader = Reader::new(input)?;
    check_suite(reader.prelude().suite_id)?;
    let header = reader.header().clone();
    required_envelope(&header, EnvelopeRole::Service)?;
    required_envelope(&header, EnvelopeRole::RecipientOrg)?;
    // Resolve the sender before reading the payload so untrusted input fails fast.
    let sender_key = *trust.resolve(&header.sender_org, &header.sender_key_id)?;

    let hh = header_hash(reader.header_region());
    let mut hasher = PayloadHasher::new(&hh);
    let mut buf = Vec::new();
    while let Some(info) = reader.next_chunk(&mut buf)? {
        hasher.update(&info, &buf);
    }
    let prelude = *reader.prelude();
    let (trailer, _) = reader.finish()?;
    let (chunk_count, commitment) = hasher.finalize();
    if chunk_count != trailer.chunk_count || !ct_eq32(&commitment, &trailer.payload_commitment) {
        return Err(CoreError::CommitmentMismatch);
    }
    verify_transcript(
        &sender_key,
        &hh,
        chunk_count,
        &commitment,
        trailer.sig_alg,
        &trailer.signature,
    )?;

    Ok(VerifiedArtifact {
        prelude,
        header,
        chunk_count,
        sender_key,
        header_hash: hh,
        payload_commitment: commitment,
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

impl VerifiedArtifact {
    pub fn header_hash(&self) -> &HeaderHash {
        &self.header_hash
    }

    pub fn payload_commitment(&self) -> &[u8; 32] {
        &self.payload_commitment
    }

    /// Whether the signed expiry has passed at `now` (Unix seconds). The
    /// managed service is authoritative for expiry; clients check this too
    /// and fail closed.
    pub fn is_expired(&self, now: i64) -> bool {
        self.header.expires_at.is_some_and(|exp| now >= exp)
    }

    pub fn envelope_context(&self) -> EnvelopeContext<'_> {
        EnvelopeContext {
            artifact_id: &self.header.artifact_id,
            sender_org: &self.header.sender_org,
            sender_key_id: &self.header.sender_key_id,
            recipient_org: &self.header.recipient_org,
            service_id: &self.header.service_id,
        }
    }

    /// Unwrap one key share with the holder's KEM secret key. In Managed
    /// Mode this runs inside the managed service (role `Service`) or the
    /// recipient organization's key agent (role `RecipientOrg`), after
    /// authorization — never on an unauthenticated client.
    pub fn unwrap_share(&self, role: EnvelopeRole, secret: &KemSecretKey) -> Result<Share> {
        let env = required_envelope(&self.header, role)?;
        if env.key_id != secret.public_key().key_id() {
            return Err(CoreError::WrongKey(role_name(role)));
        }
        Ok(open_share(
            role,
            secret,
            &self.envelope_context(),
            &env.encapped_key,
            &env.ciphertext,
        )?)
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
        let hh = header_hash(reader.header_region());
        if hh != self.header_hash {
            return Err(CoreError::ArtifactChanged);
        }
        let h = &self.header;
        let keys = ArtifactKeys::derive(&h.artifact_id, service_share, recipient_share);
        keys.check_commitment(&h.key_commitment)?;
        let manifest_bytes =
            zeroize::Zeroizing::new(open_manifest(&keys, &h.artifact_id, &h.encrypted_manifest)?);
        let manifest = Manifest::from_bytes(&manifest_bytes)?;

        let mut dec = StreamDecryptor::new(&keys, h.nonce_prefix, &hh);
        let mut hasher = PayloadHasher::new(&hh);
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
            || !ct_eq32(&commitment, &self.payload_commitment)
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

/// Equality for 32-byte hashes without data-dependent early exit. The values
/// compared here are public, but there is no reason to leak timing either.
fn ct_eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
