//! The prelude and the TLV-encoded header section.

use crate::error::{FormatError, Result};
use crate::ident::Identifier;
use crate::limits::*;
use crate::wire::Cursor;
use crate::*;

/// Header field tags. The high bit (`0x8000`) marks a field as *critical*:
/// a reader that does not understand a critical field MUST reject the
/// container. Non-critical unknown fields are skipped (but remain covered by
/// the header hash and therefore by the signature).
pub mod tags {
    pub const CRITICAL: u16 = 0x8000;

    pub const ARTIFACT_ID: u16 = 0x8001;
    pub const CREATED_AT: u16 = 0x8002;
    pub const EXPIRES_AT: u16 = 0x8003;
    pub const SENDER_ORG: u16 = 0x8004;
    pub const SENDER_KEY_ID: u16 = 0x8005;
    pub const RECIPIENT_ORG: u16 = 0x8006;
    pub const SERVICE_ID: u16 = 0x8007;
    pub const POLICY_REF: u16 = 0x8008;
    pub const CHUNK_SIZE: u16 = 0x8009;
    pub const NONCE_PREFIX: u16 = 0x800A;
    pub const KEY_COMMITMENT: u16 = 0x800B;
    pub const KEY_ENVELOPES: u16 = 0x800C;
    pub const ENCRYPTED_MANIFEST: u16 = 0x800D;
    /// Key envelopes with variable-length encapsulated keys (SVX 1.1,
    /// required by suite `0x0003`).
    pub const KEY_ENVELOPES_V2: u16 = 0x800E;
    /// Every recipient of a multi-recipient artifact (SVX 1.2, suite
    /// `0x0003` only): `count (u8) ‖ { len (u8) ‖ identifier }*`.
    pub const RECIPIENTS: u16 = 0x800F;
    /// The sender made this a view-only file (SVX 1.4, suite `0x0004` only):
    /// an empty value. Critical, so a reader that doesn't know it refuses
    /// the file instead of treating it as an ordinary one.
    pub const VIEW_ONLY: u16 = 0x8010;
}

/// How the key envelopes are laid out on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EnvelopeLayout {
    /// Tag `0x800C`: `role ‖ key_id ‖ enc (32) ‖ ct_len ‖ ct` (suite `0x0001`).
    V1,
    /// Tag `0x800E`: `role ‖ key_id ‖ enc_len (u16) ‖ enc ‖ ct_len ‖ ct` (suite `0x0003`).
    V2,
}

/// The fixed 16-byte prelude that precedes the header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prelude {
    pub major: u8,
    pub minor: u8,
    pub suite_id: u16,
    pub header_len: u32,
}

impl Prelude {
    pub const LEN: usize = 16;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..8].copy_from_slice(&MAGIC);
        out[8] = self.major;
        out[9] = self.minor;
        out[10..12].copy_from_slice(&self.suite_id.to_le_bytes());
        out[12..16].copy_from_slice(&self.header_len.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8; Self::LEN]) -> Result<Self> {
        if bytes[..8] != MAGIC {
            return Err(FormatError::BadMagic);
        }
        let p = Prelude {
            major: bytes[8],
            minor: bytes[9],
            suite_id: u16::from_le_bytes([bytes[10], bytes[11]]),
            header_len: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        };
        // Minor versions within major 1 are forward compatible: anything a
        // newer minor adds that we must understand is a critical field.
        if p.major != FORMAT_MAJOR {
            return Err(FormatError::UnsupportedVersion {
                major: p.major,
                minor: p.minor,
            });
        }
        if p.header_len > MAX_HEADER_LEN {
            return Err(FormatError::LimitExceeded {
                what: "header length",
                limit: MAX_HEADER_LEN as u64,
            });
        }
        Ok(p)
    }
}

/// Which party a key envelope is sealed to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EnvelopeRole {
    /// The managed key-release service named by `service_id`.
    Service,
    /// The recipient organization's key-agreement key.
    RecipientOrg,
}

impl EnvelopeRole {
    pub fn to_byte(self) -> u8 {
        match self {
            EnvelopeRole::Service => 0x01,
            EnvelopeRole::RecipientOrg => 0x02,
        }
    }

    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x01 => Ok(EnvelopeRole::Service),
            0x02 => Ok(EnvelopeRole::RecipientOrg),
            _ => Err(FormatError::Malformed("key envelope role")),
        }
    }
}

/// One HPKE-sealed key share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEnvelope {
    pub role: EnvelopeRole,
    pub key_id: [u8; KEY_ID_LEN],
    /// 32 bytes in layout V1; 1..=[`MAX_ENCAPPED_KEY_LEN`] in layout V2.
    pub encapped_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// A non-critical header field this implementation does not understand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownField {
    pub tag: u16,
    pub value: Vec<u8>,
}

/// The decoded header. Nothing here is trustworthy until the signature over
/// the header hash has been verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub artifact_id: [u8; ARTIFACT_ID_LEN],
    /// Unix seconds, UTC.
    pub created_at: i64,
    /// Unix seconds, UTC. Advisory on the client; enforced by the managed service.
    pub expires_at: Option<i64>,
    pub sender_org: Identifier,
    pub sender_key_id: [u8; KEY_ID_LEN],
    pub recipient_org: Identifier,
    /// Every recipient, in envelope order, for a multi-recipient artifact
    /// (SVX 1.2): `recipients[0] == recipient_org` and there is one
    /// recipient envelope per entry. Empty for single-recipient artifacts.
    pub recipients: Vec<Identifier>,
    pub service_id: Identifier,
    /// Opaque reference to a policy held by the managed service. Never the policy text.
    pub policy_ref: Identifier,
    pub chunk_size: u32,
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
    pub key_commitment: [u8; KEY_COMMITMENT_LEN],
    pub envelope_layout: EnvelopeLayout,
    pub envelopes: Vec<KeyEnvelope>,
    pub encrypted_manifest: Vec<u8>,
    /// The sender limited the file to viewing in the app (SVX 1.4). Signed
    /// with the rest of the header, so it can't be removed or added later.
    pub view_only: bool,
    /// Non-critical fields from a newer minor version, preserved verbatim.
    pub unknown: Vec<UnknownField>,
}

impl Header {
    /// Look up the envelope for `role`. The parser guarantees exactly one
    /// service envelope, and one recipient envelope unless the artifact has
    /// several recipients (then this is the first; see
    /// [`recipient_envelope`](Self::recipient_envelope)).
    pub fn envelope(&self, role: EnvelopeRole) -> Option<&KeyEnvelope> {
        self.envelopes.iter().find(|e| e.role == role)
    }

    /// The recipient envelope sealed to the key `key_id`.
    pub fn recipient_envelope(&self, key_id: &[u8; KEY_ID_LEN]) -> Option<&KeyEnvelope> {
        self.envelopes
            .iter()
            .find(|e| e.role == EnvelopeRole::RecipientOrg && &e.key_id == key_id)
    }

    /// Every recipient: the `recipients` list, or just `recipient_org`.
    pub fn all_recipients(&self) -> &[Identifier] {
        if self.recipients.is_empty() {
            std::slice::from_ref(&self.recipient_org)
        } else {
            &self.recipients
        }
    }

    /// Encode to canonical bytes (fields in ascending tag order).
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.check_semantics()?;
        let mut fields: Vec<(u16, Vec<u8>)> = vec![
            (tags::ARTIFACT_ID, self.artifact_id.to_vec()),
            (tags::CREATED_AT, self.created_at.to_le_bytes().to_vec()),
            (
                tags::SENDER_ORG,
                self.sender_org.as_str().as_bytes().to_vec(),
            ),
            (tags::SENDER_KEY_ID, self.sender_key_id.to_vec()),
            (
                tags::RECIPIENT_ORG,
                self.recipient_org.as_str().as_bytes().to_vec(),
            ),
            (
                tags::SERVICE_ID,
                self.service_id.as_str().as_bytes().to_vec(),
            ),
            (
                tags::POLICY_REF,
                self.policy_ref.as_str().as_bytes().to_vec(),
            ),
            (tags::CHUNK_SIZE, self.chunk_size.to_le_bytes().to_vec()),
            (tags::NONCE_PREFIX, self.nonce_prefix.to_vec()),
            (tags::KEY_COMMITMENT, self.key_commitment.to_vec()),
            match self.envelope_layout {
                EnvelopeLayout::V1 => (tags::KEY_ENVELOPES, encode_envelopes(&self.envelopes)),
                EnvelopeLayout::V2 => {
                    (tags::KEY_ENVELOPES_V2, encode_envelopes_v2(&self.envelopes))
                }
            },
            (tags::ENCRYPTED_MANIFEST, self.encrypted_manifest.clone()),
        ];
        if let Some(exp) = self.expires_at {
            fields.push((tags::EXPIRES_AT, exp.to_le_bytes().to_vec()));
        }
        if !self.recipients.is_empty() {
            fields.push((tags::RECIPIENTS, encode_recipients(&self.recipients)));
        }
        if self.view_only {
            fields.push((tags::VIEW_ONLY, Vec::new()));
        }
        for u in &self.unknown {
            if u.tag & tags::CRITICAL != 0 {
                return Err(FormatError::UnknownCriticalField(u.tag));
            }
            fields.push((u.tag, u.value.clone()));
        }
        fields.sort_by_key(|(t, _)| *t);
        if fields.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(FormatError::FieldOrder(0));
        }
        if fields.len() > MAX_FIELDS {
            return Err(FormatError::LimitExceeded {
                what: "field count",
                limit: MAX_FIELDS as u64,
            });
        }

        let mut out = Vec::new();
        for (tag, value) in fields {
            if value.len() > MAX_FIELD_LEN as usize {
                return Err(FormatError::LimitExceeded {
                    what: "field length",
                    limit: MAX_FIELD_LEN as u64,
                });
            }
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&(value.len() as u32).to_le_bytes());
            out.extend_from_slice(&value);
        }
        if out.len() > MAX_HEADER_LEN as usize {
            return Err(FormatError::LimitExceeded {
                what: "header length",
                limit: MAX_HEADER_LEN as u64,
            });
        }
        Ok(out)
    }

    /// Strictly decode a header section.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cur = Cursor::new(bytes, "header");
        let mut last_tag: Option<u16> = None;
        let mut count = 0usize;

        let mut artifact_id = None;
        let mut created_at = None;
        let mut expires_at = None;
        let mut sender_org = None;
        let mut sender_key_id = None;
        let mut recipient_org = None;
        let mut recipients = Vec::new();
        let mut service_id = None;
        let mut policy_ref = None;
        let mut chunk_size = None;
        let mut nonce_prefix = None;
        let mut key_commitment = None;
        let mut envelopes = None;
        let mut encrypted_manifest = None;
        let mut view_only = false;
        let mut unknown = Vec::new();

        while !cur.is_empty() {
            count += 1;
            if count > MAX_FIELDS {
                return Err(FormatError::LimitExceeded {
                    what: "field count",
                    limit: MAX_FIELDS as u64,
                });
            }
            let tag = cur.u16()?;
            let len = cur.u32()?;
            if len > MAX_FIELD_LEN {
                return Err(FormatError::LimitExceeded {
                    what: "field length",
                    limit: MAX_FIELD_LEN as u64,
                });
            }
            if last_tag.is_some_and(|t| tag <= t) {
                return Err(FormatError::FieldOrder(tag));
            }
            last_tag = Some(tag);
            let value = cur.take(len as usize)?;

            match tag {
                tags::ARTIFACT_ID => {
                    artifact_id = Some(fixed::<ARTIFACT_ID_LEN>(value, "artifact_id")?)
                }
                tags::CREATED_AT => created_at = Some(i64_field(value, "created_at")?),
                tags::EXPIRES_AT => expires_at = Some(i64_field(value, "expires_at")?),
                tags::SENDER_ORG => sender_org = Some(Identifier::from_wire(value, "sender_org")?),
                tags::SENDER_KEY_ID => {
                    sender_key_id = Some(fixed::<KEY_ID_LEN>(value, "sender_key_id")?)
                }
                tags::RECIPIENT_ORG => {
                    recipient_org = Some(Identifier::from_wire(value, "recipient_org")?)
                }
                tags::SERVICE_ID => service_id = Some(Identifier::from_wire(value, "service_id")?),
                tags::POLICY_REF => policy_ref = Some(Identifier::from_wire(value, "policy_ref")?),
                tags::CHUNK_SIZE => {
                    let mut c = Cursor::new(value, "chunk_size");
                    let v = c.u32()?;
                    c.finish()?;
                    chunk_size = Some(v);
                }
                tags::NONCE_PREFIX => {
                    nonce_prefix = Some(fixed::<NONCE_PREFIX_LEN>(value, "nonce_prefix")?)
                }
                tags::KEY_COMMITMENT => {
                    key_commitment = Some(fixed::<KEY_COMMITMENT_LEN>(value, "key_commitment")?)
                }
                tags::KEY_ENVELOPES => {
                    envelopes = Some((EnvelopeLayout::V1, decode_envelopes(value)?))
                }
                // Tags are strictly ascending, so at most one of the two
                // envelope fields can be present... unless both are; refuse that.
                tags::KEY_ENVELOPES_V2 => {
                    if envelopes.is_some() {
                        return Err(FormatError::Malformed("both key envelope layouts"));
                    }
                    envelopes = Some((EnvelopeLayout::V2, decode_envelopes_v2(value)?))
                }
                tags::ENCRYPTED_MANIFEST => {
                    if value.len() > MAX_MANIFEST_CT_LEN {
                        return Err(FormatError::LimitExceeded {
                            what: "encrypted manifest",
                            limit: MAX_MANIFEST_CT_LEN as u64,
                        });
                    }
                    encrypted_manifest = Some(value.to_vec());
                }
                tags::RECIPIENTS => recipients = decode_recipients(value)?,
                tags::VIEW_ONLY => {
                    if !value.is_empty() {
                        return Err(FormatError::Malformed("view_only (must be empty)"));
                    }
                    view_only = true;
                }
                t if t & tags::CRITICAL != 0 => return Err(FormatError::UnknownCriticalField(t)),
                t => unknown.push(UnknownField {
                    tag: t,
                    value: value.to_vec(),
                }),
            }
        }

        let h = Header {
            artifact_id: artifact_id.ok_or(FormatError::MissingField("artifact_id"))?,
            created_at: created_at.ok_or(FormatError::MissingField("created_at"))?,
            expires_at,
            sender_org: sender_org.ok_or(FormatError::MissingField("sender_org"))?,
            sender_key_id: sender_key_id.ok_or(FormatError::MissingField("sender_key_id"))?,
            recipient_org: recipient_org.ok_or(FormatError::MissingField("recipient_org"))?,
            recipients,
            service_id: service_id.ok_or(FormatError::MissingField("service_id"))?,
            policy_ref: policy_ref.ok_or(FormatError::MissingField("policy_ref"))?,
            chunk_size: chunk_size.ok_or(FormatError::MissingField("chunk_size"))?,
            nonce_prefix: nonce_prefix.ok_or(FormatError::MissingField("nonce_prefix"))?,
            key_commitment: key_commitment.ok_or(FormatError::MissingField("key_commitment"))?,
            envelope_layout: envelopes
                .as_ref()
                .map(|(l, _)| *l)
                .ok_or(FormatError::MissingField("key_envelopes"))?,
            envelopes: envelopes
                .ok_or(FormatError::MissingField("key_envelopes"))?
                .1,
            encrypted_manifest: encrypted_manifest
                .ok_or(FormatError::MissingField("encrypted_manifest"))?,
            view_only,
            unknown,
        };
        h.check_semantics()?;
        Ok(h)
    }

    /// Structural rules that apply to both encoding and decoding.
    fn check_semantics(&self) -> Result<()> {
        if self.created_at < 0 {
            return Err(FormatError::Malformed("created_at"));
        }
        if let Some(exp) = self.expires_at
            && exp <= self.created_at
        {
            return Err(FormatError::Malformed("expires_at (not after created_at)"));
        }
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&self.chunk_size) {
            return Err(FormatError::LimitExceeded {
                what: "chunk size",
                limit: MAX_CHUNK_SIZE as u64,
            });
        }
        if self.envelopes.is_empty() {
            return Err(FormatError::MissingField("key_envelopes"));
        }
        if self.envelopes.len() > MAX_ENVELOPES {
            return Err(FormatError::LimitExceeded {
                what: "envelope count",
                limit: MAX_ENVELOPES as u64,
            });
        }
        self.check_recipients()?;
        for (i, a) in self.envelopes.iter().enumerate() {
            // One envelope per role, except one recipient envelope per
            // recipient key in a multi-recipient artifact.
            let dup = self.envelopes[..i].iter().any(|b| {
                b.role == a.role && (a.role == EnvelopeRole::Service || self.recipients.is_empty())
            });
            if dup {
                return Err(FormatError::Malformed("key envelopes (duplicate role)"));
            }
            if a.ciphertext.is_empty() || a.ciphertext.len() > MAX_ENVELOPE_CT_LEN {
                return Err(FormatError::Malformed("key envelope ciphertext length"));
            }
            let enc_ok = match self.envelope_layout {
                EnvelopeLayout::V1 => a.encapped_key.len() == ENCAPPED_KEY_LEN,
                EnvelopeLayout::V2 => {
                    !a.encapped_key.is_empty() && a.encapped_key.len() <= MAX_ENCAPPED_KEY_LEN
                }
            };
            if !enc_ok {
                return Err(FormatError::Malformed(
                    "key envelope encapsulated key length",
                ));
            }
        }
        if self.encrypted_manifest.len() < 16 || self.encrypted_manifest.len() > MAX_MANIFEST_CT_LEN
        {
            return Err(FormatError::Malformed("encrypted manifest length"));
        }
        Ok(())
    }
}

impl Header {
    /// Rules for the `recipients` list (SVX 1.2).
    fn check_recipients(&self) -> Result<()> {
        if self.recipients.is_empty() {
            return Ok(());
        }
        if self.envelope_layout != EnvelopeLayout::V2 {
            return Err(FormatError::Malformed(
                "recipients list requires key envelope layout V2",
            ));
        }
        // A single recipient is written without the list (canonical form).
        if self.recipients.len() < 2 {
            return Err(FormatError::Malformed("recipients (fewer than two)"));
        }
        if self.recipients.len() > MAX_RECIPIENTS {
            return Err(FormatError::LimitExceeded {
                what: "recipient count",
                limit: MAX_RECIPIENTS as u64,
            });
        }
        if self.recipients[0] != self.recipient_org {
            return Err(FormatError::Malformed(
                "recipients (first entry must be recipient_org)",
            ));
        }
        for (i, r) in self.recipients.iter().enumerate() {
            if self.recipients[..i].contains(r) {
                return Err(FormatError::Malformed("recipients (duplicate)"));
            }
        }
        let keys: Vec<_> = self
            .envelopes
            .iter()
            .filter(|e| e.role == EnvelopeRole::RecipientOrg)
            .map(|e| e.key_id)
            .collect();
        if keys.len() != self.recipients.len() {
            return Err(FormatError::Malformed(
                "recipients (one recipient envelope per recipient)",
            ));
        }
        for (i, k) in keys.iter().enumerate() {
            if keys[..i].contains(k) {
                return Err(FormatError::Malformed(
                    "recipient envelopes (duplicate key)",
                ));
            }
        }
        Ok(())
    }
}

fn encode_recipients(ids: &[Identifier]) -> Vec<u8> {
    let mut out = vec![ids.len() as u8];
    for id in ids {
        // Identifiers are at most 128 bytes, so the length fits in a u8.
        out.push(id.as_str().len() as u8);
        out.extend_from_slice(id.as_str().as_bytes());
    }
    out
}

fn decode_recipients(value: &[u8]) -> Result<Vec<Identifier>> {
    let mut c = Cursor::new(value, "recipients");
    let n = c.u8()? as usize;
    if !(2..=MAX_RECIPIENTS).contains(&n) {
        return Err(FormatError::LimitExceeded {
            what: "recipient count",
            limit: MAX_RECIPIENTS as u64,
        });
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let len = c.u8()? as usize;
        out.push(Identifier::from_wire(c.take(len)?, "recipients")?);
    }
    c.finish()?;
    Ok(out)
}

fn fixed<const N: usize>(value: &[u8], what: &'static str) -> Result<[u8; N]> {
    let mut c = Cursor::new(value, what);
    let v = c.array::<N>()?;
    c.finish()?;
    Ok(v)
}

fn i64_field(value: &[u8], what: &'static str) -> Result<i64> {
    let mut c = Cursor::new(value, what);
    let v = c.i64()?;
    c.finish()?;
    Ok(v)
}

fn encode_envelopes(envs: &[KeyEnvelope]) -> Vec<u8> {
    let mut out = vec![envs.len() as u8];
    for e in envs {
        out.push(e.role.to_byte());
        out.extend_from_slice(&e.key_id);
        out.extend_from_slice(&e.encapped_key);
        out.extend_from_slice(&(e.ciphertext.len() as u16).to_le_bytes());
        out.extend_from_slice(&e.ciphertext);
    }
    out
}

fn encode_envelopes_v2(envs: &[KeyEnvelope]) -> Vec<u8> {
    let mut out = vec![envs.len() as u8];
    for e in envs {
        out.push(e.role.to_byte());
        out.extend_from_slice(&e.key_id);
        out.extend_from_slice(&(e.encapped_key.len() as u16).to_le_bytes());
        out.extend_from_slice(&e.encapped_key);
        out.extend_from_slice(&(e.ciphertext.len() as u16).to_le_bytes());
        out.extend_from_slice(&e.ciphertext);
    }
    out
}

fn decode_envelopes_v2(value: &[u8]) -> Result<Vec<KeyEnvelope>> {
    let mut c = Cursor::new(value, "key envelopes");
    let n = c.u8()? as usize;
    if n == 0 || n > MAX_ENVELOPES {
        return Err(FormatError::LimitExceeded {
            what: "envelope count",
            limit: MAX_ENVELOPES as u64,
        });
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let role = EnvelopeRole::from_byte(c.u8()?)?;
        let key_id = c.array::<KEY_ID_LEN>()?;
        let enc_len = c.u16()? as usize;
        if enc_len == 0 || enc_len > MAX_ENCAPPED_KEY_LEN {
            return Err(FormatError::Malformed(
                "key envelope encapsulated key length",
            ));
        }
        let encapped_key = c.take(enc_len)?.to_vec();
        let ct_len = c.u16()? as usize;
        if ct_len == 0 || ct_len > MAX_ENVELOPE_CT_LEN {
            return Err(FormatError::Malformed("key envelope ciphertext length"));
        }
        let ciphertext = c.take(ct_len)?.to_vec();
        out.push(KeyEnvelope {
            role,
            key_id,
            encapped_key,
            ciphertext,
        });
    }
    c.finish()?;
    Ok(out)
}

fn decode_envelopes(value: &[u8]) -> Result<Vec<KeyEnvelope>> {
    let mut c = Cursor::new(value, "key envelopes");
    let n = c.u8()? as usize;
    if n == 0 || n > MAX_ENVELOPES {
        return Err(FormatError::LimitExceeded {
            what: "envelope count",
            limit: MAX_ENVELOPES as u64,
        });
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let role = EnvelopeRole::from_byte(c.u8()?)?;
        let key_id = c.array::<KEY_ID_LEN>()?;
        let encapped_key = c.array::<ENCAPPED_KEY_LEN>()?.to_vec();
        let ct_len = c.u16()? as usize;
        if ct_len == 0 || ct_len > MAX_ENVELOPE_CT_LEN {
            return Err(FormatError::Malformed("key envelope ciphertext length"));
        }
        let ciphertext = c.take(ct_len)?.to_vec();
        out.push(KeyEnvelope {
            role,
            key_id,
            encapped_key,
            ciphertext,
        });
    }
    c.finish()?;
    Ok(out)
}
