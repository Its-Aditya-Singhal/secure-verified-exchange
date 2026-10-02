//! Streaming reader and writer for a complete container:
//! prelude ‖ header ‖ chunk records ‖ trailer.

use std::io::{Read, Write};

use crate::error::{FormatError, Result, map_eof};
use crate::header::{Header, Prelude};
use crate::limits::*;
use crate::*;

/// Metadata about one payload chunk record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkInfo {
    /// Zero-based position; this is the STREAM counter.
    pub index: u64,
    pub is_final: bool,
    /// Length of the ciphertext (plaintext length + 16-byte tag).
    pub ct_len: u32,
}

impl ChunkInfo {
    /// The 5 bytes that precede the ciphertext on the wire (`flag ‖ ct_len`).
    /// These are included in the payload commitment.
    pub fn record_prefix(&self) -> [u8; 5] {
        let mut out = [0u8; 5];
        out[0] = if self.is_final {
            CHUNK_FLAG_FINAL
        } else {
            CHUNK_FLAG_MORE
        };
        out[1..].copy_from_slice(&self.ct_len.to_le_bytes());
        out
    }

    /// Validate a chunk record header against the stream position and chunk size.
    fn check(index: u64, flag: u8, ct_len: u32, chunk_size: u32) -> Result<Self> {
        if index >= MAX_CHUNKS {
            return Err(FormatError::LimitExceeded {
                what: "chunk count",
                limit: MAX_CHUNKS,
            });
        }
        let full = chunk_size + CHUNK_TAG_LEN;
        let is_final = match flag {
            CHUNK_FLAG_MORE => false,
            CHUNK_FLAG_FINAL => true,
            _ => return Err(FormatError::Malformed("chunk flag")),
        };
        if !is_final && ct_len != full {
            return Err(FormatError::Malformed("non-final chunk length"));
        }
        if is_final && !(CHUNK_TAG_LEN..=full).contains(&ct_len) {
            return Err(FormatError::Malformed("final chunk length"));
        }
        // An empty final chunk is only canonical for an empty payload.
        if is_final && ct_len == CHUNK_TAG_LEN && index > 0 {
            return Err(FormatError::Malformed("empty final chunk"));
        }
        Ok(ChunkInfo {
            index,
            is_final,
            ct_len,
        })
    }
}

/// The trailer: chunk count, payload commitment and sender signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trailer {
    pub chunk_count: u64,
    pub payload_commitment: [u8; PAYLOAD_COMMITMENT_LEN],
    pub sig_alg: u16,
    pub signature: Vec<u8>,
}

impl Trailer {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.signature.len() > MAX_SIGNATURE_LEN {
            return Err(FormatError::LimitExceeded {
                what: "signature",
                limit: MAX_SIGNATURE_LEN as u64,
            });
        }
        let mut out = Vec::with_capacity(48 + self.signature.len());
        out.extend_from_slice(&TRAILER_MAGIC);
        out.extend_from_slice(&self.chunk_count.to_le_bytes());
        out.extend_from_slice(&self.payload_commitment);
        out.extend_from_slice(&self.sig_alg.to_le_bytes());
        out.extend_from_slice(&(self.signature.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    fn read_from<R: Read>(r: &mut R) -> Result<Self> {
        let mut fixed = [0u8; 4 + 8 + 32 + 2 + 2];
        r.read_exact(&mut fixed).map_err(map_eof)?;
        if fixed[..4] != TRAILER_MAGIC {
            return Err(FormatError::Malformed("trailer magic"));
        }
        let chunk_count = u64::from_le_bytes(fixed[4..12].try_into().expect("slice length"));
        let payload_commitment: [u8; 32] = fixed[12..44].try_into().expect("slice length");
        let sig_alg = u16::from_le_bytes([fixed[44], fixed[45]]);
        let sig_len = u16::from_le_bytes([fixed[46], fixed[47]]) as usize;
        if sig_len == 0 || sig_len > MAX_SIGNATURE_LEN {
            return Err(FormatError::Malformed("signature length"));
        }
        let mut signature = vec![0u8; sig_len];
        r.read_exact(&mut signature).map_err(map_eof)?;
        Ok(Trailer {
            chunk_count,
            payload_commitment,
            sig_alg,
            signature,
        })
    }
}

/// Streaming reader. Reads the prelude and header eagerly, then yields
/// chunk records one at a time so payloads of any size use bounded memory.
pub struct Reader<R: Read> {
    inner: R,
    prelude: Prelude,
    header: Header,
    header_region: Vec<u8>,
    next_index: u64,
    saw_final: bool,
}

impl<R: Read> Reader<R> {
    pub fn new(mut inner: R) -> Result<Self> {
        let mut pbytes = [0u8; Prelude::LEN];
        inner.read_exact(&mut pbytes).map_err(map_eof)?;
        let prelude = Prelude::decode(&pbytes)?;

        // header_len is bounded by Prelude::decode, so this allocation is bounded.
        let mut header_region = Vec::with_capacity(Prelude::LEN + prelude.header_len as usize);
        header_region.extend_from_slice(&pbytes);
        header_region.resize(Prelude::LEN + prelude.header_len as usize, 0);
        inner
            .read_exact(&mut header_region[Prelude::LEN..])
            .map_err(map_eof)?;
        let header = Header::decode(&header_region[Prelude::LEN..])?;

        Ok(Reader {
            inner,
            prelude,
            header,
            header_region,
            next_index: 0,
            saw_final: false,
        })
    }

    pub fn prelude(&self) -> &Prelude {
        &self.prelude
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The exact bytes of prelude ‖ header, as they appeared on the wire.
    /// This is what the header hash is computed over.
    pub fn header_region(&self) -> &[u8] {
        &self.header_region
    }

    /// Read the next chunk ciphertext into `buf`. Returns `Ok(None)` once
    /// the final chunk has been consumed.
    pub fn next_chunk(&mut self, buf: &mut Vec<u8>) -> Result<Option<ChunkInfo>> {
        if self.saw_final {
            return Ok(None);
        }
        let mut rec = [0u8; 5];
        self.inner.read_exact(&mut rec).map_err(map_eof)?;
        let ct_len = u32::from_le_bytes([rec[1], rec[2], rec[3], rec[4]]);
        let info = ChunkInfo::check(self.next_index, rec[0], ct_len, self.header.chunk_size)?;
        // ct_len is bounded by chunk_size + 16 <= 16 MiB + 16.
        buf.clear();
        buf.resize(ct_len as usize, 0);
        self.inner.read_exact(buf).map_err(map_eof)?;
        self.next_index += 1;
        self.saw_final = info.is_final;
        Ok(Some(info))
    }

    /// Read the trailer and require end-of-input. Must be called after the
    /// final chunk.
    pub fn finish(mut self) -> Result<(Trailer, R)> {
        if !self.saw_final {
            return Err(FormatError::Malformed(
                "trailer requested before final chunk",
            ));
        }
        let trailer = Trailer::read_from(&mut self.inner)?;
        if trailer.chunk_count != self.next_index {
            return Err(FormatError::Malformed("trailer chunk count"));
        }
        let mut probe = [0u8; 1];
        loop {
            match self.inner.read(&mut probe) {
                Ok(0) => break,
                Ok(_) => return Err(FormatError::TrailingData),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok((trailer, self.inner))
    }
}

/// Streaming writer enforcing the same structural rules as [`Reader`].
pub struct Writer<W: Write> {
    inner: W,
    chunk_size: u32,
    next_index: u64,
    saw_final: bool,
    header_region: Vec<u8>,
}

impl<W: Write> Writer<W> {
    /// Write the prelude and header.
    pub fn new(mut inner: W, suite_id: u16, header: &Header) -> Result<Self> {
        let hbytes = header.encode()?;
        let prelude = Prelude {
            major: FORMAT_MAJOR,
            minor: FORMAT_MINOR,
            suite_id,
            header_len: hbytes.len() as u32,
        };
        let mut header_region = prelude.encode().to_vec();
        header_region.extend_from_slice(&hbytes);
        inner.write_all(&header_region)?;
        Ok(Writer {
            inner,
            chunk_size: header.chunk_size,
            next_index: 0,
            saw_final: false,
            header_region,
        })
    }

    /// Encode prelude ‖ header without writing, e.g. to compute the header
    /// hash before any chunk is encrypted.
    pub fn header_region_for(suite_id: u16, header: &Header) -> Result<Vec<u8>> {
        let hbytes = header.encode()?;
        let prelude = Prelude {
            major: FORMAT_MAJOR,
            minor: FORMAT_MINOR,
            suite_id,
            header_len: hbytes.len() as u32,
        };
        let mut out = prelude.encode().to_vec();
        out.extend_from_slice(&hbytes);
        Ok(out)
    }

    pub fn header_region(&self) -> &[u8] {
        &self.header_region
    }

    /// Write one chunk record and return its metadata.
    pub fn write_chunk(&mut self, is_final: bool, ciphertext: &[u8]) -> Result<ChunkInfo> {
        if self.saw_final {
            return Err(FormatError::WriterState("chunk after final chunk"));
        }
        let ct_len = u32::try_from(ciphertext.len()).map_err(|_| FormatError::LimitExceeded {
            what: "chunk length",
            limit: u32::MAX as u64,
        })?;
        let flag = if is_final {
            CHUNK_FLAG_FINAL
        } else {
            CHUNK_FLAG_MORE
        };
        let info = ChunkInfo::check(self.next_index, flag, ct_len, self.chunk_size)?;
        self.inner.write_all(&info.record_prefix())?;
        self.inner.write_all(ciphertext)?;
        self.next_index += 1;
        self.saw_final = is_final;
        Ok(info)
    }

    /// Write the trailer and return the underlying writer.
    pub fn finish(mut self, trailer: &Trailer) -> Result<W> {
        if !self.saw_final {
            return Err(FormatError::WriterState("finish before final chunk"));
        }
        if trailer.chunk_count != self.next_index {
            return Err(FormatError::WriterState("trailer chunk count mismatch"));
        }
        self.inner.write_all(&trailer.encode()?)?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

/// A fully parsed, in-memory container. Intended for tests, tooling and
/// fuzzing; use [`Reader`] for real payloads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Container {
    pub prelude: Prelude,
    pub header: Header,
    pub header_region: Vec<u8>,
    pub chunks: Vec<(ChunkInfo, Vec<u8>)>,
    pub trailer: Trailer,
}

/// Parse a complete container from memory.
pub fn parse(bytes: &[u8]) -> Result<Container> {
    let mut reader = Reader::new(bytes)?;
    let mut chunks = Vec::new();
    loop {
        let mut buf = Vec::new();
        match reader.next_chunk(&mut buf)? {
            Some(info) => chunks.push((info, buf)),
            None => break,
        }
    }
    let prelude = *reader.prelude();
    let header = reader.header().clone();
    let header_region = reader.header_region().to_vec();
    let (trailer, _) = reader.finish()?;
    Ok(Container {
        prelude,
        header,
        header_region,
        chunks,
        trailer,
    })
}
