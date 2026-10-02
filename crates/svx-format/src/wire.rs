//! Little-endian primitives over an in-memory slice.

use crate::error::{FormatError, Result};

/// A bounds-checked cursor over a byte slice. Every read either succeeds in
/// full or returns an error; it never panics on short input.
pub(crate) struct Cursor<'a> {
    buf: &'a [u8],
    what: &'static str,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(buf: &'a [u8], what: &'static str) -> Self {
        Self { buf, what }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(FormatError::Malformed(self.what));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub(crate) fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Require that the whole value has been consumed.
    pub(crate) fn finish(self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(FormatError::Malformed(self.what))
        }
    }
}
