//! Minimal, panic-free buffer read/write helpers for the v3 wire format.
//!
//! PostgreSQL's wire protocol is big-endian, with NUL-terminated C-strings and
//! length-prefixed fields. These helpers wrap [`bytes`] so message
//! encode/decode reads as a sequence of typed field operations and every short
//! read becomes a [`ProtocolError`] instead of a panic (fail-closed).

use crate::error::ProtocolError;
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// A cursor over a single message body that yields typed fields or errors on
/// truncation. All multi-byte integers are big-endian (network order).
pub(crate) struct BufReader {
    inner: Bytes,
}

impl BufReader {
    pub(crate) fn new(inner: Bytes) -> Self {
        Self { inner }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.inner.remaining()
    }

    fn ensure(&self, n: usize) -> Result<(), ProtocolError> {
        if self.inner.remaining() < n {
            return Err(ProtocolError::malformed("unexpected end of message"));
        }
        Ok(())
    }

    pub(crate) fn get_u8(&mut self) -> Result<u8, ProtocolError> {
        self.ensure(1)?;
        Ok(self.inner.get_u8())
    }

    pub(crate) fn get_i16(&mut self) -> Result<i16, ProtocolError> {
        self.ensure(2)?;
        Ok(self.inner.get_i16())
    }

    pub(crate) fn get_i32(&mut self) -> Result<i32, ProtocolError> {
        self.ensure(4)?;
        Ok(self.inner.get_i32())
    }

    /// Read exactly `n` raw bytes.
    pub(crate) fn get_bytes(&mut self, n: usize) -> Result<Bytes, ProtocolError> {
        self.ensure(n)?;
        Ok(self.inner.split_to(n))
    }

    /// Consume the remaining bytes of the body.
    pub(crate) fn rest(&mut self) -> Bytes {
        let n = self.inner.remaining();
        self.inner.split_to(n)
    }

    /// Read a NUL-terminated C-string and decode it as UTF-8.
    pub(crate) fn get_cstr(&mut self) -> Result<String, ProtocolError> {
        let bytes = self.get_cstr_bytes()?;
        String::from_utf8(bytes.to_vec()).map_err(|_| ProtocolError::InvalidUtf8)
    }

    /// Read a NUL-terminated C-string as raw bytes (NUL not included).
    pub(crate) fn get_cstr_bytes(&mut self) -> Result<Bytes, ProtocolError> {
        let pos = self
            .inner
            .iter()
            .position(|&b| b == 0)
            .ok_or(ProtocolError::UnterminatedCString)?;
        let s = self.inner.split_to(pos);
        // discard the NUL terminator
        let _ = self.inner.get_u8();
        Ok(s)
    }
}

/// A growable writer that emits the v3 wire format big-endian.
pub(crate) struct BufWriter {
    inner: BytesMut,
}

impl BufWriter {
    pub(crate) fn new() -> Self {
        Self {
            inner: BytesMut::new(),
        }
    }

    pub(crate) fn put_u8(&mut self, v: u8) {
        self.inner.put_u8(v);
    }

    pub(crate) fn put_i16(&mut self, v: i16) {
        self.inner.put_i16(v);
    }

    pub(crate) fn put_i32(&mut self, v: i32) {
        self.inner.put_i32(v);
    }

    pub(crate) fn put_slice(&mut self, v: &[u8]) {
        self.inner.put_slice(v);
    }

    /// Write a string followed by a NUL terminator.
    pub(crate) fn put_cstr(&mut self, v: &str) {
        self.inner.put_slice(v.as_bytes());
        self.inner.put_u8(0);
    }

    pub(crate) fn len(&self) -> usize {
        self.inner.len()
    }

    pub(crate) fn into_bytes(self) -> BytesMut {
        self.inner
    }
}
