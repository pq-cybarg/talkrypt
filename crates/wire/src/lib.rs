//! Minimal, allocation-conscious length-prefixed wire codec.
//!
//! All multi-byte integers are big-endian. Byte slices are framed with a
//! `u32` big-endian length prefix. A hard `MAX_FRAME` bound rejects hostile
//! lengths before any allocation, so a malicious peer cannot trigger a huge
//! allocation by lying about a length.
//!
//! This codec carries only opaque ciphertext and protocol headers; it never
//! sees plaintext or key material.

use thiserror::Error;

/// Largest single length-prefixed field we will ever read (16 MiB).
/// Chat messages and crypto headers are kilobytes at most; this is a generous
/// ceiling that still bounds memory against a hostile length prefix.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("unexpected end of input: needed {needed} more bytes, had {had}")]
    UnexpectedEof { needed: usize, had: usize },
    #[error("length prefix {len} exceeds MAX_FRAME ({max})")]
    FrameTooLarge { len: usize, max: usize },
    #[error("trailing bytes remain after decode: {0}")]
    TrailingBytes(usize),
}

/// Appends framed data to an owned byte buffer.
#[derive(Default, Debug)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Write a raw `u8`.
    pub fn put_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Write a big-endian `u32`.
    pub fn put_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Write a `u32` length prefix followed by the bytes themselves.
    pub fn put_bytes(&mut self, bytes: &[u8]) {
        // Caller-side invariant: nothing we serialize approaches MAX_FRAME.
        debug_assert!(bytes.len() <= MAX_FRAME);
        self.put_u32(bytes.len() as u32);
        self.buf.extend_from_slice(bytes);
    }

    /// Consume the writer, returning the assembled buffer.
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

/// Reads framed data from a byte slice, tracking a cursor.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::UnexpectedEof {
            needed: n,
            had: self.remaining(),
        })?;
        if end > self.buf.len() {
            return Err(WireError::UnexpectedEof {
                needed: n,
                had: self.remaining(),
            });
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub fn get_u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    pub fn get_u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a `u32`-length-prefixed byte field, enforcing `MAX_FRAME`.
    pub fn get_bytes(&mut self) -> Result<&'a [u8], WireError> {
        let len = self.get_u32()? as usize;
        if len > MAX_FRAME {
            return Err(WireError::FrameTooLarge {
                len,
                max: MAX_FRAME,
            });
        }
        self.take(len)
    }

    /// Read a length-prefixed field into an owned `Vec`.
    pub fn get_vec(&mut self) -> Result<Vec<u8>, WireError> {
        Ok(self.get_bytes()?.to_vec())
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Assert the input is fully consumed. Use after decoding a complete
    /// message to reject trailing garbage.
    pub fn finish(self) -> Result<(), WireError> {
        if self.remaining() != 0 {
            Err(WireError::TrailingBytes(self.remaining()))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_multiple_fields() {
        let mut w = Writer::new();
        w.put_u8(0xAB);
        w.put_u32(0xDEAD_BEEF);
        w.put_bytes(b"hello");
        w.put_bytes(b"");
        w.put_bytes(&[0u8; 300]);
        let bytes = w.into_vec();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.get_u8().unwrap(), 0xAB);
        assert_eq!(r.get_u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.get_bytes().unwrap(), b"hello");
        assert_eq!(r.get_bytes().unwrap(), b"");
        assert_eq!(r.get_bytes().unwrap(), &[0u8; 300]);
        r.finish().unwrap();
    }

    #[test]
    fn truncated_input_errors() {
        // length prefix says 5 bytes but only 2 follow
        let bytes = [0u8, 0, 0, 5, b'h', b'i'];
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            r.get_bytes(),
            Err(WireError::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn oversized_length_rejected_without_allocation() {
        // length prefix claims 0xFFFFFFFF bytes
        let bytes = [0xFFu8, 0xFF, 0xFF, 0xFF];
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            r.get_bytes(),
            Err(WireError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn trailing_bytes_detected() {
        let mut w = Writer::new();
        w.put_bytes(b"x");
        let mut bytes = w.into_vec();
        bytes.push(0); // junk
        let mut r = Reader::new(&bytes);
        let _ = r.get_bytes().unwrap();
        assert!(matches!(r.finish(), Err(WireError::TrailingBytes(1))));
    }
}
