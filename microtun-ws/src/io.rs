//! Thin wrappers that map `embedded-io-async` failures onto [`Error`].
//!
//! Both directions of this protocol are length-prefixed, so a partial read is
//! never a recoverable state: the receiver knows exactly how many bytes belong
//! to the frame it is decoding, and anything short of that many means the
//! stream ended mid-frame. `read_exact` is therefore the only read primitive
//! the crate uses, and its two failure modes are flattened into the crate's
//! own [`Error::Eof`] and [`Error::Io`].

use embedded_io_async::{Error as _, Read, ReadExactError, Write};

use crate::error::Error;

/// Read exactly `buf.len()` bytes.
pub(crate) async fn read_exact<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<(), Error> {
    reader.read_exact(buf).await.map_err(|error| match error {
        ReadExactError::UnexpectedEof => Error::Eof,
        ReadExactError::Other(error) => Error::Io(error.kind()),
    })
}

/// Write every byte of `buf`.
pub(crate) async fn write_all<W: Write>(writer: &mut W, buf: &[u8]) -> Result<(), Error> {
    writer
        .write_all(buf)
        .await
        .map_err(|error| Error::Io(error.kind()))
}

/// Flush the transport.
pub(crate) async fn flush<W: Write>(writer: &mut W) -> Result<(), Error> {
    writer
        .flush()
        .await
        .map_err(|error| Error::Io(error.kind()))
}

/// A `core::fmt::Write` sink over a caller-owned byte buffer.
///
/// The handshake is the only text this crate produces, and it is produced once
/// per connection, so it is formatted into a scratch buffer and written in a
/// single call rather than assembled from a dozen small writes.
pub(crate) struct Cursor<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    pub(crate) fn written(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl core::fmt::Write for Cursor<'_> {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let bytes = text.as_bytes();
        let end = self.len + bytes.len();
        if end > self.buf.len() {
            return Err(core::fmt::Error);
        }
        self.buf[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}
