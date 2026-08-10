//! Tokio 1.x transport compatibility.
//!
//! The JSON-RPC engine stays generic over `embedded-io-async`, but this module
//! carries the tiny Tokio bridge itself so applications do not need a separate
//! adapter crate.

use core::{future::poll_fn, pin::Pin, task::Poll};

use crate::{Connection, Notifier};

/// Adapter from Tokio 1.x I/O traits to `embedded-io-async`.
///
/// Most users do not need to name this type: use [`Connection::from_tokio`] or
/// [`Notifier::from_tokio`] with raw Tokio I/O values.
#[derive(Debug, Clone)]
pub struct TokioIo<T: ?Sized> {
    inner: T,
}

impl<T> TokioIo<T> {
    /// Create a new adapter.
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Consume the adapter, returning the original Tokio I/O value.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: ?Sized> TokioIo<T> {
    /// Borrow the original Tokio I/O value.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Mutably borrow the original Tokio I/O value.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: ?Sized> embedded_io_async::ErrorType for TokioIo<T> {
    type Error = std::io::Error;
}

impl<T: tokio::io::AsyncRead + Unpin + ?Sized> embedded_io_async::Read for TokioIo<T> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        // Tokio can leave an empty read pending at EOF. Embedded I/O requires
        // an empty buffer to complete immediately.
        if buf.is_empty() {
            return Ok(0);
        }

        poll_fn(|cx| {
            let mut read_buf = tokio::io::ReadBuf::new(buf);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }
}

impl<T: tokio::io::AsyncWrite + Unpin + ?Sized> embedded_io_async::Write for TokioIo<T> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        match poll_fn(|cx| Pin::new(&mut self.inner).poll_write(cx, buf)).await {
            Ok(0) if !buf.is_empty() => Err(std::io::ErrorKind::WriteZero.into()),
            result => result,
        }
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        poll_fn(|cx| Pin::new(&mut self.inner).poll_flush(cx)).await
    }
}

impl<R, W, H, const RX: usize, const TX: usize> Connection<TokioIo<R>, TokioIo<W>, H, RX, TX> {
    /// Create a connection directly from Tokio reader/writer halves.
    pub fn from_tokio(reader: R, writer: W, handler: H) -> Self {
        Self::new(TokioIo::new(reader), TokioIo::new(writer), handler)
    }

    /// Tear the connection apart and recover the original Tokio I/O values.
    pub fn into_tokio_parts(self) -> (R, W, H) {
        let (reader, writer, handler) = self.into_parts();
        (reader.into_inner(), writer.into_inner(), handler)
    }
}

impl<W, const TX: usize> Notifier<TokioIo<W>, TX> {
    /// Create a notification sender directly from a Tokio writer.
    pub fn from_tokio(writer: W) -> Self {
        Self::new(TokioIo::new(writer))
    }

    /// Recover the original Tokio writer.
    pub fn into_tokio_inner(self) -> W {
        self.into_inner().into_inner()
    }
}
