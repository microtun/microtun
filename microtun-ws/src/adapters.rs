//! Tokio 1.x transport compatibility.
//!
//! The connection stays generic over `embedded-io-async`, and the bridge from
//! Tokio's own I/O traits is `embedded-io-adapters`, maintained alongside
//! `embedded-io` itself. It is re-exported here under a shorter name rather
//! than reimplemented: the adapter is a little `poll_fn` wrapping around
//! `poll_read`/`poll_write`, and the part of it that matters — Tokio leaving
//! an empty read pending at end of stream, which `embedded-io` forbids — is
//! exactly the part worth not writing twice.
//!
//! ```ignore
//! let (reader, writer) = tokio::io::split(stream);
//! let connection = Connection::server(TokioIo::new(reader), TokioIo::new(writer));
//! ```

/// Adapter from Tokio 1.x I/O traits to `embedded-io-async`.
pub type TokioIo<T> = embedded_io_adapters::tokio_1::FromTokio<T>;
