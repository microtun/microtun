//! A `no_std` **bidirectional JSON-RPC 2.0** connection for embedded systems.
//!
//! * Zero allocation by default: [`serde-json-core`] + [`heapless`] buffers.
//! * Transport-agnostic: any [`embedded-io`] (`sync` feature) or
//!   [`embedded-io-async`] (`async` feature, default) `Read`/`Write` pair — UART,
//!   TCP socket, USB CDC, pipes, ... — plus raw Tokio 1.x I/O with the
//!   `tokio` feature via [`Connection::from_tokio`] / [`Notifier::from_tokio`].
//! * One code base for blocking and async I/O via [`maybe-async`].
//! * Optional `alloc` feature for unbounded remote error messages and a
//!   growable receive buffer.
//! * **Bidirectional**: a single [`Connection`] can issue outgoing requests and
//!   serve incoming requests/notifications over the same connection —
//!   incoming traffic that arrives while you are waiting for a response is
//!   dispatched to your [`Handler`] on the fly.
//!
//! Framing is newline-delimited JSON (one message per `\n`-terminated line),
//! the de-facto standard for JSON-RPC over streams.
//!
//! This crate defines only JSON-RPC transport, framing, ids, dispatch, and
//! errors. It intentionally contains no application method names or payload
//! schemas; those belong in downstream protocol crates.
//!
//! # Example (blocking)
//!
//! ```ignore
//! use microtun_jsonrpc::{Connection, Handler, Params, Responder, Reply};
//!
//! struct Calc;
//!
//! impl Handler for Calc {
//!     fn handle_request(&mut self, method: &str, params: Params<'_>, resp: Responder<'_>) -> Reply {
//!         match method {
//!             "add" => match params.parse::<(i32, i32)>() {
//!                 Ok((a, b)) => resp.ok(&(a + b)),
//!                 Err(_) => resp.invalid_params(),
//!             },
//!             _ => resp.method_not_found(),
//!         }
//!     }
//!
//!     fn handle_notification(&mut self, method: &str, _params: Params<'_>) {
//!         if method == "log" { /* ... */ }
//!     }
//! }
//!
//! // `uart_rx`/`uart_tx` implement embedded_io::{Read, Write}
//! let mut connection: Connection<_, _, _, 512, 512> = Connection::new(uart_rx, uart_tx, Calc);
//!
//! // Client side of the connection: call the remote endpoint.
//! let sum: i32 = connection.call("add", Some(&(1, 2)))?;
//!
//! // Server side: serve one incoming message (request, notification, ...).
//! connection.poll()?;
//! ```
//!
//! With the default `async` feature the same code uses
//! `connection.call(...).await` / `connection.poll().await` and the transport must
//! implement `embedded_io_async::{Read, Write}`. With `features = ["tokio"]`,
//! use `Connection::from_tokio` to pass raw `tokio::io::{AsyncRead, AsyncWrite}`
//! halves without adapter boilerplate. Select the blocking API with
//! `--no-default-features --features sync`.

#![no_std]
#![deny(unsafe_code)]

#[cfg(feature = "tokio")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(all(feature = "sync", feature = "async"))]
compile_error!(
    "features `sync` and `async` are mutually exclusive; \
     use `--no-default-features --features async` for the async API"
);

#[cfg(not(any(feature = "sync", feature = "async")))]
compile_error!("one of the features `sync` or `async` must be enabled");

// Single import point for the I/O traits so the rest of the crate is
// agnostic to blocking vs async.
#[cfg(feature = "sync")]
pub(crate) use embedded_io as eio;
#[cfg(all(feature = "async", not(feature = "sync")))]
pub(crate) use embedded_io_async as eio;

mod buf;
mod connection;
mod error;
mod handler;
mod msg;
#[cfg(feature = "tokio")]
mod tokio;

pub use connection::{Connection, Notifier};
pub use error::{Error, IoErrorKind, MAX_ERR_MSG_LEN, RemoteError};
pub use handler::{Handler, NoHandler, Params, Reply, Responder};
#[cfg(feature = "tokio")]
pub use tokio::TokioIo;

/// Standard JSON-RPC 2.0 error codes.
pub mod codes {
    /// Invalid JSON was received by the server.
    pub const PARSE_ERROR: i32 = -32700;
    /// The JSON sent is not a valid Request object.
    pub const INVALID_REQUEST: i32 = -32600;
    /// The method does not exist / is not available.
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// Invalid method parameter(s).
    pub const INVALID_PARAMS: i32 = -32602;
    /// Internal JSON-RPC error.
    pub const INTERNAL_ERROR: i32 = -32603;
}
