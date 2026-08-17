//! A `no_std` **WebSocket** (RFC 6455) transport for embedded systems.
//!
//! * Zero allocation: every buffer is either caller-owned or a fixed stack
//!   array sized by the protocol itself.
//! * Transport-agnostic: any [`embedded-io-async`] `Read`/`Write` pair — a
//!   TCP socket, a TLS stream, an in-memory duplex — plus raw Tokio 1.x I/O
//!   with the `tokio` feature.
//! * Both roles: clients perform the opening handshake and mask what they
//!   send; [`Connection::server`] answers one and requires
//!   incoming frames to be masked, as the RFC does.
//!
//! This crate deliberately implements the part of RFC 6455 a control channel
//! uses and nothing else:
//!
//! | Implemented | Not implemented |
//! | --- | --- |
//! | Client and server opening handshake | `permessage-deflate` and every other extension |
//! | Text messages, including continuation frames | Binary messages (rejected with `1003`) |
//! | Ping/pong, answered inside [`Connection::recv_text`] | Automatic keepalive scheduling |
//! | Close frames with status codes | HTTP redirects, proxies, cookies, `wss://` |
//!
//! The omissions are the point: what is left is small enough to read in one
//! sitting and to run on a device with kilobytes of RAM, while a browser's
//! built-in `WebSocket` still talks to it unmodified.
//!
//! # Buffers belong to the caller
//!
//! [`Connection::recv_text`] takes the destination buffer as an argument
//! rather than owning one. That is not only a memory-budget choice: it is what
//! lets a caller hold a decoded message *and* write a reply, because the
//! message lives in one of the caller's fields and the connection in another,
//! so the borrow checker sees two disjoint borrows rather than one aliased
//! `&mut self`.
//!
//! The buffer is also the message-size limit. A message larger than the
//! buffer is refused with a `1009` close rather than silently truncated, so a
//! peer cannot make a fixed-buffer receiver read a message it has no room for.
//!
//! # Example
//!
//! ```ignore
//! use microtun_ws::{ClientRequest, CloseCode, Connection};
//!
//! let mut scratch = [0u8; 512];
//! let mut connection = Connection::client(
//!     reader,
//!     writer,
//!     &ClientRequest {
//!         host: "example.com",
//!         path: "/socket",
//!     },
//!     &mut rng,
//!     &mut scratch,
//! )
//! .await?;
//!
//! connection.send_text(br#"{"id":1,"method":"peer.by_key"}"#).await?;
//!
//! let mut message = [0u8; 1024];
//! let len = connection.recv_text(&mut message).await?;
//! // `message[..len]` is one complete text message.
//!
//! connection.close(CloseCode::NORMAL, "done").await?;
//! ```
//!
//! # Security note
//!
//! This crate implements WebSocket framing over an already-open byte stream; it
//! authenticates nothing and encrypts nothing by itself. RFC 6455 client-side
//! masking is a defense against confusing intermediaries, not a confidentiality
//! mechanism. Client construction requires a caller-provided cryptographic
//! RNG; the crate seeds per-connection ChaCha20 masking state from it and never
//! falls back to a non-cryptographic WebSocket-specific generator. If
//! confidentiality or peer authentication is required, provide a TLS or
//! otherwise protected underlying transport.

#![no_std]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]

#[cfg(test)]
extern crate std;

#[cfg(feature = "tokio")]
mod adapters;
mod connection;
mod error;
mod frame;
mod handshake;
mod io;
mod mask;

#[cfg(feature = "tokio")]
pub use adapters::TokioIo;
pub use connection::{Connection, Sender};
pub use error::{CloseCode, Error, IoErrorKind};
pub use frame::MAX_CONTROL_PAYLOAD_LEN;
pub use handshake::{ClientRequest, ServerConfig, Status, Upgrade, reject, request_upgrade};

/// The role this endpoint plays in the connection.
///
/// The role decides two asymmetries RFC 6455 defines, and getting either
/// backwards is a protocol error the other end is required to close on: a
/// client masks every frame it sends and rejects a masked frame it receives,
/// and a server does exactly the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Opened the connection: masks outgoing frames.
    Client,
    /// Accepted the connection: sends unmasked frames.
    Server,
}

impl Role {
    /// Whether this role masks the frames it sends.
    pub(crate) const fn masks_output(self) -> bool {
        matches!(self, Role::Client)
    }

    /// Whether a frame arriving in this role must carry a masking key.
    pub(crate) const fn requires_masked_input(self) -> bool {
        matches!(self, Role::Server)
    }
}
