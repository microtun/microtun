//! Errors and WebSocket close codes.

/// Re-export of the transport error kind from `embedded-io-async`. Tokio
/// transport errors are normalized to this kind by the optional adapter.
pub use embedded_io_async::ErrorKind as IoErrorKind;

/// A WebSocket close status code (RFC 6455 §7.4).
///
/// Only the codes this crate can actually produce are named. The type stays
/// open, because a peer may close with any registered code and the receiver
/// reports it verbatim rather than collapsing it to "closed".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseCode(pub u16);

impl CloseCode {
    /// The purpose of the connection has been fulfilled.
    pub const NORMAL: Self = Self(1000);
    /// The endpoint is going away (server shutting down, browser navigating).
    pub const GOING_AWAY: Self = Self(1001);
    /// A protocol error: a malformed frame, a reserved bit, a masking
    /// violation, or a fragment sequence that cannot be assembled.
    pub const PROTOCOL_ERROR: Self = Self(1002);
    /// A message this endpoint cannot accept, which here means a binary
    /// message: the payload of every message in this transport is text.
    pub const UNSUPPORTED_DATA: Self = Self(1003);
    /// A policy violation. The Tracker uses this for a caller it will
    /// not serve, when it has already upgraded the connection.
    pub const POLICY_VIOLATION: Self = Self(1008);
    /// The message is larger than the receiving buffer.
    pub const MESSAGE_TOO_BIG: Self = Self(1009);
    /// An unexpected condition on this side.
    pub const INTERNAL_ERROR: Self = Self(1011);
}

/// Errors produced by this crate.
///
/// The variants a caller must tell apart are the ones with different
/// consequences: [`Error::Closed`] is an orderly shutdown the peer announced,
/// [`Error::Eof`] and [`Error::Io`] are the transport disappearing, and
/// everything else says the peer is not speaking this protocol. All of them
/// end the connection — none is recoverable in place, because a WebSocket
/// stream has no resynchronization point once a frame boundary is in doubt.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Transport error from the underlying `Read`/`Write`.
    #[error("i/o error: {0:?}")]
    Io(IoErrorKind),
    /// The transport reached end-of-stream mid-frame or mid-handshake.
    #[error("end of stream")]
    Eof,
    /// The peer sent a close frame. Carries the status code it named, or
    /// `None` when the close frame had no payload.
    #[error("connection closed by peer")]
    Closed(Option<CloseCode>),
    /// This endpoint has already sent a close frame, so it may not send more.
    #[error("connection already closed")]
    AlreadyClosed,
    /// The frame stream violates RFC 6455: a reserved bit, a fragmented
    /// control frame, an oversized control payload, a continuation with
    /// nothing to continue, or a masking rule broken for the peer's role.
    #[error("websocket protocol error")]
    Protocol,
    /// A binary message arrived. This transport carries text only.
    #[error("binary messages are not supported")]
    UnsupportedData,
    /// An incoming message did not fit the receive buffer, or an outgoing
    /// handshake did not fit the scratch buffer.
    #[error("message too large for the buffer")]
    TooLarge,
    /// The opening handshake failed: a malformed HTTP head, a status other
    /// than 101, a missing or wrong `Sec-WebSocket-Accept`, an unacceptable
    /// path or another invalid WebSocket handshake field.
    #[error("websocket handshake failed")]
    Handshake,
}

impl Error {
    /// The close code that describes this failure to the peer.
    pub(crate) const fn close_code(&self) -> CloseCode {
        match self {
            Error::UnsupportedData => CloseCode::UNSUPPORTED_DATA,
            Error::TooLarge => CloseCode::MESSAGE_TOO_BIG,
            Error::Protocol | Error::Handshake => CloseCode::PROTOCOL_ERROR,
            _ => CloseCode::INTERNAL_ERROR,
        }
    }
}
