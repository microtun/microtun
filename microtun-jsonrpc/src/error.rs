/// Re-export of the transport error kind from `embedded-io` /
/// `embedded-io-async` (they share the same type). Tokio transport errors are
/// normalized to this kind by the optional Tokio adapter.
pub use crate::eio::ErrorKind as IoErrorKind;

/// Maximum length of a remote error message captured without `alloc`.
/// Longer messages are truncated.
pub const MAX_ERR_MSG_LEN: usize = 64;

#[cfg(feature = "alloc")]
type ErrMsg = alloc::string::String;
#[cfg(not(feature = "alloc"))]
type ErrMsg = heapless::String<MAX_ERR_MSG_LEN>;

/// An `error` object received in a response from the remote endpoint.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("remote error {code}: {message}")]
pub struct RemoteError {
    /// JSON-RPC error code (see [`crate::codes`] for the standard ones).
    pub code: i32,
    /// Error message (truncated to [`MAX_ERR_MSG_LEN`] bytes without `alloc`).
    pub message: ErrMsg,
}

impl RemoteError {
    pub(crate) fn new(code: i32, message: Option<&str>) -> Self {
        let msg = message.unwrap_or("");
        #[cfg(feature = "alloc")]
        let message = ErrMsg::from(msg);
        #[cfg(not(feature = "alloc"))]
        let message = {
            let mut out = ErrMsg::new();
            for c in msg.chars() {
                if out.push(c).is_err() {
                    break;
                }
            }
            out
        };
        RemoteError { code, message }
    }
}

/// Errors produced by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Transport error from the underlying `Read`/`Write`.
    #[error("i/o error: {0:?}")]
    Io(IoErrorKind),
    /// The transport reached end-of-stream.
    #[error("end of stream")]
    Eof,
    /// A buffer was too small: the incoming frame exceeded the receive
    /// buffer, or a serialized message exceeded the transmit buffer.
    #[error("buffer overflow")]
    Overflow,
    /// Malformed JSON / JSON-RPC data was received (or, from
    /// [`crate::Params::parse`], the params did not match the expected type).
    ///
    /// This is the `-32700` case: the bytes are not JSON the receiver can
    /// parse at all, or they are a batch, which this crate does not support.
    #[error("malformed message")]
    Parse,
    /// Well-formed JSON that is not a well-formed JSON-RPC envelope: a
    /// missing or wrong `jsonrpc` version, an `id` that is not a signed
    /// 64-bit JSON integer, an explicit `"id": null`, or a message that is
    /// neither a request, a notification, nor a response.
    ///
    /// Distinct from [`Error::Parse`] because the two map to different
    /// JSON-RPC error codes — `-32600` here, `-32700` there — and a caller
    /// cannot fix a fault it is told the wrong name for.
    #[error("invalid request envelope")]
    InvalidRequest,
    /// A request expected params but the message contained none.
    #[error("missing params")]
    MissingParams,
    /// The remote endpoint answered one of our requests with an error object.
    #[error(transparent)]
    Remote(#[from] RemoteError),
}
