use serde::{Deserialize, Serialize};

use crate::{
    codes,
    error::Error,
    msg::{OutErrorObj, OutErrorResponse, OutResponse, ParamsEnvelope, VERSION},
};

/// Application-side dispatcher for **incoming** requests and notifications.
///
/// The handler is synchronous by design: it should compute and serialize a
/// reply, not perform I/O (the [`crate::Connection`] does the I/O). This keeps it
/// identical between the `sync` and `async` builds of the crate.
pub trait Handler {
    /// Handle an incoming request (a message with an `id`).
    ///
    /// Exactly one response **must** be produced, which the type system
    /// enforces: the only way to obtain the [`Reply`] return value is
    /// through one of the [`Responder`] methods, each of which consumes the
    /// responder.
    fn handle_request(
        &mut self,
        method: &str,
        params: Params<'_>,
        responder: Responder<'_>,
    ) -> Reply;

    /// Handle an incoming notification (no `id`, no response possible).
    ///
    /// The default implementation ignores all notifications.
    fn handle_notification(&mut self, method: &str, params: Params<'_>) {
        let _ = (method, params);
    }
}

/// A [`Handler`] that rejects every request with *method not found* and
/// ignores all notifications. Useful for client-only connections.
pub struct NoHandler;

impl Handler for NoHandler {
    fn handle_request(&mut self, _: &str, _: Params<'_>, responder: Responder<'_>) -> Reply {
        responder.method_not_found()
    }
}

/// Lazily-parsed `params` of an incoming request or notification.
#[derive(Clone, Copy)]
pub struct Params<'a> {
    pub(crate) raw: &'a [u8],
}

impl<'a> Params<'a> {
    /// Deserialize the params into `T`.
    ///
    /// `T` may borrow from the receive buffer (e.g. `&str` fields), valid
    /// for the duration of the handler call.
    ///
    /// Returns [`Error::MissingParams`] if the message has no `params`
    /// member and [`Error::Parse`] if it does not match `T`.
    pub fn parse<T: Deserialize<'a>>(&self) -> Result<T, Error> {
        let (env, _) =
            serde_json_core::from_slice::<ParamsEnvelope<T>>(self.raw).map_err(|_| Error::Parse)?;
        env.params.ok_or(Error::MissingParams)
    }

    /// The raw bytes of the whole JSON-RPC message this `params` belongs to.
    pub fn raw_message(&self) -> &'a [u8] {
        self.raw
    }
}

/// Proof token that a response was produced; returned by [`Responder`]
/// methods and consumed by the connection. Not constructible by user code.
pub struct Reply {
    /// Length of the serialized response in the connection's transmit buffer, or
    /// an error if serialization failed (e.g. buffer overflow) — in that
    /// case the connection sends an *internal error* response instead.
    pub(crate) res: Result<usize, Error>,
}

/// One-shot response builder handed to [`Handler::handle_request`].
pub struct Responder<'a> {
    pub(crate) out: &'a mut [u8],
    pub(crate) id: &'a i64,
}

impl<'a> Responder<'a> {
    /// Respond with a success `result`.
    pub fn ok<T: Serialize + ?Sized>(self, result: &T) -> Reply {
        let msg = OutResponse {
            jsonrpc: VERSION,
            id: self.id,
            result,
        };
        Reply {
            res: serde_json_core::to_slice(&msg, self.out).map_err(|_| Error::Overflow),
        }
    }

    /// Respond with an application-defined error.
    pub fn error(self, code: i32, message: &str) -> Reply {
        Reply {
            res: write_error(self.out, Some(self.id), code, message),
        }
    }

    /// Respond with the standard *method not found* error (`-32601`).
    pub fn method_not_found(self) -> Reply {
        self.error(codes::METHOD_NOT_FOUND, "method not found")
    }

    /// Respond with the standard *invalid params* error (`-32602`).
    pub fn invalid_params(self) -> Reply {
        self.error(codes::INVALID_PARAMS, "invalid params")
    }
}

/// Serialize an error response into `out`, returning its length.
pub(crate) fn write_error(
    out: &mut [u8],
    id: Option<&i64>,
    code: i32,
    message: &str,
) -> Result<usize, Error> {
    let msg = OutErrorResponse {
        jsonrpc: VERSION,
        id,
        error: OutErrorObj { code, message },
    };
    serde_json_core::to_slice(&msg, out).map_err(|_| Error::Overflow)
}
