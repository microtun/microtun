//! One Peers API conversation over one WebSocket connection.
//!
//! A [`Session`] adds the two things WebSocket framing does not provide:
//! *correlation*, so a response can be matched to the call that asked for it,
//! and *dispatch*, so a message arriving while a call is outstanding reaches
//! the application instead of being mistaken for that call's answer.
//!
//! The type is symmetric. The Tracker holds one to serve requests and
//! push invalidations; a resolver holds one to issue lookups and receive those
//! invalidations. Only the [`Handler`] differs.
//!
//! # Bidirectional by construction
//!
//! [`Session::call`] keeps reading until the response it is waiting for
//! arrives, handing every other message to the [`Handler`] on the way past.
//! That is what makes a single connection enough: a `peer.changed` sent while
//! a lookup is in flight is queued by the handler before the lookup's own
//! answer is applied, so a client cannot install a record and then silently
//! miss the invalidation that raced it.

use microtun_ws::{CloseCode, Connection};
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    codes,
    message::{
        Envelope, ErrorObject, OutCall, OutError, OutResult, ParamsEnvelope, RemoteError,
        ResponseEnvelope,
    },
};

/// Failures of the session layer.
///
/// The distinction that matters to a resolver is between [`Self::Remote`] —
/// a complete, well-formed answer that happens to be an error, after which the
/// connection is still usable — and everything else, which ends the
/// connection. A WebSocket stream has no resynchronization point, so a message
/// that could not be decoded is not a message that can be skipped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// The WebSocket transport failed or the peer closed the connection.
    #[error("websocket error: {0}")]
    Transport(#[from] microtun_ws::Error),
    /// A message was not a well-formed Peers API envelope, or its payload did
    /// not match the expected type.
    #[error("malformed Peers API message")]
    Malformed,
    /// A message did not fit the transmit buffer.
    #[error("Peers API message too large for its buffer")]
    Overflow,
    /// A request expected `params` and the message carried none.
    #[error("missing params")]
    MissingParams,
    /// The remote endpoint answered a call with an error object.
    #[error(transparent)]
    Remote(#[from] RemoteError),
}

/// Application-side dispatcher for **incoming** requests and notifications.
///
/// The handler is synchronous by design: it computes and serializes a reply,
/// and the [`Session`] performs the I/O. That keeps a handler usable from an
/// interrupt-driven embedded task and a Tokio worker alike, and keeps the
/// borrow of the receive buffer from spanning an `await`.
pub trait Handler {
    /// Handle an incoming request — a message with an `id`.
    ///
    /// Exactly one response must be produced, which the type system enforces:
    /// the only way to obtain a [`Reply`] is through a [`Responder`] method,
    /// and each of them consumes the responder.
    fn handle_request(
        &mut self,
        method: &str,
        params: Params<'_>,
        responder: Responder<'_>,
    ) -> Reply;

    /// Handle an incoming notification. The default implementation ignores
    /// every one.
    fn handle_notification(&mut self, method: &str, params: Params<'_>) {
        let _ = (method, params);
    }
}

/// A [`Handler`] that answers every request with *unknown method* and ignores
/// notifications. Useful for a connection that only makes calls.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHandler;

impl Handler for NoHandler {
    fn handle_request(&mut self, _: &str, _: Params<'_>, responder: Responder<'_>) -> Reply {
        responder.unknown_method()
    }
}

/// Lazily-parsed `params` of an incoming message.
#[derive(Debug, Clone, Copy)]
pub struct Params<'a> {
    raw: &'a [u8],
}

impl<'a> Params<'a> {
    /// Deserialize the params into `T`, which may borrow from the receive
    /// buffer for the duration of the handler call.
    pub fn parse<T: serde::Deserialize<'a>>(&self) -> Result<T, SessionError> {
        let (envelope, _) = serde_json_core::from_slice::<ParamsEnvelope<T>>(self.raw)
            .map_err(|_| SessionError::Malformed)?;
        envelope.params.ok_or(SessionError::MissingParams)
    }

    /// The raw bytes of the whole message these params belong to.
    pub fn raw_message(&self) -> &'a [u8] {
        self.raw
    }
}

/// Proof that a response was produced. Not constructible by application code.
#[derive(Debug)]
pub struct Reply {
    /// Length of the serialized response in the session's transmit buffer, or
    /// the failure that prevented it — in which case the session sends a small
    /// internal-error response instead of desynchronizing the conversation.
    res: Result<usize, SessionError>,
}

/// One-shot response builder handed to [`Handler::handle_request`].
#[derive(Debug)]
pub struct Responder<'a> {
    out: &'a mut [u8],
    id: u32,
}

impl Responder<'_> {
    /// Respond with a result.
    pub fn ok<T: Serialize + ?Sized>(self, result: &T) -> Reply {
        let message = OutResult {
            id: self.id,
            result,
        };
        Reply {
            res: serde_json_core::to_slice(&message, self.out).map_err(|_| SessionError::Overflow),
        }
    }

    /// Respond with an error.
    pub fn error(self, code: u16, message: &str) -> Reply {
        Reply {
            res: write_error(self.out, Some(self.id), code, message),
        }
    }

    /// Respond with [`codes::UNKNOWN_METHOD`].
    pub fn unknown_method(self) -> Reply {
        self.error(codes::UNKNOWN_METHOD, "unknown method")
    }

    /// Respond with [`codes::INVALID_PARAMS`].
    pub fn invalid_params(self) -> Reply {
        self.error(codes::INVALID_PARAMS, "invalid params")
    }
}

/// One Peers API conversation.
///
/// * `R`/`W`: the transport halves.
/// * `H`: the [`Handler`] for incoming traffic.
/// * `RX_BUFFER_SIZE`: the largest message this endpoint will accept. A larger
///   one is refused with a WebSocket `1009` close rather than truncated.
/// * `TX_BUFFER_SIZE`: the largest message this endpoint will send.
#[derive(Debug)]
pub struct Session<R, W, H, const RX_BUFFER_SIZE: usize, const TX_BUFFER_SIZE: usize> {
    ws: Connection<R, W>,
    handler: H,
    rx: [u8; RX_BUFFER_SIZE],
    tx: [u8; TX_BUFFER_SIZE],
    next_id: u32,
}

impl<R, W, H, const RX_BUFFER_SIZE: usize, const TX_BUFFER_SIZE: usize>
    Session<R, W, H, RX_BUFFER_SIZE, TX_BUFFER_SIZE>
{
    /// Wrap an already-upgraded WebSocket connection.
    pub fn new(ws: Connection<R, W>, handler: H) -> Self {
        Self {
            ws,
            handler,
            rx: [0; RX_BUFFER_SIZE],
            tx: [0; TX_BUFFER_SIZE],
            next_id: 1,
        }
    }

    /// Access the handler.
    pub fn handler(&self) -> &H {
        &self.handler
    }

    /// Mutably access the handler.
    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
    }

    /// The underlying WebSocket connection, for sending a close frame or
    /// splitting off a [`microtun_ws::Sender`].
    pub fn connection_mut(&mut self) -> &mut Connection<R, W> {
        &mut self.ws
    }

    /// Tear the session apart again.
    pub fn into_parts(self) -> (Connection<R, W>, H) {
        (self.ws, self.handler)
    }
}

impl<R, W, H, const RX_BUFFER_SIZE: usize, const TX_BUFFER_SIZE: usize>
    Session<R, W, H, RX_BUFFER_SIZE, TX_BUFFER_SIZE>
where
    R: embedded_io_async::Read,
    W: embedded_io_async::Write,
    H: Handler,
{
    /// Send a request and wait for its response, returning the deserialized
    /// `result`.
    ///
    /// Requests and notifications from the remote endpoint that arrive while
    /// waiting are dispatched to the [`Handler`] and answered first. A
    /// response naming some other call is discarded: this endpoint keeps one
    /// call outstanding at a time, so such a response is either a duplicate or
    /// the late answer to a call that already timed out, and in both cases the
    /// current call is still unanswered.
    ///
    /// `T` must be owned, because the receive buffer is reused; borrow inside
    /// a handler through [`Params::parse`] instead when zero-copy matters.
    pub async fn call<P, T>(&mut self, method: &str, params: Option<&P>) -> Result<T, SessionError>
    where
        P: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let id = self.next_id;
        // Zero is never used, so a peer's log can tell "the first call on this
        // session" from "a field that was left at its default".
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.send(Some(id), method, params).await?;

        loop {
            let len = self.ws.recv_text(&mut self.rx).await?;
            let message = &self.rx[..len];

            let Ok((envelope, _)) = serde_json_core::from_slice::<Envelope<'_>>(message) else {
                // The message is not an envelope at all. Say so and stop:
                // there is no way to know whether the *next* message is one
                // either, and a caller that keeps reading past a peer it
                // cannot parse is guessing.
                let _ = report(&mut self.ws, &mut self.tx, None, "malformed message").await;
                return Err(SessionError::Malformed);
            };

            match (envelope.method, envelope.id) {
                // An incoming request or notification while we wait: serve it.
                (Some(method), inbound_id) => {
                    dispatch(
                        &mut self.handler,
                        &mut self.ws,
                        &mut self.tx,
                        message,
                        method,
                        inbound_id,
                    )
                    .await?;
                }
                // The response this call is waiting for.
                (None, Some(response_id)) if response_id == id => {
                    let (response, _) =
                        serde_json_core::from_slice::<ResponseEnvelope<'_, T>>(message)
                            .map_err(|_| SessionError::Malformed)?;
                    if let Some(error) = response.error {
                        return Err(RemoteError::new(error.code, error.message).into());
                    }
                    return response.result.ok_or(SessionError::Malformed);
                }
                // A response to something else: drop it and keep waiting.
                (None, Some(_)) => continue,
                // Neither a call nor a response.
                (None, None) => {
                    let _ =
                        report(&mut self.ws, &mut self.tx, None, "not a Peers API message").await;
                    return Err(SessionError::Malformed);
                }
            }
        }
    }

    /// Send a notification: no `id`, no response.
    pub async fn notify<P>(&mut self, method: &str, params: Option<&P>) -> Result<(), SessionError>
    where
        P: Serialize + ?Sized,
    {
        self.send(None, method, params).await
    }

    /// Receive and serve exactly one incoming message.
    ///
    /// Requests are dispatched and answered, notifications are dispatched, and
    /// an unsolicited response is discarded. Run it in a loop to be a server:
    ///
    /// ```ignore
    /// loop { session.poll().await?; }
    /// ```
    pub async fn poll(&mut self) -> Result<(), SessionError> {
        let len = self.ws.recv_text(&mut self.rx).await?;
        let message = &self.rx[..len];

        let Ok((envelope, _)) = serde_json_core::from_slice::<Envelope<'_>>(message) else {
            let _ = report(&mut self.ws, &mut self.tx, None, "malformed message").await;
            return Err(SessionError::Malformed);
        };

        match (envelope.method, envelope.id) {
            (Some(method), id) => {
                dispatch(
                    &mut self.handler,
                    &mut self.ws,
                    &mut self.tx,
                    message,
                    method,
                    id,
                )
                .await
            }
            // An unsolicited response. Nothing asked for it, but it is a
            // well-formed message, so it costs nothing to ignore.
            (None, Some(_)) => Ok(()),
            (None, None) => {
                let _ = report(&mut self.ws, &mut self.tx, None, "not a Peers API message").await;
                Err(SessionError::Malformed)
            }
        }
    }

    /// Close the connection with a status the peer can read.
    pub async fn close(&mut self, code: CloseCode, reason: &str) -> Result<(), SessionError> {
        self.ws.close(code, reason).await?;
        Ok(())
    }

    async fn send<P>(
        &mut self,
        id: Option<u32>,
        method: &str,
        params: Option<&P>,
    ) -> Result<(), SessionError>
    where
        P: Serialize + ?Sized,
    {
        let message = OutCall { id, method, params };
        let len = serde_json_core::to_slice(&message, &mut self.tx)
            .map_err(|_| SessionError::Overflow)?;
        self.ws.send_text(&self.tx[..len]).await?;
        Ok(())
    }
}

/// Serialize one notification into `out`, returning its length.
///
/// A [`Session`] owns the transmit buffer it writes through, and a server that
/// pushes notifications from a second task has no session there to borrow —
/// its session belongs to the task doing the reading. It has a
/// [`microtun_ws::Sender`] and a buffer of its own, and this is the only piece
/// of the envelope it still needs.
pub fn encode_notification<P>(
    out: &mut [u8],
    method: &str,
    params: &P,
) -> Result<usize, SessionError>
where
    P: Serialize + ?Sized,
{
    let message = OutCall {
        id: None,
        method,
        params: Some(params),
    };
    serde_json_core::to_slice(&message, out).map_err(|_| SessionError::Overflow)
}

/// Serialize an error response into `out`, returning its length.
fn write_error(
    out: &mut [u8],
    id: Option<u32>,
    code: u16,
    message: &str,
) -> Result<usize, SessionError> {
    let message = OutError {
        id,
        error: ErrorObject { code, message },
    };
    serde_json_core::to_slice(&message, out).map_err(|_| SessionError::Overflow)
}

/// Report a message this endpoint could not attribute to any call.
async fn report<R, W>(
    ws: &mut Connection<R, W>,
    tx: &mut [u8],
    id: Option<u32>,
    text: &str,
) -> Result<(), SessionError>
where
    R: embedded_io_async::Read,
    W: embedded_io_async::Write,
{
    let len = write_error(tx, id, codes::BAD_MESSAGE, text)?;
    ws.send_text(&tx[..len]).await?;
    Ok(())
}

/// Hand one incoming request or notification to the handler, and send the
/// response if there is to be one.
async fn dispatch<R, W, H>(
    handler: &mut H,
    ws: &mut Connection<R, W>,
    tx: &mut [u8],
    message: &[u8],
    method: &str,
    id: Option<u32>,
) -> Result<(), SessionError>
where
    R: embedded_io_async::Read,
    W: embedded_io_async::Write,
    H: Handler,
{
    let params = Params { raw: message };
    match id {
        None => {
            handler.handle_notification(method, params);
            Ok(())
        }
        Some(id) => {
            // Reborrowed explicitly: the responder writes into this same
            // buffer, and the fallback below has to be able to overwrite it
            // when the handler's reply did not fit.
            let responder = Responder { out: &mut *tx, id };
            let reply = handler.handle_request(method, params, responder);
            let len = match reply.res {
                Ok(len) => len,
                // The handler's reply did not fit the transmit buffer. Answer
                // the call with a small internal error rather than leaving the
                // caller waiting for a response that will never come.
                Err(_) => write_error(tx, Some(id), codes::INTERNAL, "internal error")?,
            };
            ws.send_text(&tx[..len]).await?;
            Ok(())
        }
    }
}
