use serde::{Serialize, de::DeserializeOwned};

use crate::{
    buf::{FrameBuf, trim},
    codes,
    eio::{Error as _, Read, Write},
    error::{Error, RemoteError},
    handler::{Handler, Params, Responder, write_error},
    msg::{
        AnyObject, Envelope, EnvelopeNullId, EnvelopeNumId, OutRequest, ResponseEnvelope, VERSION,
    },
};

/// A write-only JSON-RPC notification sender.
///
/// This is useful when a connection has one task continuously reading through
/// [`Connection::poll`] while another task must push notifications. The caller is
/// responsible for serializing access when the writer is shared with a
/// [`Connection`].
pub struct Notifier<W, const TX: usize = 1024> {
    writer: W,
    tx: [u8; TX],
}

impl<W, const TX: usize> Notifier<W, TX> {
    /// Create a notification sender around a writer.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            tx: [0; TX],
        }
    }

    /// Recover the wrapped writer.
    pub fn into_inner(self) -> W {
        self.writer
    }
}

#[maybe_async::maybe_async]
impl<W, const TX: usize> Notifier<W, TX>
where
    W: Write,
{
    /// Send one fire-and-forget JSON-RPC notification.
    pub async fn notify<P>(&mut self, method: &str, params: Option<&P>) -> Result<(), Error>
    where
        P: Serialize + ?Sized,
    {
        let msg = OutRequest {
            jsonrpc: VERSION,
            method,
            params,
            id: None,
        };
        let len = serde_json_core::to_slice(&msg, &mut self.tx).map_err(|_| Error::Overflow)?;
        write_frame(&mut self.writer, &self.tx[..len]).await
    }
}

/// A bidirectional JSON-RPC 2.0 connection over a byte stream.
///
/// * `R`/`W`: the transport halves (`embedded-io` with the `sync` feature,
///   `embedded-io-async` with the `async` feature). With `tokio`, use
///   [`Connection::from_tokio`] to construct the same connection from raw Tokio halves.
/// * `H`: your [`Handler`] for incoming requests/notifications.
/// * `RX`: receive buffer size in bytes — must hold one complete incoming
///   frame (growable instead when the `alloc` feature is enabled).
/// * `TX`: transmit buffer size in bytes — must hold one complete outgoing
///   frame.
///
/// Messages are newline-delimited JSON. All methods take `&mut self`; wrap
/// the connection in your platform's mutex if it is shared between contexts.
pub struct Connection<R, W, H, const RX: usize = 1024, const TX: usize = 1024> {
    reader: R,
    writer: W,
    handler: H,
    rx: FrameBuf<RX>,
    tx: [u8; TX],
    next_id: i64,
}

impl<R, W, H, const RX: usize, const TX: usize> Connection<R, W, H, RX, TX> {
    /// Create a connection from a transport pair and a handler.
    ///
    /// For client-only use pass [`crate::NoHandler`].
    pub fn new(reader: R, writer: W, handler: H) -> Self {
        Connection {
            reader,
            writer,
            handler,
            rx: FrameBuf::new(),
            tx: [0; TX],
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

    /// Tear the connection apart again.
    pub fn into_parts(self) -> (R, W, H) {
        (self.reader, self.writer, self.handler)
    }
}

#[maybe_async::maybe_async]
impl<R, W, H, const RX: usize, const TX: usize> Connection<R, W, H, RX, TX>
where
    R: Read,
    W: Write,
    H: Handler,
{
    /// Send a request and block (or `.await`) until the matching response
    /// arrives, returning its deserialized `result`.
    ///
    /// **Bidirectional:** any requests or notifications from the remote endpoint
    /// that arrive *while waiting* are dispatched to the [`Handler`] and
    /// answered before this returns. Responses with a stale/unknown id are
    /// discarded.
    ///
    /// Pass `None::<&()>` (or use [`Self::call_no_params`]) for methods
    /// without parameters. `T` must be owned (`DeserializeOwned`) because
    /// the receive buffer is reused; borrow inside a handler via
    /// [`Params::parse`] instead if you need zero-copy.
    pub async fn call<P, T>(&mut self, method: &str, params: Option<&P>) -> Result<T, Error>
    where
        P: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        self.send_request(method, params, Some(&id)).await?;

        loop {
            let end = read_frame(&mut self.reader, &mut self.rx).await?;
            let frame = trim(self.rx.frame(end));
            if frame.is_empty() {
                continue;
            }

            let env = match parse_envelope(frame) {
                Ok(env) => env,
                // A malformed frame makes stream position unreliable: the
                // sender and this receiver no longer agree on where messages
                // begin. Report it, then stop reading rather than trying to
                // resynchronize on a stream that may be arbitrarily skewed.
                Err(error) => {
                    let (code, message) = envelope_error(&error);
                    reply_error(&mut self.writer, &mut self.tx, None, code, message).await?;
                    return Err(error);
                }
            };

            match (env.method, env.id) {
                // Incoming request / notification while we wait: serve it.
                (Some(m), inbound_id) => {
                    dispatch_inbound(
                        &mut self.handler,
                        &mut self.writer,
                        &mut self.tx,
                        frame,
                        m,
                        inbound_id,
                    )
                    .await?;
                }
                // The response we are waiting for.
                (None, Some(resp_id)) if resp_id == id => {
                    let (resp, _) = serde_json_core::from_slice::<ResponseEnvelope<T>>(frame)
                        .map_err(|_| Error::Parse)?;
                    if let Some(err) = resp.error {
                        return Err(Error::Remote(RemoteError::new(err.code, err.message)));
                    }
                    return match resp.result {
                        Some(v) => Ok(v),
                        // `"result": null` (or absent): let `T` decide
                        // whether it can be built from JSON `null`
                        // (e.g. `()` or `Option<_>`).
                        None => serde_json_core::from_slice::<T>(b"null")
                            .map(|(v, _)| v)
                            .map_err(|_| Error::Parse),
                    };
                }
                // Response to some other/stale request: drop it.
                (None, Some(_)) => continue,
                // Neither request nor response.
                (None, None) => {
                    reply_error(
                        &mut self.writer,
                        &mut self.tx,
                        None,
                        codes::INVALID_REQUEST,
                        "invalid request",
                    )
                    .await?;
                    return Err(Error::InvalidRequest);
                }
            }
        }
    }

    /// [`Self::call`] without parameters.
    pub async fn call_no_params<T: DeserializeOwned>(&mut self, method: &str) -> Result<T, Error> {
        self.call::<(), T>(method, None).await
    }

    /// Send a notification (fire-and-forget, no response).
    pub async fn notify<P>(&mut self, method: &str, params: Option<&P>) -> Result<(), Error>
    where
        P: Serialize + ?Sized,
    {
        self.send_request(method, params, None).await
    }

    /// Receive and serve exactly one incoming message.
    ///
    /// * Requests are dispatched to the [`Handler`] and answered.
    /// * Notifications are dispatched to the [`Handler`].
    /// * Malformed frames are answered with a *parse error* / *invalid
    ///   request* response.
    /// * Unsolicited responses are silently discarded.
    ///
    /// Run this in a loop to implement the server role:
    ///
    /// ```ignore
    /// loop { connection.poll()?; }
    /// ```
    pub async fn poll(&mut self) -> Result<(), Error> {
        loop {
            let end = read_frame(&mut self.reader, &mut self.rx).await?;
            let frame = trim(self.rx.frame(end));
            if frame.is_empty() {
                continue;
            }

            let env = match parse_envelope(frame) {
                Ok(env) => env,
                // Answer first, so the sender learns which of the two faults
                // it committed, then end the session for the reason above.
                Err(error) => {
                    let (code, message) = envelope_error(&error);
                    reply_error(&mut self.writer, &mut self.tx, None, code, message).await?;
                    return Err(error);
                }
            };

            match (env.method, env.id) {
                (Some(m), inbound_id) => {
                    dispatch_inbound(
                        &mut self.handler,
                        &mut self.writer,
                        &mut self.tx,
                        frame,
                        m,
                        inbound_id,
                    )
                    .await?;
                }
                (None, Some(_)) => {} // unsolicited response: drop
                (None, None) => {
                    reply_error(
                        &mut self.writer,
                        &mut self.tx,
                        None,
                        codes::INVALID_REQUEST,
                        "invalid request",
                    )
                    .await?;
                    return Err(Error::InvalidRequest);
                }
            }
            return Ok(());
        }
    }

    async fn send_request<P>(
        &mut self,
        method: &str,
        params: Option<&P>,
        id: Option<&i64>,
    ) -> Result<(), Error>
    where
        P: Serialize + ?Sized,
    {
        let msg = OutRequest {
            jsonrpc: VERSION,
            method,
            params,
            id,
        };
        let len = serde_json_core::to_slice(&msg, &mut self.tx).map_err(|_| Error::Overflow)?;
        write_frame(&mut self.writer, &self.tx[..len]).await
    }
}

/// Parse the first-pass envelope and validate the protocol version.
///
/// The two failure modes are kept apart, because JSON-RPC gives them
/// different codes and a caller told the wrong one cannot act on it:
///
/// * [`Error::Parse`] (`-32700`) — the frame is not JSON this receiver can
///   parse, or it is a batch, which is unsupported and therefore malformed
///   traffic here.
/// * [`Error::InvalidRequest`] (`-32600`) — the frame *is* a JSON object, but
///   not a valid envelope: wrong or missing `jsonrpc`, an explicit
///   `"id": null`, or an `id` that is not a signed 64-bit JSON integer.
fn parse_envelope(frame: &[u8]) -> Result<Envelope<'_>, Error> {
    // An explicit null id. A notification must omit `id` entirely, so this is
    // never a notification, and it names no request either.
    if serde_json_core::from_slice::<EnvelopeNullId>(frame).is_ok() {
        return Err(Error::InvalidRequest);
    }

    let (version, env) = match serde_json_core::from_slice::<EnvelopeNumId<'_>>(frame) {
        Ok((e, _)) => (
            e.jsonrpc,
            Envelope {
                method: e.method,
                id: e.id,
            },
        ),
        // A present id that cannot be decoded as i64 is not valid for the
        // JSON-RPC API. If the frame is nonetheless a JSON object, classify the
        // fault as an invalid request rather than a JSON parse error.
        Err(_) => {
            return Err(match serde_json_core::from_slice::<AnyObject>(frame) {
                Ok(_) => Error::InvalidRequest,
                Err(_) => Error::Parse,
            });
        }
    };
    match version {
        Some(VERSION) => Ok(env),
        _ => Err(Error::InvalidRequest),
    }
}

/// The JSON-RPC code and message for an envelope that could not be parsed.
fn envelope_error(error: &Error) -> (i32, &'static str) {
    match error {
        Error::InvalidRequest => (codes::INVALID_REQUEST, "invalid request"),
        _ => (codes::PARSE_ERROR, "parse error"),
    }
}

/// Read until a complete `\n`-terminated frame is buffered; returns the
/// index of the terminator within the buffer.
///
/// Each read is capped at the buffer's remaining capacity. Without that cap a
/// read could pull in bytes belonging to the *next* frame and overflow on
/// them, so whether a conforming frame was accepted would depend on where the
/// transport happened to split its reads — a frame arriving alone would fit
/// while the same frame pipelined behind another would not.
///
/// Overflow is reported only when the buffer is genuinely full with no
/// newline in it, which is the real oversized-frame condition.
#[maybe_async::maybe_async]
async fn read_frame<R: Read, const N: usize>(
    reader: &mut R,
    buf: &mut FrameBuf<N>,
) -> Result<usize, Error> {
    buf.advance();
    loop {
        if let Some(end) = buf.find_frame() {
            return Ok(end);
        }
        let mut chunk = [0u8; 64];
        let room = buf.remaining_capacity().min(chunk.len());
        if room == 0 {
            // The buffer holds N bytes and none of them is a newline.
            return Err(Error::Overflow);
        }
        let n = reader
            .read(&mut chunk[..room])
            .await
            .map_err(|e| Error::Io(e.kind()))?;
        if n == 0 {
            return Err(Error::Eof);
        }
        buf.push_chunk(&chunk[..n])?;
    }
}

/// Write one frame followed by the `\n` terminator and flush.
#[maybe_async::maybe_async]
async fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), Error> {
    writer
        .write_all(payload)
        .await
        .map_err(|e| Error::Io(e.kind()))?;
    writer
        .write_all(b"\n")
        .await
        .map_err(|e| Error::Io(e.kind()))?;
    writer.flush().await.map_err(|e| Error::Io(e.kind()))
}

/// Serialize and send an error response.
#[maybe_async::maybe_async]
async fn reply_error<W: Write>(
    writer: &mut W,
    tx: &mut [u8],
    id: Option<&i64>,
    code: i32,
    message: &str,
) -> Result<(), Error> {
    let len = write_error(tx, id, code, message)?;
    write_frame(writer, &tx[..len]).await
}

/// Dispatch an incoming request or notification to the handler and send the
/// response, if any.
#[maybe_async::maybe_async]
async fn dispatch_inbound<W: Write, H: Handler>(
    handler: &mut H,
    writer: &mut W,
    tx: &mut [u8],
    frame: &[u8],
    method: &str,
    id: Option<i64>,
) -> Result<(), Error> {
    let params = Params { raw: frame };
    match id {
        None => {
            handler.handle_notification(method, params);
            Ok(())
        }
        Some(id) => {
            let responder = Responder { out: tx, id: &id };
            let reply = handler.handle_request(method, params, responder);
            let len = match reply.res {
                Ok(len) => len,
                // The handler's reply did not fit into the TX buffer:
                // fall back to a (small) internal error response.
                Err(_) => write_error(tx, Some(&id), codes::INTERNAL_ERROR, "internal error")?,
            };
            write_frame(writer, &tx[..len]).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_envelope;
    use crate::Error;

    #[test]
    fn envelope_accepts_full_i64_id_range() {
        let cases: [(&[u8], i64); 2] = [
            (
                br#"{"jsonrpc":"2.0","id":-9223372036854775808,"method":"min"}"#,
                i64::MIN,
            ),
            (
                br#"{"jsonrpc":"2.0","id":9223372036854775807,"method":"max"}"#,
                i64::MAX,
            ),
        ];
        for (frame, expected) in cases {
            let env = parse_envelope(frame).expect("i64 id must be valid");
            assert_eq!(env.id, Some(expected));
        }
    }

    #[test]
    fn envelope_rejects_non_i64_ids() {
        let cases: [&[u8]; 4] = [
            br#"{"jsonrpc":"2.0","id":"1","method":"bad"}"#,
            br#"{"jsonrpc":"2.0","id":1.5,"method":"bad"}"#,
            br#"{"jsonrpc":"2.0","id":9223372036854775808,"method":"bad"}"#,
            br#"{"jsonrpc":"2.0","id":-9223372036854775809,"method":"bad"}"#,
        ];
        for frame in cases {
            assert!(matches!(parse_envelope(frame), Err(Error::InvalidRequest)));
        }
    }
}
