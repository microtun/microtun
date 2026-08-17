//! The message-level API: one [`Connection`] per socket, and a write-only
//! [`Sender`] for the case where a second task must push messages onto it.
//!
//! # Receiving is resumable
//!
//! [`Connection::recv_text`] is written as a state machine over `read` rather
//! than as a straight-line sequence of `read_exact` calls, and the reason is
//! cancellation. Both Microtun resolvers wait on the connection and on a
//! command channel at once, so the receive future is dropped every time a
//! command wins the race — routinely, not exceptionally. A receiver that held
//! partial frame state on the stack would lose it there, and the next receive
//! would resume in the middle of a frame it no longer knew it was inside.
//!
//! So every byte this connection reads is committed to the connection's own
//! state before the next await point: the frame header accumulates in
//! [`Connection`], the payload goes straight into the caller's buffer with the
//! byte count kept here, and the masking offset rides along with it. Dropping
//! the future between two reads loses nothing, and the following call picks up
//! mid-frame.
//!
//! That guarantee rests on the transport's own `read` being cancel-safe, which
//! is true of a Tokio socket and of an `embassy-net` socket, and it covers the
//! reading half only. If a receive is cancelled while it is *writing* — which
//! it does only to answer a ping — the outgoing frame may be left partial and
//! the connection has to be dropped, like any interrupted write.

use embedded_io_async::{Error as _, Read, Write};
use rand_core::{CryptoRng, RngCore};

use crate::{
    Role,
    error::{CloseCode, Error},
    frame::{
        MAX_CONTROL_PAYLOAD_LEN, MAX_HEADER_LEN, decode_len, decode_prefix, encode_header,
        extended_len_bytes, is_control, opcode,
    },
    handshake::{ClientRequest, client_handshake},
    io::{flush, write_all},
    mask::{self, Masker},
};

/// Bytes masked per write on the client side.
///
/// Masking rewrites the payload, and the payload belongs to the caller, so the
/// bytes are copied through a small stack buffer instead. This is the size of
/// that buffer: large enough that a control-plane message costs a handful of
/// writes, small enough to sit on an embedded task's stack.
const MASK_CHUNK_LEN: usize = 64;

/// The write half of a WebSocket connection.
///
/// A [`Connection`] contains one of these. It is also constructible on its own
/// so that a server can hold a [`Connection`] in a reading task and a `Sender`
/// in a task that pushes notifications, sharing one writer between them.
///
/// **Sharing a writer requires whole-message exclusion.** One message is
/// several `write` calls — a header, then the payload, possibly in masked
/// chunks — and two senders interleaving those calls would produce a byte
/// stream that is not a valid frame sequence. A shared writer must therefore
/// hold its lock from the first byte of a message through the flush that ends
/// it, not per `write` call.
#[derive(Debug)]
pub struct Sender<W> {
    writer: W,
    role: Role,
    /// Present only for a client. Servers never create masking state because
    /// RFC 6455 requires their outgoing frames to be unmasked.
    mask: Option<Masker>,
    closed: bool,
}

impl<W> Sender<W> {
    /// A server-side sender: sends unmasked frames.
    pub fn server(writer: W) -> Self {
        Self {
            writer,
            role: Role::Server,
            mask: None,
            closed: false,
        }
    }

    /// A client-side sender seeded from a caller-provided cryptographic RNG.
    ///
    /// The RNG is used only while constructing the sender. A ChaCha20 CSPRNG
    /// seeded from it is retained for future frame masking keys, so the caller
    /// does not have to lend its RNG to the connection for its whole lifetime.
    pub fn client<R: RngCore + CryptoRng + ?Sized>(writer: W, rng: &mut R) -> Self {
        Self {
            writer,
            role: Role::Client,
            mask: Some(Masker::from_rng(rng)),
            closed: false,
        }
    }

    /// Whether this endpoint has already sent a close frame.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Recover the wrapped writer.
    pub fn into_inner(self) -> W {
        self.writer
    }
}

impl<W: Write> Sender<W> {
    /// Send one complete text message.
    ///
    /// The payload is written as a single unfragmented frame. Callers are
    /// expected to pass whole messages; nothing here splits one.
    pub async fn send_text(&mut self, payload: &[u8]) -> Result<(), Error> {
        if self.closed {
            return Err(Error::AlreadyClosed);
        }
        self.send_frame(opcode::TEXT, payload).await
    }

    /// Send a ping. The peer answers with a pong carrying the same payload.
    pub async fn send_ping(&mut self, payload: &[u8]) -> Result<(), Error> {
        if payload.len() > MAX_CONTROL_PAYLOAD_LEN {
            return Err(Error::TooLarge);
        }
        if self.closed {
            return Err(Error::AlreadyClosed);
        }
        self.send_frame(opcode::PING, payload).await
    }

    /// Send a close frame, after which this endpoint may not send again.
    ///
    /// Closing twice is not an error: the second call is a no-op, so a caller
    /// that closes on the way out of an error path does not have to know
    /// whether the error path had already closed.
    pub async fn close(&mut self, code: CloseCode, reason: &str) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        let mut payload = [0u8; MAX_CONTROL_PAYLOAD_LEN];
        payload[..2].copy_from_slice(&code.0.to_be_bytes());
        // A reason is advisory. Truncating one is better than failing to
        // close, which would leave the peer waiting for a frame that says why.
        let reason = reason.as_bytes();
        let len = reason.len().min(MAX_CONTROL_PAYLOAD_LEN - 2);
        payload[2..2 + len].copy_from_slice(&reason[..len]);

        let result = self.send_frame(opcode::CLOSE, &payload[..2 + len]).await;
        self.closed = true;
        result
    }

    async fn send_pong(&mut self, payload: &[u8]) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        self.send_frame(opcode::PONG, payload).await
    }

    async fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), Error> {
        let key = self.mask.as_mut().map(Masker::key);
        debug_assert_eq!(self.role.masks_output(), key.is_some());

        let mut header = [0u8; MAX_HEADER_LEN];
        let header_len = encode_header(&mut header, true, opcode, payload.len(), key);
        write_all(&mut self.writer, &header[..header_len]).await?;

        match key {
            None => write_all(&mut self.writer, payload).await?,
            Some(key) => {
                let mut chunk = [0u8; MASK_CHUNK_LEN];
                let mut offset = 0;
                for part in payload.chunks(MASK_CHUNK_LEN) {
                    let masked = &mut chunk[..part.len()];
                    masked.copy_from_slice(part);
                    offset = mask::apply(key, offset, masked);
                    write_all(&mut self.writer, masked).await?;
                }
            }
        }
        flush(&mut self.writer).await
    }
}

/// Where the reader is inside the frame stream.
///
/// This is the state that makes a cancelled receive resumable. It lives in the
/// [`Connection`] rather than on the receive future's stack, so dropping that
/// future loses nothing.
#[derive(Debug, Clone, Copy)]
enum Phase {
    /// Accumulating a frame header. `need` starts at the two fixed bytes and
    /// grows once those two say how much more there is.
    Header { have: usize, need: usize },
    /// Reading a data payload straight into the caller's buffer.
    Payload {
        remaining: usize,
        key: Option<[u8; 4]>,
        offset: usize,
        fin: bool,
    },
    /// Reading a control payload into the connection's own small buffer.
    Control {
        opcode: u8,
        have: usize,
        remaining: usize,
        key: Option<[u8; 4]>,
    },
}

impl Phase {
    const fn header() -> Self {
        Phase::Header { have: 0, need: 2 }
    }
}

/// A WebSocket connection over a byte-stream transport.
///
/// * `R`/`W`: the transport halves (`embedded-io-async`). With the `tokio`
///   feature, wrap raw Tokio halves in [`crate::TokioIo`].
///
/// The two constructors differ in where the handshake happens.
/// [`Connection::client`] performs it, because a client has nothing to decide
/// in between. [`Connection::server`] does not, because a server does: it
/// reads the request with [`crate::request_upgrade`], decides whether to serve
/// this caller, and only then either accepts or refuses. Building the
/// connection is the last step of that sequence, not the first.
#[derive(Debug)]
pub struct Connection<R, W> {
    reader: R,
    sender: Sender<W>,
    /// Header bytes read so far for the frame in progress.
    header: [u8; MAX_HEADER_LEN],
    /// Payload of the control frame in progress. Control payloads cannot go
    /// into the caller's buffer, because a ping may arrive between two
    /// fragments of a message that is still being assembled there.
    control: [u8; MAX_CONTROL_PAYLOAD_LEN],
    phase: Phase,
    /// Bytes of the current message assembled in the caller's buffer.
    filled: usize,
    /// Whether a non-final data frame has been seen for the current message.
    continuing: bool,
}

impl<R: Read, W: Write> Connection<R, W> {
    /// Open a client connection using a caller-provided cryptographic RNG.
    ///
    /// RFC 6455 requires client masking keys to be unpredictable. `rng`
    /// supplies the entropy for one per-connection ChaCha20 CSPRNG and is not
    /// retained after this call returns.
    ///
    /// `scratch` holds the HTTP head of both directions of the handshake and
    /// is not retained. 512 bytes is comfortable for the responses this
    /// crate's server sends.
    pub async fn client<RNG: RngCore + CryptoRng + ?Sized>(
        mut reader: R,
        mut writer: W,
        request: &ClientRequest<'_>,
        rng: &mut RNG,
        scratch: &mut [u8],
    ) -> Result<Self, Error> {
        let mut mask = Masker::from_rng(rng);
        client_handshake(&mut reader, &mut writer, request, &mut mask, scratch).await?;
        Ok(Self::wrap(
            reader,
            Sender {
                writer,
                role: Role::Client,
                mask: Some(mask),
                closed: false,
            },
        ))
    }

    /// Wrap a transport whose server-side handshake has already completed.
    ///
    /// The caller is responsible for having answered a
    /// [`crate::request_upgrade`] with [`crate::Upgrade::accept`] on this same
    /// transport. Wrapping a stream that has not been upgraded produces a
    /// connection whose first read fails as a protocol error.
    pub fn server(reader: R, writer: W) -> Self {
        Self::wrap(reader, Sender::server(writer))
    }

    fn wrap(reader: R, sender: Sender<W>) -> Self {
        Self {
            reader,
            sender,
            header: [0; MAX_HEADER_LEN],
            control: [0; MAX_CONTROL_PAYLOAD_LEN],
            phase: Phase::header(),
            filled: 0,
            continuing: false,
        }
    }

    /// The write half, for sending on a connection another task is reading.
    pub fn sender_mut(&mut self) -> &mut Sender<W> {
        &mut self.sender
    }

    /// Tear the connection apart again.
    pub fn into_parts(self) -> (R, W) {
        (self.reader, self.sender.into_inner())
    }

    /// Send one complete text message.
    pub async fn send_text(&mut self, payload: &[u8]) -> Result<(), Error> {
        self.sender.send_text(payload).await
    }

    /// Send a close frame.
    pub async fn close(&mut self, code: CloseCode, reason: &str) -> Result<(), Error> {
        self.sender.close(code, reason).await
    }

    /// Receive one complete text message into `buf`, returning its length.
    ///
    /// Control frames are handled here rather than surfaced: a ping is
    /// answered with a pong, a pong is discarded, and a close is echoed and
    /// then reported as [`Error::Closed`]. A caller therefore keeps a
    /// connection alive simply by continuing to receive on it.
    ///
    /// Fragmented messages are reassembled into `buf`. A message that does not
    /// fit is refused with a `1009` close rather than truncated.
    ///
    /// **Cancel-safe, with one condition:** dropping the returned future loses
    /// no received bytes, but the caller must pass the same `buf` to the next
    /// call, because a partly assembled message is sitting in it. Every
    /// consumer in this workspace owns one receive buffer for the life of the
    /// connection, which satisfies that by construction.
    ///
    /// The payload is not validated as UTF-8. Every consumer of this crate
    /// parses the payload as JSON immediately, and that parse rejects
    /// everything a UTF-8 check would, so the check would only be a second
    /// pass over the same bytes.
    pub async fn recv_text(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        match self.receive(buf).await {
            Ok(len) => Ok(len),
            Err(error) => {
                // Tell the peer why, when there is still a peer to tell. A
                // transport that has already failed cannot carry the reason,
                // and a peer that closed first has already been answered.
                if !matches!(
                    error,
                    Error::Eof | Error::Io(_) | Error::Closed(_) | Error::AlreadyClosed
                ) {
                    let _ = self.sender.close(error.close_code(), "").await;
                }
                Err(error)
            }
        }
    }

    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        loop {
            match self.phase {
                Phase::Header { have, need } => {
                    let read = fill(&mut self.reader, &mut self.header[have..need]).await?;
                    let have = have + read;
                    if have < need {
                        self.phase = Phase::Header { have, need };
                        continue;
                    }
                    // The first two bytes say how long the rest of the header
                    // is; anything past that is read on a later pass.
                    if need == 2 {
                        let prefix = decode_prefix([self.header[0], self.header[1]])?;
                        let full =
                            2 + extended_len_bytes(prefix.len7) + if prefix.masked { 4 } else { 0 };
                        if full > 2 {
                            self.phase = Phase::Header { have, need: full };
                            continue;
                        }
                    }
                    self.phase = self.begin_frame(need, buf.len())?;
                }

                Phase::Payload {
                    remaining,
                    key,
                    offset,
                    fin,
                } => {
                    if remaining == 0 {
                        self.phase = Phase::header();
                        if fin {
                            let len = self.filled;
                            self.filled = 0;
                            self.continuing = false;
                            return Ok(len);
                        }
                        self.continuing = true;
                        continue;
                    }
                    let end = self.filled + remaining;
                    let read = fill(&mut self.reader, &mut buf[self.filled..end]).await?;
                    let offset = match key {
                        Some(key) => {
                            mask::apply(key, offset, &mut buf[self.filled..self.filled + read])
                        }
                        None => 0,
                    };
                    self.filled += read;
                    self.phase = Phase::Payload {
                        remaining: remaining - read,
                        key,
                        offset,
                        fin,
                    };
                }

                Phase::Control {
                    opcode: control,
                    have,
                    remaining,
                    key,
                } => {
                    if remaining > 0 {
                        let end = have + remaining;
                        let read = fill(&mut self.reader, &mut self.control[have..end]).await?;
                        self.phase = Phase::Control {
                            opcode: control,
                            have: have + read,
                            remaining: remaining - read,
                            key,
                        };
                        continue;
                    }
                    // Unmask in one pass now the whole payload is here: a
                    // control payload is at most 125 bytes, so there is no
                    // running offset to carry.
                    if let Some(key) = key {
                        mask::apply(key, 0, &mut self.control[..have]);
                    }
                    self.phase = Phase::header();

                    match control {
                        opcode::PING => {
                            // The one write inside a receive, and therefore
                            // the one place a cancelled receive can leave a
                            // partial frame behind.
                            let mut payload = [0u8; MAX_CONTROL_PAYLOAD_LEN];
                            payload[..have].copy_from_slice(&self.control[..have]);
                            self.sender.send_pong(&payload[..have]).await?;
                        }
                        opcode::PONG => {}
                        _ => {
                            // A close frame carries an optional two-byte code.
                            let code = (have >= 2).then(|| {
                                CloseCode(u16::from_be_bytes([self.control[0], self.control[1]]))
                            });
                            // Answer the close, then report it. The peer is
                            // entitled to the echo (§5.5.1) and the caller is
                            // entitled to know the code it chose.
                            let _ = self
                                .sender
                                .close(code.unwrap_or(CloseCode::NORMAL), "")
                                .await;
                            return Err(Error::Closed(code));
                        }
                    }
                }
            }
        }
    }

    /// Validate a complete header and decide what comes next.
    ///
    /// `header_len` is how many header bytes were read, which is also where
    /// the masking key ends.
    fn begin_frame(&self, header_len: usize, capacity: usize) -> Result<Phase, Error> {
        let prefix = decode_prefix([self.header[0], self.header[1]])?;
        let extended = extended_len_bytes(prefix.len7);
        let len = decode_len(prefix.len7, &self.header[2..2 + extended])?;

        // A client masks; a server does not. Either end must close on the
        // other getting this wrong (RFC 6455 §5.1), because an endpoint that
        // masks when it should not is not framing by these rules at all and
        // every following frame would be misread.
        if prefix.masked != self.sender.role.requires_masked_input() {
            return Err(Error::Protocol);
        }
        let key = if prefix.masked {
            let mut key = [0u8; 4];
            key.copy_from_slice(&self.header[header_len - 4..header_len]);
            Some(key)
        } else {
            None
        };

        if is_control(prefix.opcode) {
            if !prefix.fin || len > MAX_CONTROL_PAYLOAD_LEN {
                return Err(Error::Protocol);
            }
            return Ok(Phase::Control {
                opcode: prefix.opcode,
                have: 0,
                remaining: len,
                key,
            });
        }

        match prefix.opcode {
            // A new data frame while a message is still open, or a
            // continuation with no message to continue: either way the sender
            // and this receiver disagree about where the message began.
            opcode::TEXT if self.continuing => return Err(Error::Protocol),
            opcode::CONTINUATION if !self.continuing => return Err(Error::Protocol),
            opcode::TEXT | opcode::CONTINUATION => {}
            _ => return Err(Error::UnsupportedData),
        }

        if len > capacity.saturating_sub(self.filled) {
            return Err(Error::TooLarge);
        }
        Ok(Phase::Payload {
            remaining: len,
            key,
            offset: 0,
            fin: prefix.fin,
        })
    }
}

/// One `read` into `buf`, mapped onto this crate's errors.
///
/// Deliberately *not* `read_exact`: a short read is normal and the caller
/// commits what it got before awaiting again, which is what makes the receive
/// path resumable. An empty buffer is never passed, so `Ok(0)` is end of
/// stream.
async fn fill<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, Error> {
    match reader.read(buf).await {
        Ok(0) => Err(Error::Eof),
        Ok(read) => Ok(read),
        Err(error) => Err(Error::Io(error.kind())),
    }
}
