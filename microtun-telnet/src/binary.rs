//! TELNET Binary Transmission byte-stream adapter.
//!
//! This module owns the reusable transport glue needed by binary application protocols such as
//! YMODEM. It negotiates RFC 856 BINARY in both directions, strips TELNET command framing on
//! reads, and escapes IAC bytes on writes. Timeout and application-protocol policy stay with the
//! caller.

use core::fmt;

use embedded_io_async::{Error, ErrorKind, ErrorType, Read, Write};
use heapless::{Deque, Vec};

use crate::{OPT_BINARY, Policy, Telnet, TelnetEvent};

/// Error while entering or using TELNET Binary Transmission mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BinaryModeError<E> {
    /// The underlying transport returned an I/O error.
    Io(E),
    /// The underlying byte stream ended.
    Disconnected,
    /// The peer explicitly rejected BINARY in at least one direction.
    Refused,
    /// More application data arrived during BINARY negotiation than the bounded handoff queue can
    /// preserve. Ordinary early data is buffered and does not produce this error.
    UnexpectedData,
}

impl<E> fmt::Display for BinaryModeError<E>
where
    E: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "TELNET binary transport error: {error}"),
            Self::Disconnected => f.write_str("TELNET binary transport disconnected"),
            Self::Refused => f.write_str("peer refused TELNET BINARY mode"),
            Self::UnexpectedData => {
                f.write_str("too much application data arrived during TELNET BINARY negotiation")
            }
        }
    }
}

impl<E> core::error::Error for BinaryModeError<E> where E: core::error::Error {}

impl<E> Error for BinaryModeError<E>
where
    E: Error,
{
    fn kind(&self) -> ErrorKind {
        match self {
            Self::Io(error) => error.kind(),
            Self::Disconnected | Self::Refused | Self::UnexpectedData => ErrorKind::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct BinaryPolicy;

impl Policy for BinaryPolicy {
    fn support_us(&self, option: u8) -> bool {
        option == OPT_BINARY
    }

    fn support_him(&self, option: u8) -> bool {
        option == OPT_BINARY
    }
}

/// TELNET state required by [`BinaryMode`].
///
/// Implementations can wrap a larger connection-level TELNET session. This lets a binary
/// application borrow the exact same RFC 1143 state that was used by an interactive shell rather
/// than starting a second, contradictory negotiation state machine on the same TCP connection.
pub trait BinaryTelnet {
    /// Whether RFC 856 BINARY is enabled in both directions.
    fn binary_mode_enabled(&self) -> bool;

    /// Whether a requested BINARY enable has been rejected in either direction.
    fn binary_mode_refused(&self) -> bool;

    /// Request RFC 856 BINARY in both directions.
    fn request_binary_mode(&mut self, out: &mut Vec<u8, 6>);

    /// Request a return to NVT mode in both directions.
    fn disable_binary_mode(&mut self, out: &mut Vec<u8, 6>);

    /// Feed one wire byte through the connection's TELNET parser.
    ///
    /// Any required TELNET reply is appended to `reply`. Application data is returned after IAC
    /// unescaping; all TELNET command events remain owned by the implementation.
    fn feed_binary(&mut self, byte: u8, reply: &mut Vec<u8, 16>) -> Option<u8>;
}

impl<P, const SB_CAP: usize, const OPTION_CAP: usize> BinaryTelnet for Telnet<P, SB_CAP, OPTION_CAP>
where
    P: Policy,
{
    fn binary_mode_enabled(&self) -> bool {
        Telnet::binary_mode_enabled(self)
    }

    fn binary_mode_refused(&self) -> bool {
        Telnet::binary_mode_refused(self)
    }

    fn request_binary_mode(&mut self, out: &mut Vec<u8, 6>) {
        Telnet::request_binary_mode(self, out);
    }

    fn disable_binary_mode(&mut self, out: &mut Vec<u8, 6>) {
        Telnet::disable_binary_mode(self, out);
    }

    fn feed_binary(&mut self, byte: u8, reply: &mut Vec<u8, 16>) -> Option<u8> {
        match Telnet::feed(self, byte, reply) {
            Some(TelnetEvent::Data(byte)) => Some(byte),
            _ => None,
        }
    }
}

impl<C> BinaryTelnet for &mut C
where
    C: BinaryTelnet + ?Sized,
{
    fn binary_mode_enabled(&self) -> bool {
        (**self).binary_mode_enabled()
    }

    fn binary_mode_refused(&self) -> bool {
        (**self).binary_mode_refused()
    }

    fn request_binary_mode(&mut self, out: &mut Vec<u8, 6>) {
        (**self).request_binary_mode(out);
    }

    fn disable_binary_mode(&mut self, out: &mut Vec<u8, 6>) {
        (**self).disable_binary_mode(out);
    }

    fn feed_binary(&mut self, byte: u8, reply: &mut Vec<u8, 16>) -> Option<u8> {
        (**self).feed_binary(byte, reply)
    }
}

/// Private-policy TELNET state used by [`BinaryMode::new`].
///
/// Most connection-oriented applications should prefer [`BinaryMode::with_telnet`] so BINARY
/// negotiation shares state with the surrounding TELNET session.
pub struct StandaloneBinaryTelnet {
    protocol: Telnet<BinaryPolicy, 1, 4>,
}

impl StandaloneBinaryTelnet {
    const fn new() -> Self {
        Self {
            protocol: Telnet::new(BinaryPolicy),
        }
    }
}

impl BinaryTelnet for StandaloneBinaryTelnet {
    fn binary_mode_enabled(&self) -> bool {
        self.protocol.binary_mode_enabled()
    }

    fn binary_mode_refused(&self) -> bool {
        self.protocol.binary_mode_refused()
    }

    fn request_binary_mode(&mut self, out: &mut Vec<u8, 6>) {
        self.protocol.request_binary_mode(out);
    }

    fn disable_binary_mode(&mut self, out: &mut Vec<u8, 6>) {
        self.protocol.disable_binary_mode(out);
    }

    fn feed_binary(&mut self, byte: u8, reply: &mut Vec<u8, 16>) -> Option<u8> {
        match self.protocol.feed(byte, reply) {
            Some(TelnetEvent::Data(byte)) => Some(byte),
            _ => None,
        }
    }
}

/// Write TELNET application data, escaping IAC bytes on the wire, without flushing.
///
/// This is the common framing primitive for interactive TELNET writers and [`BinaryMode`].
/// Callers that batch writes can defer flushing until the end of a logical record.
pub async fn write_data_unflushed<T: Write + ?Sized>(
    io: &mut T,
    bytes: &[u8],
) -> Result<(), T::Error> {
    let mut start = 0;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte != crate::IAC {
            continue;
        }
        if start < index {
            io.write_all(&bytes[start..index]).await?;
        }
        io.write_all(&[crate::IAC, crate::IAC]).await?;
        start = index + 1;
    }
    if start < bytes.len() {
        io.write_all(&bytes[start..]).await?;
    }
    Ok(())
}

/// Write TELNET application data, escaping IAC bytes on the wire, then flush.
pub async fn write_data<T: Write + ?Sized>(io: &mut T, bytes: &[u8]) -> Result<(), T::Error> {
    write_data_unflushed(io, bytes).await?;
    io.flush().await
}

/// A TELNET byte-stream adapter for Binary Transmission in both directions.
///
/// Call [`BinaryMode::negotiate`] before exchanging application data. For a standalone stream,
/// [`BinaryMode::new`] owns a minimal TELNET state machine. On an established TELNET connection,
/// use [`BinaryMode::with_telnet`] to borrow the existing connection-level state so option state is
/// preserved across shell/binary/shell handoffs.
///
/// Reads discard TELNET commands and unescape doubled IAC bytes; writes escape IAC while otherwise
/// preserving every payload byte. The caller owns timeout policy.
pub struct BinaryMode<'a, T: ?Sized, C = StandaloneBinaryTelnet> {
    io: &'a mut T,
    telnet: C,
    pending: Deque<u8, 64>,
}

impl<'a, T> BinaryMode<'a, T, StandaloneBinaryTelnet>
where
    T: Read + Write + ?Sized,
{
    /// Create a standalone binary-mode adapter without sending any TELNET commands yet.
    ///
    /// Use [`BinaryMode::with_telnet`] instead when `io` is already part of a TELNET session.
    pub fn new(io: &'a mut T) -> Self {
        Self {
            io,
            telnet: StandaloneBinaryTelnet::new(),
            pending: Deque::new(),
        }
    }
}

impl<'a, T, C> BinaryMode<'a, T, &'a mut C>
where
    T: Read + Write + ?Sized,
    C: BinaryTelnet + ?Sized,
{
    /// Borrow an established connection's TELNET negotiation/parser state.
    pub fn with_telnet(io: &'a mut T, telnet: &'a mut C) -> Self {
        Self {
            io,
            telnet,
            pending: Deque::new(),
        }
    }
}

impl<T, C> BinaryMode<'_, T, C>
where
    T: Read + Write + ?Sized,
    C: BinaryTelnet,
{
    /// Request BINARY in both directions and wait until the peer has accepted it.
    ///
    /// TELNET application bytes that arrive while the two independent negotiations are settling
    /// are preserved and returned by later reads rather than being treated as a TELNET protocol
    /// error. The queue is intentionally bounded for `no_std` targets.
    ///
    /// No timeout is imposed here. Callers that need a deadline should wrap this future with their
    /// runtime's timeout primitive. Keeping the adapter outside that timeout future lets the caller
    /// run [`BinaryMode::abort`] if the deadline expires.
    pub async fn negotiate(&mut self) -> Result<(), BinaryModeError<T::Error>> {
        let mut request = Vec::<u8, 6>::new();
        self.telnet.request_binary_mode(&mut request);
        if !request.is_empty() {
            self.raw_write(request.as_slice()).await?;
        }

        while !self.telnet.binary_mode_enabled() {
            if self.telnet.binary_mode_refused() {
                return Err(BinaryModeError::Refused);
            }

            let byte = self.wire_byte().await?;
            if let Some(data) = self.feed_wire_byte(byte).await?
                && self.pending.push_back(data).is_err()
            {
                return Err(BinaryModeError::UnexpectedData);
            }
        }

        Ok(())
    }

    async fn raw_write(&mut self, bytes: &[u8]) -> Result<(), BinaryModeError<T::Error>> {
        self.io
            .write_all(bytes)
            .await
            .map_err(BinaryModeError::Io)?;
        self.io.flush().await.map_err(BinaryModeError::Io)
    }

    /// Read exactly one wire byte.
    ///
    /// Deliberately avoiding transport read-ahead makes mode handoff cancellation-safe: destroying
    /// the adapter cannot discard bytes that have already been pulled out of the TCP stream but
    /// not yet consumed by the TELNET parser/application protocol.
    async fn wire_byte(&mut self) -> Result<u8, BinaryModeError<T::Error>> {
        let mut byte = [0u8; 1];
        let read = self.io.read(&mut byte).await.map_err(BinaryModeError::Io)?;
        if read == 0 {
            return Err(BinaryModeError::Disconnected);
        }
        Ok(byte[0])
    }

    async fn feed_wire_byte(&mut self, byte: u8) -> Result<Option<u8>, BinaryModeError<T::Error>> {
        let mut reply = Vec::<u8, 16>::new();
        let data = self.telnet.feed_binary(byte, &mut reply);
        if !reply.is_empty() {
            self.raw_write(reply.as_slice()).await?;
        }
        Ok(data)
    }

    async fn step(&mut self) -> Result<Option<u8>, BinaryModeError<T::Error>> {
        let byte = self.wire_byte().await?;
        self.feed_wire_byte(byte).await
    }

    /// Read one application byte, removing TELNET command framing.
    pub async fn read_byte(&mut self) -> Result<u8, BinaryModeError<T::Error>> {
        if let Some(byte) = self.pending.pop_front() {
            return Ok(byte);
        }
        loop {
            if let Some(byte) = self.step().await? {
                return Ok(byte);
            }
        }
    }

    /// Write application bytes, escaping IAC as required by TELNET even in BINARY mode.
    pub async fn write_all(&mut self, bytes: &[u8]) -> Result<(), BinaryModeError<T::Error>> {
        write_data(self.io, bytes)
            .await
            .map_err(BinaryModeError::Io)
    }

    async fn request_nvt_mode(&mut self) -> Result<(), BinaryModeError<T::Error>> {
        let mut request = Vec::<u8, 6>::new();
        self.telnet.disable_binary_mode(&mut request);
        if request.is_empty() {
            Ok(())
        } else {
            self.raw_write(request.as_slice()).await
        }
    }

    /// Ask the peer to leave BINARY mode in both directions.
    ///
    /// This sends whatever transitions RFC 1143 requires for the current connection state and does
    /// not wait for acknowledgements. A following interactive TELNET session can consume those
    /// replies using the same state machine.
    pub async fn finish(mut self) -> Result<(), BinaryModeError<T::Error>> {
        self.request_nvt_mode().await
    }

    /// Cancel a partial BINARY negotiation through the same RFC 1143 state machine.
    ///
    /// In particular, this does not inject unconditional `WONT BINARY`/`DONT BINARY` while an
    /// enable is outstanding. The Q-method records the requested reversal and emits the necessary
    /// command when the peer's in-flight response arrives.
    pub async fn abort(mut self) -> Result<(), BinaryModeError<T::Error>> {
        self.request_nvt_mode().await
    }
}

impl<T, C> ErrorType for BinaryMode<'_, T, C>
where
    T: Read + Write + ?Sized,
    T::Error: Error,
    C: BinaryTelnet,
{
    type Error = BinaryModeError<T::Error>;
}

impl<T, C> Read for BinaryMode<'_, T, C>
where
    T: Read + Write + ?Sized,
    T::Error: Error,
    C: BinaryTelnet,
{
    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        if buffer.is_empty() {
            return Ok(0);
        }
        buffer[0] = self.read_byte().await?;
        Ok(1)
    }
}

impl<T, C> Write for BinaryMode<'_, T, C>
where
    T: Read + Write + ?Sized,
    T::Error: Error,
    C: BinaryTelnet,
{
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, Self::Error> {
        self.write_all(bytes).await?;
        Ok(bytes.len())
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        self.io.flush().await.map_err(BinaryModeError::Io)
    }
}
