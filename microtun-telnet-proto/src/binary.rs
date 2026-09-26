//! TELNET Binary Transmission byte-stream adapter.
//!
//! This module owns the reusable transport glue needed by binary application protocols such as
//! YMODEM. It negotiates RFC 856 BINARY in both directions, strips TELNET command framing on
//! reads, and escapes IAC bytes on writes. Timeout and application-protocol policy stay with the
//! caller.

use core::fmt;

use embedded_io_async::{Error, ErrorKind, ErrorType, Read, Write};
use heapless::Vec;

use crate::{DONT, IAC, OPT_BINARY, Policy, Telnet, TelnetEvent, WONT};

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
    /// Application data arrived before BINARY had been agreed in both directions.
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
                f.write_str("application data received before TELNET BINARY negotiation completed")
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
        if byte != IAC {
            continue;
        }
        if start < index {
            io.write_all(&bytes[start..index]).await?;
        }
        io.write_all(&[IAC, IAC]).await?;
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
/// Call [`BinaryMode::negotiate`] before exchanging application data. `BinaryMode` owns only the
/// BINARY negotiation and TELNET framing state for the duration of a binary application protocol
/// such as YMODEM. Reads discard TELNET commands and unescape doubled IAC bytes; writes escape IAC
/// while otherwise preserving every payload byte.
///
/// The caller owns timeout policy. That keeps this adapter runtime-agnostic and lets an embedding
/// application distinguish, for example, a short YMODEM startup timeout from a longer in-transfer
/// timeout.
pub struct BinaryMode<'a, T: ?Sized> {
    io: &'a mut T,
    telnet: Telnet<BinaryPolicy, 1, 4>,
    wire: [u8; 64],
    wire_start: usize,
    wire_end: usize,
}

impl<'a, T> BinaryMode<'a, T>
where
    T: Read + Write + ?Sized,
{
    /// Create a binary-mode adapter without sending any TELNET commands yet.
    pub fn new(io: &'a mut T) -> Self {
        Self {
            io,
            telnet: Telnet::new(BinaryPolicy),
            wire: [0; 64],
            wire_start: 0,
            wire_end: 0,
        }
    }

    /// Request BINARY in both directions and wait until the peer has accepted it.
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

            // Read exactly one wire byte while negotiating. Callers commonly wrap this future in
            // a timeout; avoiding read-ahead means cancellation cannot discard bytes that belong
            // to the following shell or binary protocol.
            let mut byte = [0u8; 1];
            let read = self.io.read(&mut byte).await.map_err(BinaryModeError::Io)?;
            if read == 0 {
                return Err(BinaryModeError::Disconnected);
            }
            if self.feed_wire_byte(byte[0]).await?.is_some() {
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

    async fn wire_byte(&mut self) -> Result<u8, BinaryModeError<T::Error>> {
        if self.wire_start == self.wire_end {
            let read = self
                .io
                .read(&mut self.wire)
                .await
                .map_err(BinaryModeError::Io)?;
            if read == 0 {
                return Err(BinaryModeError::Disconnected);
            }
            self.wire_start = 0;
            self.wire_end = read;
        }

        let byte = self.wire[self.wire_start];
        self.wire_start += 1;
        Ok(byte)
    }

    async fn feed_wire_byte(&mut self, byte: u8) -> Result<Option<u8>, BinaryModeError<T::Error>> {
        let mut reply = Vec::<u8, 6>::new();
        let event = self.telnet.feed(byte, &mut reply);
        if !reply.is_empty() {
            self.raw_write(reply.as_slice()).await?;
        }

        Ok(match event {
            Some(TelnetEvent::Data(byte)) => Some(byte),
            _ => None,
        })
    }

    async fn step(&mut self) -> Result<Option<u8>, BinaryModeError<T::Error>> {
        let byte = self.wire_byte().await?;
        self.feed_wire_byte(byte).await
    }

    /// Read one application byte, removing TELNET command framing.
    pub async fn read_byte(&mut self) -> Result<u8, BinaryModeError<T::Error>> {
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

    /// Ask the peer to leave BINARY mode in both directions.
    ///
    /// This sends the disable requests but deliberately does not wait for acknowledgements. A
    /// following interactive TELNET session can consume those replies normally.
    pub async fn finish(mut self) -> Result<(), BinaryModeError<T::Error>> {
        let mut request = Vec::<u8, 6>::new();
        self.telnet.disable_binary_mode(&mut request);
        if request.is_empty() {
            Ok(())
        } else {
            self.raw_write(request.as_slice()).await
        }
    }

    /// Cancel a partial BINARY negotiation and explicitly request NVT mode in both directions.
    ///
    /// Unlike [`BinaryMode::finish`], this deliberately sends `WONT`/`DONT` even when the RFC-1143
    /// state machine is still waiting for an earlier response. It is intended for timeout and
    /// error cleanup immediately before returning ownership of the transport to a text protocol.
    pub async fn abort(mut self) -> Result<(), BinaryModeError<T::Error>> {
        self.raw_write(&[IAC, WONT, OPT_BINARY, IAC, DONT, OPT_BINARY])
            .await
    }
}

impl<T> ErrorType for BinaryMode<'_, T>
where
    T: Read + Write + ?Sized,
    T::Error: Error,
{
    type Error = BinaryModeError<T::Error>;
}

impl<T> Read for BinaryMode<'_, T>
where
    T: Read + Write + ?Sized,
    T::Error: Error,
{
    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        if buffer.is_empty() {
            return Ok(0);
        }
        buffer[0] = self.read_byte().await?;
        Ok(1)
    }
}

impl<T> Write for BinaryMode<'_, T>
where
    T: Read + Write + ?Sized,
    T::Error: Error,
{
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, Self::Error> {
        self.write_all(bytes).await?;
        Ok(bytes.len())
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        self.io.flush().await.map_err(BinaryModeError::Io)
    }
}
