//! Shared firmware-transfer plumbing for the board examples.
//!
//! Both examples receive firmware the same way: the CLI hands its accepted
//! `TcpSocket` over, the session is switched to TELNET binary mode in both
//! directions, and a YMODEM-1K/CRC transfer carries a signed MCUboot envelope
//! whose native payload is streamed into the inactive slot while it is
//! authenticated.
//!
//! Everything above the flash is identical between targets and lives here. What
//! stays in each example is the part that genuinely differs: the slot layout,
//! the [`PayloadSink`] implementation over that slot, the read-back view of it,
//! and the bootloader's own rollback bookkeeping.

use embassy_net::tcp::TcpSocket;
use embassy_time::{Duration, with_timeout};
use microtun_mcuboot::{FeedError as McubootFeedError, PayloadSink, StreamingVerifier};
use microtun_ymodem::{
    BufferSink, Config as YmodemConfig, Error as YmodemError, ReadError as YmodemReadError,
    Sink as YmodemSink, Transport as YmodemTransport,
};

const IAC: u8 = 0xff;
const SE: u8 = 0xf0;
const SB: u8 = 0xfa;
const WILL: u8 = 0xfb;
const WONT: u8 = 0xfc;
const DO: u8 = 0xfd;
const DONT: u8 = 0xfe;
const BINARY: u8 = 0x00;

/// How long the peer has to agree to binary mode before the transfer is
/// abandoned.
const BINARY_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(5);

/// Firmware slot/state summary shown by the `fw` command on both boards.
#[derive(Clone, Copy)]
pub struct FirmwareStatus {
    pub slot: &'static str,
    pub state: &'static str,
    pub trial: bool,
}

/// Errors that can come out of the shared transport, independent of target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TransferError {
    Io,
    Timeout,
    Cancelled,
    Ymodem,
    /// The peer answered the binary-mode request with `WONT`/`DONT`.
    BinaryModeRefused,
    /// The peer never answered the binary-mode request.
    BinaryModeTimeout,
    /// The peer sent payload bytes before binary mode was agreed.
    BinaryModeUnexpectedData,
}

pub fn transfer_error_text(error: TransferError) -> &'static str {
    match error {
        TransferError::Io => "TELNET connection ended",
        TransferError::Timeout => "YMODEM transfer timed out",
        TransferError::Cancelled => "YMODEM transfer cancelled",
        TransferError::Ymodem => "invalid YMODEM-1K/CRC transfer",
        TransferError::BinaryModeRefused => "client refused TELNET binary mode",
        TransferError::BinaryModeTimeout => "client did not answer the TELNET binary-mode request",
        TransferError::BinaryModeUnexpectedData => {
            "client sent data before agreeing to TELNET binary mode"
        }
    }
}

/// Error from streaming a signed image into a target sink.
#[derive(Debug, PartialEq, Eq)]
pub enum ImageTransferError<E> {
    Transfer(TransferError),
    Image(microtun_mcuboot::Error),
    Sink(E),
}

impl<E> From<TransferError> for ImageTransferError<E> {
    fn from(error: TransferError) -> Self {
        Self::Transfer(error)
    }
}

pub async fn socket_write_all(
    socket: &mut TcpSocket<'_>,
    mut bytes: &[u8],
) -> Result<(), TransferError> {
    while !bytes.is_empty() {
        let written = socket.write(bytes).await.map_err(|_| TransferError::Io)?;
        if written == 0 {
            return Err(TransferError::Io);
        }
        bytes = &bytes[written..];
    }
    socket.flush().await.map_err(|_| TransferError::Io)
}

/// Write payload bytes to a TELNET peer, escaping IAC as required.
pub async fn telnet_write_data(
    socket: &mut TcpSocket<'_>,
    bytes: &[u8],
) -> Result<(), TransferError> {
    let mut encoded = [0u8; 256];
    let mut input = 0;
    while input < bytes.len() {
        let mut output = 0;
        while input < bytes.len() && output < encoded.len() {
            let byte = bytes[input];
            if byte == IAC {
                if output + 2 > encoded.len() {
                    break;
                }
                encoded[output] = IAC;
                encoded[output + 1] = IAC;
                output += 2;
            } else {
                encoded[output] = byte;
                output += 1;
            }
            input += 1;
        }
        socket_write_all(socket, &encoded[..output]).await?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum TelnetBinaryState {
    Data,
    Iac,
    /// An `IAC WILL/WONT/DO/DONT` was seen; the byte held here is the verb and
    /// the next byte on the wire is the option it applies to.
    Negotiation(u8),
    Subnegotiation,
    SubnegotiationIac,
}

/// TELNET receive framing with enough state to answer "did the peer actually
/// agree to binary mode?".
pub struct TelnetBinaryRx {
    state: TelnetBinaryState,
    wire: [u8; 512],
    wire_start: usize,
    wire_end: usize,
    peer_will_binary: bool,
    peer_do_binary: bool,
    peer_refused_binary: bool,
}

impl Default for TelnetBinaryRx {
    fn default() -> Self {
        Self::new()
    }
}

impl TelnetBinaryRx {
    pub const fn new() -> Self {
        Self {
            state: TelnetBinaryState::Data,
            wire: [0; 512],
            wire_start: 0,
            wire_end: 0,
            peer_will_binary: false,
            peer_do_binary: false,
            peer_refused_binary: false,
        }
    }

    fn binary_agreed(&self) -> bool {
        self.peer_will_binary && self.peer_do_binary
    }

    async fn wire_byte(&mut self, socket: &mut TcpSocket<'_>) -> Result<u8, TransferError> {
        if self.wire_start == self.wire_end {
            let read = socket
                .read(&mut self.wire)
                .await
                .map_err(|_| TransferError::Io)?;
            if read == 0 {
                return Err(TransferError::Io);
            }
            self.wire_start = 0;
            self.wire_end = read;
        }

        let byte = self.wire[self.wire_start];
        self.wire_start += 1;
        Ok(byte)
    }
}

/// Consume exactly one byte from the wire.
///
/// Returns `Some(byte)` for payload data and `None` when the byte was part of
/// TELNET framing. Splitting it this way lets the negotiation loop observe
/// control bytes instead of silently swallowing them.
async fn telnet_step(
    socket: &mut TcpSocket<'_>,
    rx: &mut TelnetBinaryRx,
) -> Result<Option<u8>, TransferError> {
    let byte = rx.wire_byte(socket).await?;
    match rx.state {
        TelnetBinaryState::Data => {
            if byte == IAC {
                rx.state = TelnetBinaryState::Iac;
                Ok(None)
            } else {
                Ok(Some(byte))
            }
        }
        TelnetBinaryState::Iac => match byte {
            IAC => {
                rx.state = TelnetBinaryState::Data;
                Ok(Some(IAC))
            }
            WILL | WONT | DO | DONT => {
                rx.state = TelnetBinaryState::Negotiation(byte);
                Ok(None)
            }
            SB => {
                rx.state = TelnetBinaryState::Subnegotiation;
                Ok(None)
            }
            _ => {
                rx.state = TelnetBinaryState::Data;
                Ok(None)
            }
        },
        TelnetBinaryState::Negotiation(verb) => {
            if byte == BINARY {
                match verb {
                    // The peer will send binary.
                    WILL => rx.peer_will_binary = true,
                    // The peer accepts binary from us.
                    DO => rx.peer_do_binary = true,
                    WONT | DONT => rx.peer_refused_binary = true,
                    _ => {}
                }
            }
            rx.state = TelnetBinaryState::Data;
            Ok(None)
        }
        TelnetBinaryState::Subnegotiation => {
            if byte == IAC {
                rx.state = TelnetBinaryState::SubnegotiationIac;
            }
            Ok(None)
        }
        TelnetBinaryState::SubnegotiationIac => {
            rx.state = if byte == SE {
                TelnetBinaryState::Data
            } else {
                TelnetBinaryState::Subnegotiation
            };
            Ok(None)
        }
    }
}

async fn telnet_binary_byte(
    socket: &mut TcpSocket<'_>,
    rx: &mut TelnetBinaryRx,
) -> Result<u8, TransferError> {
    loop {
        if let Some(byte) = telnet_step(socket, rx).await? {
            return Ok(byte);
        }
    }
}

async fn await_binary_agreement(
    socket: &mut TcpSocket<'_>,
    rx: &mut TelnetBinaryRx,
) -> Result<(), TransferError> {
    while !rx.binary_agreed() {
        if rx.peer_refused_binary {
            return Err(TransferError::BinaryModeRefused);
        }
        if telnet_step(socket, rx).await?.is_some() {
            // Nothing should be sent before we ask for the first YMODEM block,
            // and anything that is cannot be framed correctly yet.
            return Err(TransferError::BinaryModeUnexpectedData);
        }
    }
    Ok(())
}

/// YMODEM transport over a TELNET session in binary mode.
pub struct TelnetYmodemTransport<'socket, 'net> {
    socket: &'socket mut TcpSocket<'net>,
    rx: TelnetBinaryRx,
}

impl<'socket, 'net> TelnetYmodemTransport<'socket, 'net> {
    pub const fn new(socket: &'socket mut TcpSocket<'net>) -> Self {
        Self {
            socket,
            rx: TelnetBinaryRx::new(),
        }
    }

    /// Ask the peer for binary mode in both directions and wait for it to
    /// agree.
    ///
    /// YMODEM carries arbitrary bytes, so a client still in NVT mode will
    /// mangle the transfer. Previously the request was sent and the answer
    /// ignored, which turned a client-side misconfiguration into a corrupt
    /// image that only failed later at signature verification.
    ///
    /// Note that this expects a fresh answer. A client that already enabled
    /// BINARY earlier in the same session may, per RFC 1143 loop avoidance,
    /// decline to answer a redundant request; the CLI's own negotiation does
    /// not touch BINARY, so that does not arise here.
    pub async fn negotiate_binary(&mut self) -> Result<(), TransferError> {
        socket_write_all(self.socket, &[IAC, WILL, BINARY, IAC, DO, BINARY]).await?;

        match with_timeout(
            BINARY_NEGOTIATION_TIMEOUT,
            await_binary_agreement(self.socket, &mut self.rx),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(TransferError::BinaryModeTimeout),
        }
    }
}

impl YmodemTransport for TelnetYmodemTransport<'_, '_> {
    type Error = TransferError;

    async fn read_byte(&mut self, timeout_ms: u32) -> Result<u8, YmodemReadError<Self::Error>> {
        match with_timeout(
            Duration::from_millis(u64::from(timeout_ms)),
            telnet_binary_byte(self.socket, &mut self.rx),
        )
        .await
        {
            Ok(Ok(byte)) => Ok(byte),
            Ok(Err(error)) => Err(YmodemReadError::Io(error)),
            Err(_) => Err(YmodemReadError::Timeout),
        }
    }

    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        socket_write_all(self.socket, bytes).await
    }
}

/// Adapter feeding YMODEM payload bytes through the MCUboot verifier and on
/// into the target's flash sink.
struct McubootYmodemSink<'a, S> {
    verifier: &'a mut StreamingVerifier,
    sink: &'a mut S,
}

impl<S: PayloadSink> YmodemSink for McubootYmodemSink<'_, S> {
    type Error = McubootFeedError<S::Error>;

    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.verifier.feed(bytes, self.sink)
    }
}

fn map_plain_ymodem_error<S>(error: YmodemError<TransferError, S>) -> TransferError {
    match error {
        YmodemError::Io(error) => error,
        YmodemError::Timeout => TransferError::Timeout,
        YmodemError::Cancelled => TransferError::Cancelled,
        YmodemError::Protocol | YmodemError::Sink(_) => TransferError::Ymodem,
    }
}

fn map_image_ymodem_error<E>(
    error: YmodemError<TransferError, McubootFeedError<E>>,
) -> ImageTransferError<E> {
    match error {
        YmodemError::Io(error) => ImageTransferError::Transfer(error),
        YmodemError::Timeout => ImageTransferError::Transfer(TransferError::Timeout),
        YmodemError::Cancelled => ImageTransferError::Transfer(TransferError::Cancelled),
        YmodemError::Protocol => ImageTransferError::Transfer(TransferError::Ymodem),
        YmodemError::Sink(McubootFeedError::Image(error)) => ImageTransferError::Image(error),
        YmodemError::Sink(McubootFeedError::Sink(error)) => ImageTransferError::Sink(error),
    }
}

/// Receive a YMODEM file into a plain RAM buffer, used for provisioning
/// records.
pub async fn receive_ymodem_buffer(
    socket: &mut TcpSocket<'_>,
    output: &mut [u8],
) -> Result<usize, TransferError> {
    let mut transport = TelnetYmodemTransport::new(socket);
    transport.negotiate_binary().await?;

    let mut sink = BufferSink::new(output);
    let transfer = microtun_ymodem::receive(&mut transport, &mut sink, YmodemConfig::default())
        .await
        .map_err(map_plain_ymodem_error)?;

    if !sink.is_complete() || sink.file_size() != Some(transfer.file_size) {
        return Err(TransferError::Ymodem);
    }
    Ok(transfer.file_size)
}

/// Receive a signed MCUboot envelope and stream its native payload into
/// `sink`, authenticating as it goes.
///
/// The image is verified but *not* activated here; the caller must read the
/// slot back with `microtun_mcuboot::verify_stored_image` and only then make
/// it bootable.
pub async fn receive_signed_image<S: PayloadSink>(
    socket: &mut TcpSocket<'_>,
    verifier: &mut StreamingVerifier,
    sink: &mut S,
) -> Result<(), ImageTransferError<S::Error>> {
    let mut transport = TelnetYmodemTransport::new(socket);
    transport.negotiate_binary().await?;

    let mut ymodem_sink = McubootYmodemSink { verifier, sink };
    microtun_ymodem::receive(&mut transport, &mut ymodem_sink, YmodemConfig::default())
        .await
        .map_err(map_image_ymodem_error)?;
    Ok(())
}
