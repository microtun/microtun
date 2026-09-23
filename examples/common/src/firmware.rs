//! Shared YMODEM firmware-transfer plumbing for the board examples.

use embassy_net::Stack;
use embassy_time::{Duration, Timer, with_timeout};
use embedded_io_async::{ErrorKind, ErrorType, Read, Write};
use microtun_cli::telnet::{BinaryMode, BinaryModeError};
use microtun_mcuboot::{FeedError, PayloadSink, StreamingVerifier};
use microtun_ymodem::{Config as YmodemConfig, Error as YmodemError};

const BINARY_NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(5);
const YMODEM_START_TIMEOUT: Duration = Duration::from_secs(1);
const YMODEM_TRANSFER_TIMEOUT: Duration = Duration::from_secs(10);
const TRIAL_LINK_TIMEOUT: Duration = Duration::from_secs(120);
const TRIAL_HEALTH_WINDOW: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
pub struct FirmwareStatus {
    pub slot: &'static str,
    pub state: &'static str,
    pub trial: bool,
}

pub type TransferError = &'static str;

/// Wait until the tunnel is actually running, then observe a short stability window before an
/// A/B trial image is confirmed. Both boards use the same health policy.
pub async fn trial_image_is_healthy(inner_stack: Stack<'static>) -> bool {
    if with_timeout(TRIAL_LINK_TIMEOUT, inner_stack.wait_link_up())
        .await
        .is_err()
    {
        return false;
    }

    Timer::after(TRIAL_HEALTH_WINDOW).await;
    true
}

const IO_ERROR: TransferError = "TELNET connection ended";
const TIMEOUT_ERROR: TransferError = "YMODEM transfer timed out";
const CANCELLED_ERROR: TransferError = "YMODEM transfer cancelled";
const PROTOCOL_ERROR: TransferError = "invalid YMODEM-1K/CRC transfer";
const BINARY_MODE_ERROR: TransferError = "could not enter TELNET binary mode";

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

fn negotiation_error<E>(error: BinaryModeError<E>) -> TransferError {
    match error {
        BinaryModeError::Io(_) | BinaryModeError::Disconnected => IO_ERROR,
        BinaryModeError::Refused | BinaryModeError::UnexpectedData => BINARY_MODE_ERROR,
    }
}

struct YmodemTransport<'a, T: ?Sized> {
    binary: BinaryMode<'a, T>,
    started: bool,
}

impl<'a, T> YmodemTransport<'a, T>
where
    T: Read + Write + ?Sized,
{
    async fn start(io: &'a mut T) -> Result<Self, TransferError> {
        let mut binary = BinaryMode::new(io);
        match with_timeout(BINARY_NEGOTIATION_TIMEOUT, binary.negotiate()).await {
            Ok(Ok(())) => Ok(Self {
                binary,
                started: false,
            }),
            Ok(Err(error)) => {
                let error = negotiation_error(error);
                let _ = binary.abort().await;
                Err(error)
            }
            Err(_) => {
                let _ = binary.abort().await;
                Err(BINARY_MODE_ERROR)
            }
        }
    }

    async fn finish(self) {
        let _ = self.binary.finish().await;
    }
}

impl<T> ErrorType for YmodemTransport<'_, T>
where
    T: Read + Write + ?Sized,
{
    type Error = ErrorKind;
}

impl<T> Read for YmodemTransport<'_, T>
where
    T: Read + Write + ?Sized,
{
    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let timeout = if self.started {
            YMODEM_TRANSFER_TIMEOUT
        } else {
            YMODEM_START_TIMEOUT
        };
        match with_timeout(timeout, self.binary.read_byte()).await {
            Ok(Ok(byte)) => {
                buffer[0] = byte;
                self.started = true;
                Ok(1)
            }
            Ok(Err(_)) => Err(ErrorKind::Other),
            Err(_) => Err(ErrorKind::TimedOut),
        }
    }
}

impl<T> Write for YmodemTransport<'_, T>
where
    T: Read + Write + ?Sized,
{
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, Self::Error> {
        self.binary
            .write_all(bytes)
            .await
            .map_err(|_| ErrorKind::Other)?;
        Ok(bytes.len())
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn ymodem_error<I, W, M>(error: YmodemError<I, W, M>) -> TransferError {
    match error {
        YmodemError::Io(_) | YmodemError::EndOfStream => IO_ERROR,
        YmodemError::Timeout => TIMEOUT_ERROR,
        YmodemError::Cancelled => CANCELLED_ERROR,
        YmodemError::Protocol | YmodemError::Output(_) | YmodemError::Metadata(_) => PROTOCOL_ERROR,
    }
}

pub async fn receive_ymodem_buffer<T>(io: &mut T, output: &mut [u8]) -> Result<usize, TransferError>
where
    T: Read + Write + ?Sized,
{
    let mut transport = YmodemTransport::start(io).await?;
    let mut output = output;
    let result = microtun_ymodem::receive(&mut transport, &mut output, YmodemConfig::default())
        .await
        .map_err(ymodem_error);
    transport.finish().await;
    result.map(|transfer| transfer.file_size)
}

struct VerifiedSink<'a, S: PayloadSink> {
    verifier: &'a mut StreamingVerifier,
    sink: &'a mut S,
    error: Option<FeedError<S::Error>>,
}

impl<S: PayloadSink> ErrorType for VerifiedSink<'_, S> {
    type Error = ErrorKind;
}

impl<S: PayloadSink> Write for VerifiedSink<'_, S> {
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, Self::Error> {
        match self.verifier.feed(bytes, self.sink) {
            Ok(()) => Ok(bytes.len()),
            Err(error) => {
                self.error = Some(error);
                Err(ErrorKind::Other)
            }
        }
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub async fn receive_signed_image<T, S>(
    io: &mut T,
    verifier: &mut StreamingVerifier,
    sink: &mut S,
) -> Result<(), ImageTransferError<S::Error>>
where
    T: Read + Write + ?Sized,
    S: PayloadSink,
{
    let mut transport = YmodemTransport::start(io).await?;
    let mut output = VerifiedSink {
        verifier,
        sink,
        error: None,
    };
    let result =
        microtun_ymodem::receive(&mut transport, &mut output, YmodemConfig::default()).await;
    let output_error = output.error.take();
    transport.finish().await;

    if let Some(error) = output_error {
        return Err(match error {
            FeedError::Image(error) => ImageTransferError::Image(error),
            FeedError::Sink(error) => ImageTransferError::Sink(error),
        });
    }

    result
        .map(|_| ())
        .map_err(|error| ImageTransferError::Transfer(ymodem_error(error)))
}
