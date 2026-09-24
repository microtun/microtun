#![no_std]
#![forbid(unsafe_code)]
//! Small, transport-agnostic YMODEM-1K/CRC sender and receiver.
//!
//! The crate is always `no_std` and performs no heap allocation in its core
//! protocol implementation. Protocol-facing byte streams use the standard
//! [`embedded_io_async::Read`] and [`embedded_io_async::Write`] traits so UART,
//! USB, TCP, and adapter types can interoperate without crate-specific I/O traits.
//!
//! `embedded-io-async` does not prescribe timeout durations. If bounded waits are
//! required, the supplied reader should apply the desired timeout and return an
//! error whose [`embedded_io_async::Error::kind`] is
//! [`embedded_io_async::ErrorKind::TimedOut`].
use crc::{CRC_16_XMODEM, Crc, NoTable};

mod receive;
mod send;

pub use embedded_io_async::{Error as EmbeddedIoError, ErrorKind, ErrorType, Read, Write};
pub use receive::{BufferSink, BufferSinkError, Error, receive, receive_with};
pub use send::{SendError, SendEvent, send, send_with};

const CRC16: Crc<u16, NoTable> = Crc::<u16, NoTable>::new(&CRC_16_XMODEM);
/// Payload size of a YMODEM 1K (`STX`) block.
pub const BLOCK_SIZE: usize = 1024;
/// Payload size of a classic YMODEM (`SOH`) block, including block 0 metadata.
pub const HEADER_BLOCK_SIZE: usize = 128;

pub(crate) const SOH: u8 = 0x01;
pub(crate) const STX: u8 = 0x02;
pub(crate) const EOT: u8 = 0x04;
pub(crate) const ACK: u8 = 0x06;
pub(crate) const NAK: u8 = 0x15;
pub(crate) const CAN: u8 = 0x18;
pub(crate) const CRC_REQUEST: u8 = b'C';
pub(crate) const PAD: u8 = 0x1a;
/// Retry policy shared by the sender and receiver.
///
/// Timeout durations are configured by the supplied [`embedded_io_async::Read`]
/// implementation. A timed-out read must return an error with
/// [`ErrorKind::TimedOut`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// Number of timed-out reads tolerated while establishing a transfer.
    pub start_retries: u8,
    /// Maximum protocol retries or retransmissions before giving up.
    pub max_retries: u8,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            start_retries: 60,
            max_retries: 16,
        }
    }
}

/// Metadata carried in standard YMODEM block 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata<'a> {
    /// Filename bytes. They are transported as-is and must not contain NUL when sending.
    pub filename: &'a [u8],
    /// Exact unpadded file length.
    pub file_size: usize,
}
/// Summary returned after a complete single-file YMODEM batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transfer {
    /// Exact number of file bytes transferred, excluding YMODEM padding.
    pub file_size: usize,
}

pub(crate) enum ReadByteError<E> {
    Io(E),
    Timeout,
    Eof,
}
pub(crate) async fn read_byte<R>(reader: &mut R) -> Result<u8, ReadByteError<R::Error>>
where
    R: Read + ?Sized,
{
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte).await {
            Ok(0) => return Err(ReadByteError::Eof),
            Ok(_) => return Ok(byte[0]),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == ErrorKind::TimedOut => {
                return Err(ReadByteError::Timeout);
            }
            Err(error) => return Err(ReadByteError::Io(error)),
        }
    }
}
/// Calculate the CRC-16/XMODEM checksum used by YMODEM CRC mode.
pub fn crc16(bytes: &[u8]) -> u16 {
    CRC16.checksum(bytes)
}

pub(crate) fn block_size(control: u8) -> Option<usize> {
    match control {
        SOH => Some(HEADER_BLOCK_SIZE),
        STX => Some(BLOCK_SIZE),
        _ => None,
    }
}
