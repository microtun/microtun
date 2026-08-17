#![no_std]
#![forbid(unsafe_code)]

//! Small, allocation-free YMODEM-1K/CRC receiver.
//!
//! The crate owns the YMODEM receive state machine but deliberately does not
//! own a concrete transport. Callers provide a byte-oriented [`Transport`]
//! plus a [`Sink`] for the verified file payload.
//!
//! A standard YMODEM block 0 is required. Its filename and decimal file-size
//! fields make the transfer self-describing, so callers never need to pass an
//! out-of-band byte count. Data may use 128-byte (`SOH`) or 1024-byte (`STX`)
//! CRC blocks; the receiver delivers exactly the advertised file size and
//! strips transfer padding before calling the sink.

use crc::{CRC_16_XMODEM, Crc, NoTable};

const CRC16: Crc<u16, NoTable> = Crc::<u16, NoTable>::new(&CRC_16_XMODEM);

pub const BLOCK_SIZE: usize = 1024;
pub const HEADER_BLOCK_SIZE: usize = 128;

const SOH: u8 = 0x01;
const STX: u8 = 0x02;
const EOT: u8 = 0x04;
const ACK: u8 = 0x06;
const NAK: u8 = 0x15;
const CAN: u8 = 0x18;
const CRC_REQUEST: u8 = b'C';

/// Receiver timing/retry policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// Timeout used while periodically sending `C` before block 0.
    pub start_timeout_ms: u32,
    /// Timeout used between bytes once a transfer has started.
    pub transfer_timeout_ms: u32,
    /// Number of `C` requests sent while waiting for block 0.
    pub start_retries: u8,
    /// Maximum consecutive malformed/unexpected frames before cancellation.
    pub max_retries: u8,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            start_timeout_ms: 1_000,
            transfer_timeout_ms: 10_000,
            start_retries: 60,
            max_retries: 16,
        }
    }
}

/// Metadata parsed from the standard YMODEM block 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata<'a> {
    /// Filename field from block 0. The receiver does not interpret it.
    pub filename: &'a [u8],
    /// Exact unpadded file length advertised by the sender.
    pub file_size: usize,
}

/// Summary returned after a complete single-file YMODEM batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub file_size: usize,
}

/// Error returned by a transport read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError<E> {
    Timeout,
    Io(E),
}

/// Byte-oriented transport used by the YMODEM receiver.
///
/// Implementations may sit on UART, USB CDC, a raw TCP stream, or a decoded
/// Telnet stream. `write_all` receives only YMODEM control bytes.
#[allow(async_fn_in_trait)]
pub trait Transport {
    type Error;

    async fn read_byte(&mut self, timeout_ms: u32) -> Result<u8, ReadError<Self::Error>>;
    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
}

/// Consumer for one verified YMODEM file.
pub trait Sink {
    type Error;

    /// Called once after a valid non-empty block 0 has been received.
    fn start(&mut self, _metadata: Metadata<'_>) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Consume verified, unpadded file bytes.
    ///
    /// Duplicate blocks caused by a lost ACK are never delivered twice.
    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
}

/// Error returned by [`BufferSink`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferSinkError {
    Overflow,
}

/// YMODEM sink that copies one self-described file into a caller buffer.
///
/// The output slice is a capacity, not an expected file length. The size from
/// YMODEM block 0 is checked against that capacity and can be queried after a
/// successful transfer with [`file_size`](Self::file_size).
pub struct BufferSink<'a> {
    output: &'a mut [u8],
    file_size: Option<usize>,
    written: usize,
}

impl<'a> BufferSink<'a> {
    pub fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            file_size: None,
            written: 0,
        }
    }

    pub const fn written(&self) -> usize {
        self.written
    }

    pub const fn file_size(&self) -> Option<usize> {
        self.file_size
    }

    pub fn is_complete(&self) -> bool {
        self.file_size == Some(self.written)
    }
}

impl Sink for BufferSink<'_> {
    type Error = BufferSinkError;

    fn start(&mut self, metadata: Metadata<'_>) -> Result<(), Self::Error> {
        if metadata.file_size > self.output.len() {
            return Err(BufferSinkError::Overflow);
        }
        self.file_size = Some(metadata.file_size);
        self.written = 0;
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        let end = self
            .written
            .checked_add(bytes.len())
            .filter(|&end| end <= self.output.len())
            .ok_or(BufferSinkError::Overflow)?;
        self.output[self.written..end].copy_from_slice(bytes);
        self.written = end;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error<I, S> {
    Io(I),
    Timeout,
    Cancelled,
    Protocol,
    Sink(S),
}

/// Calculate the CRC-16/XMODEM checksum used by YMODEM CRC mode.
pub fn crc16(bytes: &[u8]) -> u16 {
    CRC16.checksum(bytes)
}

async fn cancel<T: Transport>(transport: &mut T) -> Result<(), T::Error> {
    transport.write_all(&[CAN, CAN]).await
}

async fn read_block<T: Transport>(
    transport: &mut T,
    timeout_ms: u32,
    block_size: usize,
    frame: &mut [u8; BLOCK_SIZE + 4],
) -> Result<(), ReadError<T::Error>> {
    for byte in &mut frame[..block_size + 4] {
        *byte = transport.read_byte(timeout_ms).await?;
    }
    Ok(())
}

fn block_size(control: u8) -> Option<usize> {
    match control {
        SOH => Some(HEADER_BLOCK_SIZE),
        STX => Some(BLOCK_SIZE),
        _ => None,
    }
}

fn valid_frame(frame: &[u8], block_size: usize) -> bool {
    let block = frame[0];
    let inverse = frame[1];
    let data = &frame[2..2 + block_size];
    let received_crc = u16::from_be_bytes([frame[2 + block_size], frame[3 + block_size]]);
    inverse == !block && received_crc == crc16(data)
}

fn decimal_usize(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    let mut value = 0usize;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(usize::from(byte - b'0'))?;
    }
    Some(value)
}

fn parse_metadata(data: &[u8]) -> Option<Metadata<'_>> {
    let name_end = data.iter().position(|&byte| byte == 0)?;
    if name_end == 0 {
        return None;
    }
    let filename = &data[..name_end];
    let rest = &data[name_end + 1..];
    let field_end = rest
        .iter()
        .position(|&byte| byte == 0 || byte == b' ')
        .unwrap_or(rest.len());
    let file_size = decimal_usize(&rest[..field_end])?;
    Some(Metadata {
        filename,
        file_size,
    })
}

fn is_empty_header(data: &[u8]) -> bool {
    data.first() == Some(&0)
}

async fn first_control<T: Transport>(
    transport: &mut T,
    config: Config,
) -> Result<u8, Error<T::Error, core::convert::Infallible>> {
    for _ in 0..config.start_retries {
        transport
            .write_all(&[CRC_REQUEST])
            .await
            .map_err(Error::Io)?;
        match transport.read_byte(config.start_timeout_ms).await {
            Ok(byte) => return Ok(byte),
            Err(ReadError::Timeout) => {}
            Err(ReadError::Io(error)) => return Err(Error::Io(error)),
        }
    }
    Err(Error::Timeout)
}

async fn next_byte<T: Transport, E>(
    transport: &mut T,
    timeout_ms: u32,
) -> Result<u8, Error<T::Error, E>> {
    match transport.read_byte(timeout_ms).await {
        Ok(byte) => Ok(byte),
        Err(ReadError::Timeout) => Err(Error::Timeout),
        Err(ReadError::Io(error)) => Err(Error::Io(error)),
    }
}

/// Receive one file as a standards-compatible single-file YMODEM batch.
///
/// The receiver requires a metadata block 0 containing a filename and decimal
/// file size, ACKs it, requests CRC mode again, receives data blocks starting
/// at block 1, performs the canonical `EOT / NAK / EOT / ACK` exchange, then
/// requests and ACKs the final empty block 0 that terminates the batch.
///
/// Only the advertised number of file bytes are delivered to [`Sink::write`];
/// padding in the final data block is discarded by the receiver.
pub async fn receive<T, S>(
    transport: &mut T,
    sink: &mut S,
    config: Config,
) -> Result<Transfer, Error<T::Error, S::Error>>
where
    T: Transport,
    S: Sink,
{
    let mut frame = [0u8; BLOCK_SIZE + 4];
    let mut retries = 0u8;

    let first = match first_control(transport, config).await {
        Ok(byte) => byte,
        Err(Error::Io(error)) => return Err(Error::Io(error)),
        Err(Error::Timeout) => return Err(Error::Timeout),
        Err(Error::Cancelled | Error::Protocol | Error::Sink(_)) => unreachable!(),
    };
    let mut control = first;

    let metadata = loop {
        if control == CAN {
            return Err(Error::Cancelled);
        }
        let Some(size) = block_size(control) else {
            retries = retries.saturating_add(1);
            if retries > config.max_retries {
                cancel(transport).await.map_err(Error::Io)?;
                return Err(Error::Protocol);
            }
            transport.write_all(&[NAK]).await.map_err(Error::Io)?;
            control = next_byte::<T, S::Error>(transport, config.transfer_timeout_ms).await?;
            continue;
        };

        match read_block(transport, config.transfer_timeout_ms, size, &mut frame).await {
            Ok(()) => {}
            Err(ReadError::Timeout) => return Err(Error::Timeout),
            Err(ReadError::Io(error)) => return Err(Error::Io(error)),
        }

        if !valid_frame(&frame, size) || frame[0] != 0 {
            retries = retries.saturating_add(1);
            if retries > config.max_retries {
                cancel(transport).await.map_err(Error::Io)?;
                return Err(Error::Protocol);
            }
            transport.write_all(&[NAK]).await.map_err(Error::Io)?;
            control = next_byte::<T, S::Error>(transport, config.transfer_timeout_ms).await?;
            continue;
        }

        let data = &frame[2..2 + size];
        let Some(metadata) = parse_metadata(data) else {
            cancel(transport).await.map_err(Error::Io)?;
            return Err(Error::Protocol);
        };
        if let Err(error) = sink.start(metadata) {
            cancel(transport).await.map_err(Error::Io)?;
            return Err(Error::Sink(error));
        }
        transport.write_all(&[ACK]).await.map_err(Error::Io)?;
        transport
            .write_all(&[CRC_REQUEST])
            .await
            .map_err(Error::Io)?;
        break Metadata {
            filename: &[],
            file_size: metadata.file_size,
        };
    };

    let mut expected_block = 1u8;
    let mut written = 0usize;
    retries = 0;
    control = next_byte::<T, S::Error>(transport, config.transfer_timeout_ms).await?;

    loop {
        if control == CAN {
            return Err(Error::Cancelled);
        }
        if control == EOT {
            if written != metadata.file_size {
                cancel(transport).await.map_err(Error::Io)?;
                return Err(Error::Protocol);
            }

            transport.write_all(&[NAK]).await.map_err(Error::Io)?;
            let second = next_byte::<T, S::Error>(transport, config.transfer_timeout_ms).await?;
            if second != EOT {
                cancel(transport).await.map_err(Error::Io)?;
                return Err(Error::Protocol);
            }
            transport.write_all(&[ACK]).await.map_err(Error::Io)?;
            transport
                .write_all(&[CRC_REQUEST])
                .await
                .map_err(Error::Io)?;
            break;
        }

        let Some(size) = block_size(control) else {
            retries = retries.saturating_add(1);
            if retries > config.max_retries {
                cancel(transport).await.map_err(Error::Io)?;
                return Err(Error::Protocol);
            }
            transport.write_all(&[NAK]).await.map_err(Error::Io)?;
            control = next_byte::<T, S::Error>(transport, config.transfer_timeout_ms).await?;
            continue;
        };

        match read_block(transport, config.transfer_timeout_ms, size, &mut frame).await {
            Ok(()) => {}
            Err(ReadError::Timeout) => return Err(Error::Timeout),
            Err(ReadError::Io(error)) => return Err(Error::Io(error)),
        }

        let block = frame[0];
        if !valid_frame(&frame, size) {
            retries = retries.saturating_add(1);
            if retries > config.max_retries {
                cancel(transport).await.map_err(Error::Io)?;
                return Err(Error::Protocol);
            }
            transport.write_all(&[NAK]).await.map_err(Error::Io)?;
        } else if block == expected_block {
            if written >= metadata.file_size {
                cancel(transport).await.map_err(Error::Io)?;
                return Err(Error::Protocol);
            }
            let remaining = metadata.file_size - written;
            let count = remaining.min(size);
            if let Err(error) = sink.write(&frame[2..2 + count]) {
                cancel(transport).await.map_err(Error::Io)?;
                return Err(Error::Sink(error));
            }
            written += count;
            expected_block = expected_block.wrapping_add(1);
            retries = 0;
            transport.write_all(&[ACK]).await.map_err(Error::Io)?;
        } else if block == expected_block.wrapping_sub(1) {
            transport.write_all(&[ACK]).await.map_err(Error::Io)?;
        } else {
            retries = retries.saturating_add(1);
            if retries > config.max_retries {
                cancel(transport).await.map_err(Error::Io)?;
                return Err(Error::Protocol);
            }
            transport.write_all(&[NAK]).await.map_err(Error::Io)?;
        }

        control = next_byte::<T, S::Error>(transport, config.transfer_timeout_ms).await?;
    }

    // A single-file YMODEM transfer is a one-file batch. The sender terminates
    // the batch with an empty block 0 after the receiver's post-EOT `C`.
    retries = 0;
    control = next_byte::<T, S::Error>(transport, config.transfer_timeout_ms).await?;
    loop {
        if control == CAN {
            return Err(Error::Cancelled);
        }
        let Some(size) = block_size(control) else {
            retries = retries.saturating_add(1);
            if retries > config.max_retries {
                cancel(transport).await.map_err(Error::Io)?;
                return Err(Error::Protocol);
            }
            transport.write_all(&[NAK]).await.map_err(Error::Io)?;
            control = next_byte::<T, S::Error>(transport, config.transfer_timeout_ms).await?;
            continue;
        };

        match read_block(transport, config.transfer_timeout_ms, size, &mut frame).await {
            Ok(()) => {}
            Err(ReadError::Timeout) => return Err(Error::Timeout),
            Err(ReadError::Io(error)) => return Err(Error::Io(error)),
        }

        if valid_frame(&frame, size) && frame[0] == 0 && is_empty_header(&frame[2..2 + size]) {
            transport.write_all(&[ACK]).await.map_err(Error::Io)?;
            return Ok(Transfer {
                file_size: metadata.file_size,
            });
        }

        retries = retries.saturating_add(1);
        if retries > config.max_retries {
            cancel(transport).await.map_err(Error::Io)?;
            return Err(Error::Protocol);
        }
        transport.write_all(&[NAK]).await.map_err(Error::Io)?;
        control = next_byte::<T, S::Error>(transport, config.transfer_timeout_ms).await?;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    use std::{boxed::Box, collections::VecDeque, sync::Arc, task::Wake, vec, vec::Vec};

    use super::*;

    struct NoopWake;
    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum IoError {
        Broken,
    }

    struct FakeTransport {
        input: VecDeque<Result<u8, ReadError<IoError>>>,
        output: Vec<u8>,
        fail_write: bool,
    }

    impl FakeTransport {
        fn from_bytes(bytes: Vec<u8>) -> Self {
            Self {
                input: bytes.into_iter().map(Ok).collect(),
                output: Vec::new(),
                fail_write: false,
            }
        }
    }

    impl Transport for FakeTransport {
        type Error = IoError;

        async fn read_byte(&mut self, _timeout_ms: u32) -> Result<u8, ReadError<Self::Error>> {
            self.input.pop_front().unwrap_or(Err(ReadError::Timeout))
        }

        async fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
            if self.fail_write {
                return Err(IoError::Broken);
            }
            self.output.extend_from_slice(bytes);
            Ok(())
        }
    }

    #[derive(Default)]
    struct CollectSink {
        bytes: Vec<u8>,
        size: Option<usize>,
        fail: bool,
    }

    impl Sink for CollectSink {
        type Error = &'static str;

        fn start(&mut self, metadata: Metadata<'_>) -> Result<(), Self::Error> {
            self.size = Some(metadata.file_size);
            Ok(())
        }

        fn write(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
            if self.fail {
                return Err("sink failed");
            }
            self.bytes.extend_from_slice(bytes);
            Ok(())
        }
    }

    fn packet(control: u8, block: u8, data: &[u8]) -> Vec<u8> {
        let size = block_size(control).unwrap();
        assert_eq!(data.len(), size);
        let crc = crc16(data);
        let mut frame = Vec::with_capacity(size + 5);
        frame.push(control);
        frame.push(block);
        frame.push(!block);
        frame.extend_from_slice(data);
        frame.extend_from_slice(&crc.to_be_bytes());
        frame
    }

    fn header(filename: &[u8], size: usize) -> Vec<u8> {
        let mut data = [0u8; HEADER_BLOCK_SIZE];
        let mut cursor = 0;
        data[..filename.len()].copy_from_slice(filename);
        cursor += filename.len() + 1;
        let text = std::format!("{size}");
        data[cursor..cursor + text.len()].copy_from_slice(text.as_bytes());
        packet(SOH, 0, &data)
    }

    fn end_header() -> Vec<u8> {
        packet(SOH, 0, &[0u8; HEADER_BLOCK_SIZE])
    }

    fn data_packet(block: u8, bytes: &[u8], control: u8) -> Vec<u8> {
        let size = block_size(control).unwrap();
        let mut data = vec![0x1a; size];
        data[..bytes.len()].copy_from_slice(bytes);
        packet(control, block, &data)
    }

    fn transfer(filename: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut input = header(filename, payload.len());
        let mut block = 1u8;
        for chunk in payload.chunks(BLOCK_SIZE) {
            input.extend_from_slice(&data_packet(block, chunk, STX));
            block = block.wrapping_add(1);
        }
        input.extend_from_slice(&[EOT, EOT]);
        input.extend_from_slice(&end_header());
        input
    }

    #[test]
    fn receives_metadata_and_strips_final_padding() {
        let payload = vec![0x5a; 1030];
        let mut transport = FakeTransport::from_bytes(transfer(b"config.ini", &payload));
        let mut sink = CollectSink::default();

        let result = block_on(receive(&mut transport, &mut sink, Config::default()));

        assert_eq!(result, Ok(Transfer { file_size: 1030 }));
        assert_eq!(sink.size, Some(1030));
        assert_eq!(sink.bytes, payload);
        assert_eq!(
            transport.output,
            vec![
                CRC_REQUEST,
                ACK,
                CRC_REQUEST,
                ACK,
                ACK,
                NAK,
                ACK,
                CRC_REQUEST,
                ACK
            ]
        );
    }

    #[test]
    fn accepts_128_byte_data_blocks() {
        let payload = b"small file";
        let mut input = header(b"small.ini", payload.len());
        input.extend_from_slice(&data_packet(1, payload, SOH));
        input.extend_from_slice(&[EOT, EOT]);
        input.extend_from_slice(&end_header());
        let mut transport = FakeTransport::from_bytes(input);
        let mut sink = CollectSink::default();

        assert_eq!(
            block_on(receive(&mut transport, &mut sink, Config::default())),
            Ok(Transfer {
                file_size: payload.len()
            })
        );
        assert_eq!(sink.bytes, payload);
    }

    #[test]
    fn duplicate_data_block_is_acked_but_not_written_twice() {
        let payload = vec![0x11; 100];
        let mut input = header(b"file.bin", payload.len());
        let block = data_packet(1, &payload, STX);
        input.extend_from_slice(&block);
        input.extend_from_slice(&block);
        input.extend_from_slice(&[EOT, EOT]);
        input.extend_from_slice(&end_header());
        let mut transport = FakeTransport::from_bytes(input);
        let mut sink = CollectSink::default();

        assert!(block_on(receive(&mut transport, &mut sink, Config::default())).is_ok());
        assert_eq!(sink.bytes, payload);
    }

    #[test]
    fn invalid_or_missing_size_is_rejected() {
        let mut data = [0u8; HEADER_BLOCK_SIZE];
        data[..9].copy_from_slice(b"file.bin\0");
        data[9..12].copy_from_slice(b"wat");
        let mut transport = FakeTransport::from_bytes(packet(SOH, 0, &data));
        let mut sink = CollectSink::default();

        assert_eq!(
            block_on(receive(&mut transport, &mut sink, Config::default())),
            Err(Error::Protocol)
        );
        assert_eq!(transport.output, vec![CRC_REQUEST, CAN, CAN]);
    }

    #[test]
    fn sender_cancel_is_reported() {
        let mut transport = FakeTransport::from_bytes(vec![CAN]);
        let mut sink = CollectSink::default();
        assert_eq!(
            block_on(receive(&mut transport, &mut sink, Config::default())),
            Err(Error::Cancelled)
        );
    }

    #[test]
    fn sink_failure_cancels_transfer() {
        let payload = b"payload";
        let mut transport = FakeTransport::from_bytes(transfer(b"file.bin", payload));
        let mut sink = CollectSink {
            fail: true,
            ..CollectSink::default()
        };
        assert_eq!(
            block_on(receive(&mut transport, &mut sink, Config::default())),
            Err(Error::Sink("sink failed"))
        );
    }

    #[test]
    fn buffer_sink_uses_header_size_as_capacity_check() {
        let payload = vec![0x22; 1030];
        let mut output = [0u8; 2048];
        let mut sink = BufferSink::new(&mut output);
        let mut transport = FakeTransport::from_bytes(transfer(b"config.ini", &payload));

        let transfer = block_on(receive(&mut transport, &mut sink, Config::default())).unwrap();
        assert_eq!(transfer.file_size, 1030);
        assert_eq!(sink.file_size(), Some(1030));
        assert_eq!(sink.written(), 1030);
        assert!(sink.is_complete());
        drop(sink);
        assert_eq!(&output[..1030], payload.as_slice());
    }

    #[test]
    fn buffer_sink_rejects_file_larger_than_destination() {
        let payload = vec![0x33; 200];
        let mut output = [0u8; 100];
        let mut sink = BufferSink::new(&mut output);
        let mut transport = FakeTransport::from_bytes(transfer(b"config.ini", &payload));

        assert_eq!(
            block_on(receive(&mut transport, &mut sink, Config::default())),
            Err(Error::Sink(BufferSinkError::Overflow))
        );
    }

    #[test]
    fn start_timeouts_repeat_crc_request_then_fail() {
        let config = Config {
            start_retries: 3,
            ..Config::default()
        };
        let mut transport = FakeTransport {
            input: VecDeque::from([
                Err(ReadError::Timeout),
                Err(ReadError::Timeout),
                Err(ReadError::Timeout),
            ]),
            output: Vec::new(),
            fail_write: false,
        };
        let mut sink = CollectSink::default();

        assert_eq!(
            block_on(receive(&mut transport, &mut sink, config)),
            Err(Error::Timeout)
        );
        assert_eq!(transport.output, vec![CRC_REQUEST; 3]);
    }
}
