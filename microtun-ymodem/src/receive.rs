use core::{convert::Infallible, fmt};

use embedded_io_async::{ErrorKind, ErrorType, Read, Write};

use crate::{
    ACK, BLOCK_SIZE, CAN, CRC_REQUEST, Config, EOT, Metadata, NAK, ReadByteError, Transfer,
    block_size, crc16, read_byte,
};

/// Error returned by [`BufferSink`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferSinkError {
    Overflow,
}
impl fmt::Display for BufferSinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("destination buffer is full")
    }
}

impl core::error::Error for BufferSinkError {}

impl embedded_io_async::Error for BufferSinkError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::WriteZero
    }
}

/// `embedded-io-async` writer that copies received bytes into a caller buffer.
pub struct BufferSink<'a> {
    output: &'a mut [u8],
    written: usize,
}
impl<'a> BufferSink<'a> {
    pub fn new(output: &'a mut [u8]) -> Self {
        Self { output, written: 0 }
    }

    pub const fn written(&self) -> usize {
        self.written
    }

    pub const fn remaining(&self) -> usize {
        self.output.len() - self.written
    }
}

impl ErrorType for BufferSink<'_> {
    type Error = BufferSinkError;
}
impl Write for BufferSink<'_> {
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, Self::Error> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let count = bytes.len().min(self.remaining());
        if count == 0 {
            return Err(BufferSinkError::Overflow);
        }
        let end = self.written + count;
        self.output[self.written..end].copy_from_slice(&bytes[..count]);
        self.written = end;
        Ok(count)
    }
    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Error returned by [`receive`] and [`receive_with`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error<I, W, M = Infallible> {
    Io(I),
    Timeout,
    EndOfStream,
    Cancelled,
    Protocol,
    Output(W),
    Metadata(M),
}

async fn cancel<T>(transport: &mut T) -> Result<(), T::Error>
where
    T: Read + Write,
{
    transport.write_all(&[CAN, CAN]).await?;
    transport.flush().await
}
async fn read_block<T>(
    transport: &mut T,
    block_size: usize,
    frame: &mut [u8; BLOCK_SIZE + 4],
) -> Result<(), ReadByteError<T::Error>>
where
    T: Read + Write,
{
    for byte in &mut frame[..block_size + 4] {
        *byte = read_byte(transport).await?;
    }
    Ok(())
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
async fn first_control<T, W, M>(
    transport: &mut T,
    config: Config,
) -> Result<u8, Error<T::Error, W, M>>
where
    T: Read + Write,
{
    for _ in 0..config.start_retries {
        transport
            .write_all(&[CRC_REQUEST])
            .await
            .map_err(Error::Io)?;
        transport.flush().await.map_err(Error::Io)?;
        match read_byte(transport).await {
            Ok(byte) => return Ok(byte),
            Err(ReadByteError::Timeout) => {}
            Err(ReadByteError::Eof) => return Err(Error::EndOfStream),
            Err(ReadByteError::Io(error)) => return Err(Error::Io(error)),
        }
    }
    Err(Error::Timeout)
}
async fn next_byte<T, W, M>(transport: &mut T) -> Result<u8, Error<T::Error, W, M>>
where
    T: Read + Write,
{
    match read_byte(transport).await {
        Ok(byte) => Ok(byte),
        Err(ReadByteError::Timeout) => Err(Error::Timeout),
        Err(ReadByteError::Eof) => Err(Error::EndOfStream),
        Err(ReadByteError::Io(error)) => Err(Error::Io(error)),
    }
}
/// Receive one file as a standards-compatible single-file YMODEM batch.
///
/// The receiver requires a metadata block 0 containing a filename and decimal
/// file size, ACKs it, requests CRC mode again, receives data blocks starting
/// at block 1, performs the canonical `EOT / NAK / EOT / ACK` exchange, then
/// requests and ACKs the final empty block 0 that terminates the batch.
///
/// Only the advertised number of file bytes are written to the output;
/// padding in the final data block is discarded by the receiver.
pub async fn receive<T, W>(
    transport: &mut T,
    output: &mut W,
    config: Config,
) -> Result<Transfer, Error<T::Error, W::Error>>
where
    T: Read + Write,
    W: Write,
{
    receive_with(transport, output, config, |_| Ok::<(), Infallible>(())).await
}
/// Receive one file and inspect or reject its metadata before data blocks are accepted.
///
/// The metadata callback is synchronous because the borrowed filename points into the
/// receiver's fixed frame buffer. Return an error to cancel the transfer before block 0
/// is acknowledged.
pub async fn receive_with<T, W, F, M>(
    transport: &mut T,
    output: &mut W,
    config: Config,
    mut on_metadata: F,
) -> Result<Transfer, Error<T::Error, W::Error, M>>
where
    T: Read + Write,
    W: Write,
    F: for<'a> FnMut(Metadata<'a>) -> Result<(), M>,
{
    let mut frame = [0u8; BLOCK_SIZE + 4];
    let mut retries = 0u8;
    let first = match first_control::<T, W::Error, M>(transport, config).await {
        Ok(byte) => byte,
        Err(Error::Io(error)) => return Err(Error::Io(error)),
        Err(Error::Timeout) => return Err(Error::Timeout),
        Err(Error::EndOfStream) => return Err(Error::EndOfStream),
        Err(Error::Cancelled | Error::Protocol | Error::Output(_) | Error::Metadata(_)) => {
            unreachable!()
        }
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
            transport.flush().await.map_err(Error::Io)?;
            control = next_byte::<T, W::Error, M>(transport).await?;
            continue;
        };
        match read_block(transport, size, &mut frame).await {
            Ok(()) => {}
            Err(ReadByteError::Timeout) => return Err(Error::Timeout),
            Err(ReadByteError::Eof) => return Err(Error::EndOfStream),
            Err(ReadByteError::Io(error)) => return Err(Error::Io(error)),
        }
        if !valid_frame(&frame, size) || frame[0] != 0 {
            retries = retries.saturating_add(1);
            if retries > config.max_retries {
                cancel(transport).await.map_err(Error::Io)?;
                return Err(Error::Protocol);
            }
            transport.write_all(&[NAK]).await.map_err(Error::Io)?;
            transport.flush().await.map_err(Error::Io)?;
            control = next_byte::<T, W::Error, M>(transport).await?;
            continue;
        }
        let data = &frame[2..2 + size];
        let Some(metadata) = parse_metadata(data) else {
            cancel(transport).await.map_err(Error::Io)?;
            return Err(Error::Protocol);
        };
        if let Err(error) = on_metadata(metadata) {
            cancel(transport).await.map_err(Error::Io)?;
            return Err(Error::Metadata(error));
        }
        transport.write_all(&[ACK]).await.map_err(Error::Io)?;
        transport
            .write_all(&[CRC_REQUEST])
            .await
            .map_err(Error::Io)?;
        transport.flush().await.map_err(Error::Io)?;
        break metadata.file_size;
    };
    let mut expected_block = 1u8;
    let mut written = 0usize;
    retries = 0;
    control = next_byte::<T, W::Error, M>(transport).await?;
    loop {
        if control == CAN {
            return Err(Error::Cancelled);
        }
        if control == EOT {
            if written != metadata {
                cancel(transport).await.map_err(Error::Io)?;
                return Err(Error::Protocol);
            }
            if let Err(error) = output.flush().await {
                cancel(transport).await.map_err(Error::Io)?;
                return Err(Error::Output(error));
            }
            transport.write_all(&[NAK]).await.map_err(Error::Io)?;
            transport.flush().await.map_err(Error::Io)?;
            let second = next_byte::<T, W::Error, M>(transport).await?;
            if second != EOT {
                cancel(transport).await.map_err(Error::Io)?;
                return Err(Error::Protocol);
            }
            transport.write_all(&[ACK]).await.map_err(Error::Io)?;
            transport
                .write_all(&[CRC_REQUEST])
                .await
                .map_err(Error::Io)?;
            transport.flush().await.map_err(Error::Io)?;
            break;
        }
        let Some(size) = block_size(control) else {
            retries = retries.saturating_add(1);
            if retries > config.max_retries {
                cancel(transport).await.map_err(Error::Io)?;
                return Err(Error::Protocol);
            }
            transport.write_all(&[NAK]).await.map_err(Error::Io)?;
            transport.flush().await.map_err(Error::Io)?;
            control = next_byte::<T, W::Error, M>(transport).await?;
            continue;
        };
        match read_block(transport, size, &mut frame).await {
            Ok(()) => {}
            Err(ReadByteError::Timeout) => return Err(Error::Timeout),
            Err(ReadByteError::Eof) => return Err(Error::EndOfStream),
            Err(ReadByteError::Io(error)) => return Err(Error::Io(error)),
        }
        let block = frame[0];
        if !valid_frame(&frame, size) {
            retries = retries.saturating_add(1);
            if retries > config.max_retries {
                cancel(transport).await.map_err(Error::Io)?;
                return Err(Error::Protocol);
            }
            transport.write_all(&[NAK]).await.map_err(Error::Io)?;
            transport.flush().await.map_err(Error::Io)?;
        } else if block == expected_block {
            if written >= metadata {
                cancel(transport).await.map_err(Error::Io)?;
                return Err(Error::Protocol);
            }
            let remaining = metadata - written;
            let count = remaining.min(size);
            if let Err(error) = output.write_all(&frame[2..2 + count]).await {
                cancel(transport).await.map_err(Error::Io)?;
                return Err(Error::Output(error));
            }
            written += count;
            expected_block = expected_block.wrapping_add(1);
            retries = 0;
            transport.write_all(&[ACK]).await.map_err(Error::Io)?;
            transport.flush().await.map_err(Error::Io)?;
        } else if block == expected_block.wrapping_sub(1) {
            transport.write_all(&[ACK]).await.map_err(Error::Io)?;
            transport.flush().await.map_err(Error::Io)?;
        } else {
            retries = retries.saturating_add(1);
            if retries > config.max_retries {
                cancel(transport).await.map_err(Error::Io)?;
                return Err(Error::Protocol);
            }
            transport.write_all(&[NAK]).await.map_err(Error::Io)?;
            transport.flush().await.map_err(Error::Io)?;
        }
        control = next_byte::<T, W::Error, M>(transport).await?;
    }
    // A single-file YMODEM transfer is a one-file batch. The sender terminates
    // the batch with an empty block 0 after the receiver's post-EOT `C`.
    retries = 0;
    control = next_byte::<T, W::Error, M>(transport).await?;
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
            transport.flush().await.map_err(Error::Io)?;
            control = next_byte::<T, W::Error, M>(transport).await?;
            continue;
        };
        match read_block(transport, size, &mut frame).await {
            Ok(()) => {}
            Err(ReadByteError::Timeout) => return Err(Error::Timeout),
            Err(ReadByteError::Eof) => return Err(Error::EndOfStream),
            Err(ReadByteError::Io(error)) => return Err(Error::Io(error)),
        }
        if valid_frame(&frame, size) && frame[0] == 0 && is_empty_header(&frame[2..2 + size]) {
            transport.write_all(&[ACK]).await.map_err(Error::Io)?;
            transport.flush().await.map_err(Error::Io)?;
            return Ok(Transfer {
                file_size: metadata,
            });
        }
        retries = retries.saturating_add(1);
        if retries > config.max_retries {
            cancel(transport).await.map_err(Error::Io)?;
            return Err(Error::Protocol);
        }
        transport.write_all(&[NAK]).await.map_err(Error::Io)?;
        transport.flush().await.map_err(Error::Io)?;
        control = next_byte::<T, W::Error, M>(transport).await?;
    }
}
