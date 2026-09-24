use core::{convert::Infallible, ops::AsyncFnMut};

use embedded_io_async::{Read, Write};

use crate::{
    ACK, BLOCK_SIZE, CAN, CRC_REQUEST, Config, EOT, HEADER_BLOCK_SIZE, Metadata, NAK, PAD,
    ReadByteError, SOH, STX, Transfer, crc16, read_byte,
};
/// Sender-side event emitted by [`send_with`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendEvent {
    /// Non-YMODEM byte observed while waiting for the receiver's initial or
    /// post-header `C`. This is useful for preserving shell output in a CLI.
    Output(u8),
    /// Verified progress after a data block has been acknowledged.
    Progress { sent: usize, total: usize },
}
/// Error returned by [`send`] and [`send_with`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError<I, S, O = Infallible> {
    Io(I),
    Timeout,
    EndOfStream,
    Cancelled,
    Protocol,
    InvalidFilename,
    HeaderTooLong,
    UnexpectedEof,
    InvalidSourceRead,
    Source(S),
    Observer(O),
}
fn decimal_bytes(mut value: usize, scratch: &mut [u8; 20]) -> &[u8] {
    let mut cursor = scratch.len();
    loop {
        cursor -= 1;
        scratch[cursor] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            return &scratch[cursor..];
        }
    }
}
fn metadata_block(metadata: Metadata<'_>) -> Result<[u8; HEADER_BLOCK_SIZE], SendError<(), ()>> {
    if metadata.filename.is_empty() || metadata.filename.contains(&0) {
        return Err(SendError::InvalidFilename);
    }
    let mut size_scratch = [0u8; 20];
    let size = decimal_bytes(metadata.file_size, &mut size_scratch);
    let needed = metadata
        .filename
        .len()
        .checked_add(1)
        .and_then(|len| len.checked_add(size.len()))
        .and_then(|len| len.checked_add(1))
        .ok_or(SendError::HeaderTooLong)?;
    if needed > HEADER_BLOCK_SIZE {
        return Err(SendError::HeaderTooLong);
    }
    let mut block = [0u8; HEADER_BLOCK_SIZE];
    block[..metadata.filename.len()].copy_from_slice(metadata.filename);
    let size_start = metadata.filename.len() + 1;
    block[size_start..size_start + size.len()].copy_from_slice(size);
    Ok(block)
}
async fn wait_for_crc_request<T, S, F, O>(
    transport: &mut T,
    config: Config,
    notify: &mut F,
) -> Result<(), SendError<T::Error, S, O>>
where
    T: Read + Write,
    F: AsyncFnMut(SendEvent) -> Result<(), O>,
{
    if config.start_retries == 0 {
        return Err(SendError::Timeout);
    }
    let mut timeouts = 0u8;
    loop {
        match read_byte(transport).await {
            Ok(CRC_REQUEST) => return Ok(()),
            Ok(CAN) => return Err(SendError::Cancelled),
            Ok(byte) => notify(SendEvent::Output(byte))
                .await
                .map_err(SendError::Observer)?,
            Err(ReadByteError::Io(error)) => return Err(SendError::Io(error)),
            Err(ReadByteError::Eof) => return Err(SendError::EndOfStream),
            Err(ReadByteError::Timeout) => {
                timeouts = timeouts.saturating_add(1);
                if timeouts >= config.start_retries {
                    return Err(SendError::Timeout);
                }
            }
        }
    }
}
async fn write_control<T, S, O>(
    transport: &mut T,
    byte: u8,
) -> Result<(), SendError<T::Error, S, O>>
where
    T: Read + Write,
{
    transport.write_all(&[byte]).await.map_err(SendError::Io)?;
    transport.flush().await.map_err(SendError::Io)
}
async fn send_packet<T, S, O>(
    transport: &mut T,
    control: u8,
    block_number: u8,
    data: &[u8],
    config: Config,
) -> Result<(), SendError<T::Error, S, O>>
where
    T: Read + Write,
{
    let prefix = [control, block_number, !block_number];
    let crc = crc16(data).to_be_bytes();
    let mut retries = 0u8;
    loop {
        transport.write_all(&prefix).await.map_err(SendError::Io)?;
        transport.write_all(data).await.map_err(SendError::Io)?;
        transport.write_all(&crc).await.map_err(SendError::Io)?;
        transport.flush().await.map_err(SendError::Io)?;
        match read_byte(transport).await {
            Ok(ACK) => return Ok(()),
            Ok(NAK) => {
                if retries >= config.max_retries {
                    return Err(SendError::Protocol);
                }
            }
            Ok(CAN) => return Err(SendError::Cancelled),
            Ok(_) => return Err(SendError::Protocol),
            Err(ReadByteError::Io(error)) => return Err(SendError::Io(error)),
            Err(ReadByteError::Eof) => return Err(SendError::EndOfStream),
            Err(ReadByteError::Timeout) => {
                if retries >= config.max_retries {
                    return Err(SendError::Timeout);
                }
            }
        }
        retries = retries.saturating_add(1);
    }
}
async fn expect_control<T, S, O>(
    transport: &mut T,
    expected: u8,
) -> Result<(), SendError<T::Error, S, O>>
where
    T: Read + Write,
{
    match read_byte(transport).await {
        Ok(byte) if byte == expected => Ok(()),
        Ok(CAN) => Err(SendError::Cancelled),
        Ok(_) => Err(SendError::Protocol),
        Err(ReadByteError::Timeout) => Err(SendError::Timeout),
        Err(ReadByteError::Eof) => Err(SendError::EndOfStream),
        Err(ReadByteError::Io(error)) => Err(SendError::Io(error)),
    }
}
/// Send one file as a standards-compatible single-file YMODEM batch.
pub async fn send<T, S>(
    transport: &mut T,
    source: &mut S,
    metadata: Metadata<'_>,
    config: Config,
) -> Result<Transfer, SendError<T::Error, S::Error>>
where
    T: Read + Write,
    S: Read,
{
    send_with(transport, source, metadata, config, async |_| {
        Ok::<(), Infallible>(())
    })
    .await
}
/// Send one file and report shell/output bytes plus acknowledged progress.
pub async fn send_with<T, S, F, O>(
    transport: &mut T,
    source: &mut S,
    metadata: Metadata<'_>,
    config: Config,
    mut notify: F,
) -> Result<Transfer, SendError<T::Error, S::Error, O>>
where
    T: Read + Write,
    S: Read,
    F: AsyncFnMut(SendEvent) -> Result<(), O>,
{
    let header = match metadata_block(metadata) {
        Ok(header) => header,
        Err(SendError::InvalidFilename) => return Err(SendError::InvalidFilename),
        Err(SendError::HeaderTooLong) => return Err(SendError::HeaderTooLong),
        Err(_) => unreachable!(),
    };
    notify(SendEvent::Progress {
        sent: 0,
        total: metadata.file_size,
    })
    .await
    .map_err(SendError::Observer)?;

    wait_for_crc_request::<T, S::Error, _, O>(transport, config, &mut notify).await?;
    send_packet::<T, S::Error, O>(transport, SOH, 0, &header, config).await?;
    wait_for_crc_request::<T, S::Error, _, O>(transport, config, &mut notify).await?;
    let mut block_number = 1u8;
    let mut sent = 0usize;
    while sent < metadata.file_size {
        let mut data = [PAD; BLOCK_SIZE];
        let wanted = (metadata.file_size - sent).min(BLOCK_SIZE);
        let mut used = 0usize;
        while used < wanted {
            let count = source
                .read(&mut data[used..wanted])
                .await
                .map_err(SendError::Source)?;
            if count == 0 {
                return Err(SendError::UnexpectedEof);
            }
            if count > wanted - used {
                return Err(SendError::InvalidSourceRead);
            }
            used += count;
        }
        send_packet::<T, S::Error, O>(transport, STX, block_number, &data, config).await?;
        sent += used;
        notify(SendEvent::Progress {
            sent,
            total: metadata.file_size,
        })
        .await
        .map_err(SendError::Observer)?;
        block_number = block_number.wrapping_add(1);
    }
    write_control::<T, S::Error, O>(transport, EOT).await?;
    expect_control::<T, S::Error, O>(transport, NAK).await?;
    write_control::<T, S::Error, O>(transport, EOT).await?;
    expect_control::<T, S::Error, O>(transport, ACK).await?;

    wait_for_crc_request::<T, S::Error, _, O>(transport, config, &mut notify).await?;
    send_packet::<T, S::Error, O>(transport, SOH, 0, &[0u8; HEADER_BLOCK_SIZE], config).await?;
    notify(SendEvent::Progress {
        sent: metadata.file_size,
        total: metadata.file_size,
    })
    .await
    .map_err(SendError::Observer)?;

    Ok(Transfer {
        file_size: metadata.file_size,
    })
}
