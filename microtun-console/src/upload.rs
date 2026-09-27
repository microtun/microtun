use core::ops::AsyncFnMut;
use std::{io, path::Path};

use embedded_io_adapters::tokio_1::FromTokio;
pub(crate) use microtun_ymodem::SendEvent as UploadEvent;
use microtun_ymodem::{Config, Metadata, SendError, SendEvent, send_with};
use tokio::fs::File;

use crate::telnet::TelnetClient;
pub(crate) async fn send_file_with<F>(
    client: &mut TelnetClient,
    path: &Path,
    notify: F,
) -> Result<u64, String>
where
    F: AsyncFnMut(SendEvent) -> Result<(), String>,
{
    let file = File::open(path)
        .await
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    let file_size_u64 = file
        .metadata()
        .await
        .map_err(|error| format!("stat {}: {error}", path.display()))?
        .len();
    let file_size = usize::try_from(file_size_u64)
        .map_err(|_| format!("{} is too large for this platform", path.display()))?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("upload.bin");
    let mut source = FromTokio::new(file);
    let transfer = send_with(
        client,
        &mut source,
        Metadata {
            filename: filename.as_bytes(),
            file_size,
        },
        ymodem_config(),
        notify,
    )
    .await
    .map_err(format_send_error)?;

    Ok(transfer.file_size as u64)
}
fn ymodem_config() -> Config {
    Config {
        // TelnetClient applies the CLI timeout to each embedded-io read. One
        // start retry therefore keeps startup bounded to one timed wait.
        start_retries: 1,
        ..Config::default()
    }
}
fn format_send_error(error: SendError<io::Error, io::Error, String>) -> String {
    match error {
        SendError::Io(error) => error.to_string(),
        SendError::Timeout => "YMODEM transfer timed out".to_owned(),
        SendError::EndOfStream => "Telnet connection closed during YMODEM transfer".to_owned(),
        SendError::Cancelled => "device cancelled YMODEM transfer".to_owned(),
        SendError::Protocol => "unexpected YMODEM protocol response".to_owned(),
        SendError::InvalidFilename => "YMODEM filename is empty or contains NUL".to_owned(),
        SendError::HeaderTooLong => "YMODEM filename is too long for block 0".to_owned(),
        SendError::UnexpectedEof => "upload file ended before its advertised size".to_owned(),
        SendError::InvalidSourceRead => "upload source returned an invalid read length".to_owned(),
        SendError::Source(error) => format!("read upload file: {error}"),
        SendError::Observer(error) => error,
    }
}
