use core::fmt;

use embedded_io::ErrorType;
use embedded_io_async::Write;
use heapless::String;

use crate::{Error, ErrorKind, telnet::IAC};

/// Telnet-aware writer adapter.
///
/// `Console` implements the standard [`embedded_io_async::Write`] trait. It escapes Telnet IAC
/// bytes in application output and normalizes the underlying transport error to [`ErrorKind`].
pub struct Console<'a, W: ?Sized> {
    writer: &'a mut W,
}

impl<'a, W: ?Sized> Console<'a, W> {
    pub fn new(writer: &'a mut W) -> Self {
        Self { writer }
    }
}

impl<W: ?Sized> ErrorType for Console<'_, W> {
    type Error = ErrorKind;
}

impl<W> Write for Console<'_, W>
where
    W: Write + ?Sized,
    W::Error: embedded_io::Error,
{
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, ErrorKind> {
        let mut start = 0usize;
        for (index, byte) in bytes.iter().copied().enumerate() {
            if byte == IAC {
                if start < index {
                    self.writer
                        .write_all(&bytes[start..index])
                        .await
                        .map_err(|e| embedded_io::Error::kind(&e))?;
                }
                self.writer
                    .write_all(&[IAC, IAC])
                    .await
                    .map_err(|e| embedded_io::Error::kind(&e))?;
                start = index + 1;
            }
        }
        if start < bytes.len() {
            self.writer
                .write_all(&bytes[start..])
                .await
                .map_err(|e| embedded_io::Error::kind(&e))?;
        }
        Ok(bytes.len())
    }

    async fn flush(&mut self) -> Result<(), ErrorKind> {
        self.writer
            .flush()
            .await
            .map_err(|e| embedded_io::Error::kind(&e))
    }
}

/// Write a UTF-8 string through a standard async writer.
pub(crate) async fn write_str<W>(out: &mut W, text: &str) -> Result<(), ErrorKind>
where
    W: Write<Error = ErrorKind> + ?Sized,
{
    out.write_all(text.as_bytes()).await
}

/// Write a UTF-8 string followed by the CLI's CRLF line ending.
pub(crate) async fn write_line<W>(out: &mut W, text: &str) -> Result<(), ErrorKind>
where
    W: Write<Error = ErrorKind> + ?Sized,
{
    out.write_all(text.as_bytes()).await?;
    out.write_all(b"\r\n").await
}

/// Format into bounded stack storage and write the resulting bytes.
///
/// The output writer itself uses only the standard [`embedded_io_async::Write`] interface. The
/// explicit `FMT` capacity keeps formatting separate from the writer trait itself.
pub async fn write_fmt<const FMT: usize, W>(
    out: &mut W,
    args: fmt::Arguments<'_>,
) -> Result<(), Error>
where
    W: Write<Error = ErrorKind> + ?Sized,
{
    let mut scratch = String::<FMT>::new();
    core::fmt::Write::write_fmt(&mut scratch, args).map_err(|_| Error::FormatOverflow)?;
    out.write_all(scratch.as_bytes()).await.map_err(Error::from)
}
