use core::convert::Infallible;

use futures_lite::future::block_on;
use microtun_telnet::{
    BinaryMode, BinaryModeError, DO, DONT, IAC, OPT_BINARY, WILL, WONT, write_data_unflushed,
};

struct Loopback {
    input: std::vec::Vec<u8>,
    read_at: usize,
    output: std::vec::Vec<u8>,
}

impl Loopback {
    fn new(input: &[u8]) -> Self {
        Self {
            input: input.to_vec(),
            read_at: 0,
            output: std::vec::Vec::new(),
        }
    }
}

impl embedded_io_async::ErrorType for Loopback {
    type Error = Infallible;
}

impl embedded_io_async::Read for Loopback {
    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Self::Error> {
        let remaining = self.input.len().saturating_sub(self.read_at);
        if remaining == 0 {
            return Ok(0);
        }
        let count = remaining.min(buffer.len());
        buffer[..count].copy_from_slice(&self.input[self.read_at..self.read_at + count]);
        self.read_at += count;
        Ok(count)
    }
}

impl embedded_io_async::Write for Loopback {
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, Self::Error> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
fn binary_mode_preserves_buffered_payload_and_unescapes_iac() {
    let script = [
        IAC, DO, OPT_BINARY, IAC, WILL, OPT_BINARY, 0x01, IAC, IAC, 0x02,
    ];
    let mut io = Loopback::new(&script);

    block_on(async {
        let mut binary = BinaryMode::new(&mut io);
        binary.negotiate().await.unwrap();
        assert_eq!(binary.read_byte().await.unwrap(), 0x01);
        assert_eq!(binary.read_byte().await.unwrap(), IAC);
        assert_eq!(binary.read_byte().await.unwrap(), 0x02);
    });

    assert_eq!(io.output, [IAC, WILL, OPT_BINARY, IAC, DO, OPT_BINARY]);
}

#[test]
fn binary_mode_rejects_explicit_refusal() {
    let mut io = Loopback::new(&[IAC, DONT, OPT_BINARY]);
    let error = block_on(async {
        let mut binary = BinaryMode::new(&mut io);
        binary.negotiate().await
    })
    .unwrap_err();
    assert_eq!(error, BinaryModeError::Refused);
}

#[test]
fn binary_mode_rejects_payload_before_agreement() {
    let mut io = Loopback::new(b"x");
    let error = block_on(async {
        let mut binary = BinaryMode::new(&mut io);
        binary.negotiate().await
    })
    .unwrap_err();
    assert_eq!(error, BinaryModeError::UnexpectedData);
}

#[test]
fn binary_mode_escapes_iac_and_can_leave_binary_mode() {
    let script = [IAC, DO, OPT_BINARY, IAC, WILL, OPT_BINARY];
    let mut io = Loopback::new(&script);

    block_on(async {
        let mut binary = BinaryMode::new(&mut io);
        binary.negotiate().await.unwrap();
        binary.write_all(&[0x01, IAC, 0x02]).await.unwrap();
        binary.finish().await.unwrap();
    });

    assert_eq!(
        io.output,
        [
            IAC, WILL, OPT_BINARY, IAC, DO, OPT_BINARY, 0x01, IAC, IAC, 0x02, IAC, WONT,
            OPT_BINARY, IAC, DONT, OPT_BINARY,
        ]
    );
}

#[test]
fn binary_mode_abort_resets_partial_negotiation() {
    let mut io = Loopback::new(&[IAC, DONT, OPT_BINARY]);

    block_on(async {
        let mut binary = BinaryMode::new(&mut io);
        assert_eq!(binary.negotiate().await, Err(BinaryModeError::Refused));
        binary.abort().await.unwrap();
    });

    assert_eq!(
        io.output,
        [
            IAC, WILL, OPT_BINARY, IAC, DO, OPT_BINARY, IAC, WONT, OPT_BINARY, IAC, DONT,
            OPT_BINARY,
        ]
    );
}

#[test]
fn unflushed_writer_uses_the_same_iac_framing() {
    let mut io = Loopback::new(&[]);

    block_on(write_data_unflushed(&mut io, &[0x01, IAC, 0x02])).unwrap();

    assert_eq!(io.output, [0x01, IAC, IAC, 0x02]);
}
