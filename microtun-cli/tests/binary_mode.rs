use core::convert::Infallible;

use futures_lite::future::block_on;
use heapless::Vec;
use microtun_cli::telnet::{
    BinaryMode, BinaryModeError, DO, DONT, IAC, OPT_BINARY, Telnet, WILL, WONT,
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

impl embedded_io::ErrorType for Loopback {
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
fn telnet_requests_and_tracks_binary_mode() {
    let mut telnet = Telnet::<64, 32>::new();
    let mut request = Vec::<u8, 6>::new();
    telnet.request_binary_mode(&mut request);
    assert_eq!(
        request.as_slice(),
        &[IAC, WILL, OPT_BINARY, IAC, DO, OPT_BINARY]
    );
    assert!(!telnet.binary_mode_enabled());

    let mut reply = Vec::<u8, 32>::new();
    for byte in [IAC, DO, OPT_BINARY, IAC, WILL, OPT_BINARY] {
        telnet.feed(byte, &mut reply);
    }
    assert!(telnet.binary_mode_enabled());
    assert!(reply.is_empty());
}

#[test]
fn shared_binary_mode_reuses_shell_telnet_state() {
    let mut telnet = Telnet::<64, 32>::new();
    let mut request = Vec::<u8, 6>::new();
    telnet.request_binary_mode(&mut request);
    let mut reply = Vec::<u8, 32>::new();
    for byte in [IAC, DO, OPT_BINARY, IAC, WILL, OPT_BINARY] {
        telnet.feed(byte, &mut reply);
    }

    let mut io = Loopback::new(&[0x01, IAC, IAC, 0x02]);
    block_on(async {
        let mut binary = BinaryMode::with_telnet(&mut io, &mut telnet);
        binary.negotiate().await.unwrap();
        assert_eq!(binary.read_byte().await.unwrap(), 0x01);
        assert_eq!(binary.read_byte().await.unwrap(), IAC);
        assert_eq!(binary.read_byte().await.unwrap(), 0x02);
    });

    // Already-enabled BINARY must not be requested again.
    assert!(io.output.is_empty());
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
fn binary_mode_preserves_payload_during_negotiation() {
    let script = [IAC, WILL, OPT_BINARY, b'x', IAC, DO, OPT_BINARY];
    let mut io = Loopback::new(&script);

    block_on(async {
        let mut binary = BinaryMode::new(&mut io);
        binary.negotiate().await.unwrap();
        assert_eq!(binary.read_byte().await.unwrap(), b'x');
    });
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
fn binary_mode_abort_uses_q_method_state() {
    let mut io = Loopback::new(&[IAC, DONT, OPT_BINARY]);

    block_on(async {
        let mut binary = BinaryMode::new(&mut io);
        assert_eq!(binary.negotiate().await, Err(BinaryModeError::Refused));
        binary.abort().await.unwrap();
    });

    assert_eq!(io.output, [IAC, WILL, OPT_BINARY, IAC, DO, OPT_BINARY]);
}
