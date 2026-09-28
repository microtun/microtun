use core::convert::Infallible;

use futures_lite::future::block_on;
use heapless::Vec;
use microtun_telnet::{
    BinaryMode, BinaryModeError, DO, DONT, IAC, OPT_BINARY, Policy, Telnet, WILL, WONT,
    write_data_unflushed,
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

#[derive(Clone, Copy, Default)]
struct BinaryPolicy;

impl Policy for BinaryPolicy {
    fn support_us(&self, option: u8) -> bool {
        option == OPT_BINARY
    }

    fn support_him(&self, option: u8) -> bool {
        option == OPT_BINARY
    }
}

#[test]
fn binary_mode_preserves_payload_and_unescapes_iac() {
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
fn binary_mode_preserves_data_that_arrives_while_other_direction_is_negotiating() {
    let script = [IAC, WILL, OPT_BINARY, b'x', IAC, DO, OPT_BINARY, b'y'];
    let mut io = Loopback::new(&script);

    block_on(async {
        let mut binary = BinaryMode::new(&mut io);
        binary.negotiate().await.unwrap();
        assert_eq!(binary.read_byte().await.unwrap(), b'x');
        assert_eq!(binary.read_byte().await.unwrap(), b'y');
    });
}

#[test]
fn shared_telnet_state_does_not_renegotiate_binary_when_already_enabled() {
    let mut telnet = Telnet::<BinaryPolicy, 16, 4>::new(BinaryPolicy);
    let mut initial = Vec::<u8, 6>::new();
    telnet.request_binary_mode(&mut initial);
    let mut reply = Vec::<u8, 16>::new();
    for byte in [IAC, DO, OPT_BINARY, IAC, WILL, OPT_BINARY] {
        telnet.feed(byte, &mut reply);
    }
    assert!(telnet.binary_mode_enabled());

    let mut io = Loopback::new(&[]);
    block_on(async {
        let mut binary = BinaryMode::with_telnet(&mut io, &mut telnet);
        binary.negotiate().await.unwrap();
    });
    assert!(io.output.is_empty());
}

#[test]
fn binary_mode_does_not_read_ahead_across_mode_handoff() {
    let script = [
        IAC, DO, OPT_BINARY, IAC, WILL, OPT_BINARY, 0x01, b'n', b'e', b'x', b't',
    ];
    let mut io = Loopback::new(&script);

    block_on(async {
        let mut binary = BinaryMode::new(&mut io);
        binary.negotiate().await.unwrap();
        assert_eq!(binary.read_byte().await.unwrap(), 0x01);
        binary.finish().await.unwrap();
    });

    // Negotiation consumed six wire bytes and the application consumed one. The following bytes
    // remain in the transport for whatever mode takes ownership next.
    assert_eq!(io.read_at, 7);
    assert_eq!(&io.input[io.read_at..], b"next");
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
fn binary_mode_abort_queues_q_method_reversal_instead_of_forcing_commands() {
    let mut io = Loopback::new(&[IAC, DONT, OPT_BINARY]);

    block_on(async {
        let mut binary = BinaryMode::new(&mut io);
        assert_eq!(binary.negotiate().await, Err(BinaryModeError::Refused));
        binary.abort().await.unwrap();
    });

    // Our WILL was refused immediately, but DO BINARY is still outstanding. RFC 1143 records the
    // opposite desire without emitting DONT until the peer's WILL/WONT response arrives.
    assert_eq!(io.output, [IAC, WILL, OPT_BINARY, IAC, DO, OPT_BINARY]);
}

#[test]
fn shared_abort_emits_disable_when_the_outstanding_enable_reply_arrives() {
    let mut telnet = Telnet::<BinaryPolicy, 16, 4>::new(BinaryPolicy);
    let mut io = Loopback::new(&[IAC, DONT, OPT_BINARY]);

    block_on(async {
        let mut binary = BinaryMode::with_telnet(&mut io, &mut telnet);
        assert_eq!(binary.negotiate().await, Err(BinaryModeError::Refused));
        binary.abort().await.unwrap();
    });
    assert_eq!(io.output, [IAC, WILL, OPT_BINARY, IAC, DO, OPT_BINARY]);

    let mut reply = Vec::<u8, 16>::new();
    for byte in [IAC, WILL, OPT_BINARY] {
        telnet.feed(byte, &mut reply);
    }
    assert_eq!(reply.as_slice(), &[IAC, DONT, OPT_BINARY]);
}

#[test]
fn unflushed_writer_uses_the_same_iac_framing() {
    let mut io = Loopback::new(&[]);

    block_on(write_data_unflushed(&mut io, &[0x01, IAC, 0x02])).unwrap();

    assert_eq!(io.output, [0x01, IAC, IAC, 0x02]);
}
