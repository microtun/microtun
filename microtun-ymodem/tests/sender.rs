//! The sender against a scripted receiver, asserting exact bytes on the wire.

mod support;

use std::convert::Infallible;

use embedded_io_async::ErrorKind;
use microtun_ymodem::{Config, Metadata, SendError, SendEvent, Transfer, crc16, send, send_with};

use crate::support::{
    ACK, C, CAN, EOT, NAK, Script, Source, Step, data_frame, end_of_batch_frame, header_frame,
    payload, run,
};

type SendResult = Result<Transfer, SendError<ErrorKind, ErrorKind>>;

fn bytes(bytes: &[u8]) -> Step {
    Step::Bytes(bytes.to_vec())
}

fn send_scripted(
    steps: impl IntoIterator<Item = Step>,
    filename: &[u8],
    data: &[u8],
    config: Config,
) -> (SendResult, Script) {
    let mut transport = Script::new(steps);
    let mut source = Source::new(data, usize::MAX);
    let metadata = Metadata {
        filename,
        file_size: data.len(),
    };
    let result = run(send(&mut transport, &mut source, metadata, config));
    (result, transport)
}

/// Every receiver response for a successful transfer of `blocks` data blocks.
fn happy_receiver(blocks: usize) -> Vec<Step> {
    let mut steps = vec![bytes(&[C]), bytes(&[ACK]), bytes(&[C])];
    steps.extend((0..blocks).map(|_| bytes(&[ACK])));
    steps.extend([bytes(&[NAK]), bytes(&[ACK]), bytes(&[C]), bytes(&[ACK])]);
    steps
}

#[test]
fn crc16_matches_the_xmodem_check_value() {
    assert_eq!(crc16(b"123456789"), 0x31c3);
    assert_eq!(crc16(b""), 0x0000);
}

#[test]
fn writes_the_canonical_byte_stream() {
    let data = payload(1500);
    let (result, transport) = send_scripted(happy_receiver(2), b"fw.bin", &data, Config::default());
    assert_eq!(result, Ok(Transfer { file_size: 1500 }));
    assert!(transport.exhausted());

    let mut expected = header_frame(b"fw.bin\x001500");
    expected.extend(data_frame(1, &data[..1024]));
    expected.extend(data_frame(2, &data[1024..]));
    expected.extend([EOT, EOT]);
    expected.extend(end_of_batch_frame());
    assert_eq!(transport.written, expected);
}

#[test]
fn empty_file_sends_header_and_eot_only() {
    let (result, transport) = send_scripted(happy_receiver(0), b"empty", &[], Config::default());
    assert_eq!(result, Ok(Transfer { file_size: 0 }));

    let mut expected = header_frame(b"empty\x000");
    expected.extend([EOT, EOT]);
    expected.extend(end_of_batch_frame());
    assert_eq!(transport.written, expected);
}

#[test]
fn shell_output_before_the_crc_request_is_reported() {
    // Any uppercase 'C' in this text would be taken as the CRC request, so it must not appear.
    let mut steps = vec![bytes(b"send image now\r\n")];
    steps.extend(happy_receiver(0));
    let mut transport = Script::new(steps);
    let mut source = Source::new(&[], 1);
    let mut output = Vec::new();
    let metadata = Metadata {
        filename: b"f",
        file_size: 0,
    };
    let result = run(send_with(
        &mut transport,
        &mut source,
        metadata,
        Config::default(),
        async |event| {
            if let SendEvent::Output(byte) = event {
                output.push(byte);
            }
            Ok::<(), Infallible>(())
        },
    ));
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(output, b"send image now\r\n");
}

#[test]
fn observer_errors_abort_the_transfer() {
    let mut transport = Script::new(happy_receiver(0));
    let mut source = Source::new(&[], 1);
    let metadata = Metadata {
        filename: b"f",
        file_size: 0,
    };
    let result = run(send_with(
        &mut transport,
        &mut source,
        metadata,
        Config::default(),
        async |_| Err("stop"),
    ));
    assert_eq!(result, Err(SendError::Observer("stop")));
    assert!(
        transport.written.is_empty(),
        "nothing is sent once the observer fails"
    );
}

#[test]
fn rejects_invalid_metadata_without_touching_the_line() {
    let long_name = [b'a'; 126];
    for (filename, size, expected) in [
        (&b""[..], 1, SendError::InvalidFilename),
        (&b"bad\0name"[..], 1, SendError::InvalidFilename),
        // 126 name bytes + NUL + "10" + NUL = 130 > 128.
        (&long_name[..], 10, SendError::HeaderTooLong),
    ] {
        let data = payload(size);
        let (result, transport) = send_scripted([], filename, &data, Config::default());
        assert_eq!(result, Err(expected));
        assert!(transport.written.is_empty());
    }
}

#[test]
fn longest_valid_header_is_accepted() {
    // 125 name bytes + NUL + "1" + NUL = 128 exactly.
    let name = [b'n'; 125];
    let data = payload(1);
    let (result, transport) = send_scripted(happy_receiver(1), &name, &data, Config::default());
    assert!(result.is_ok(), "{result:?}");
    let mut expected_header = name.to_vec();
    expected_header.extend(b"\x001");
    assert_eq!(
        &transport.written[..133],
        &header_frame(&expected_header)[..]
    );
}

#[test]
fn retransmits_on_nak_then_succeeds() {
    let data = payload(10);
    let mut steps = vec![bytes(&[C]), bytes(&[ACK]), bytes(&[C])];
    steps.extend([bytes(&[NAK]), bytes(&[NAK]), bytes(&[ACK])]);
    steps.extend([bytes(&[NAK]), bytes(&[ACK]), bytes(&[C]), bytes(&[ACK])]);
    let (result, transport) = send_scripted(steps, b"f", &data, Config::default());
    assert!(result.is_ok(), "{result:?}");
    let block = data_frame(1, &data);
    let frames = transport
        .written
        .windows(block.len())
        .filter(|window| *window == &block[..])
        .count();
    assert_eq!(frames, 3, "block 1 is sent once plus two retransmissions");
}

#[test]
fn gives_up_after_max_retries_naks() {
    let config = Config {
        start_retries: 1,
        max_retries: 2,
    };
    let mut steps = vec![bytes(&[C])];
    steps.extend((0..3).map(|_| bytes(&[NAK])));
    let (result, transport) = send_scripted(steps, b"f", &payload(1), config);
    assert_eq!(result, Err(SendError::Protocol));
    assert_eq!(
        transport.written.len(),
        3 * 133,
        "header sent 1 + max_retries times"
    );
}

#[test]
fn retransmits_on_timeout_then_gives_up() {
    let config = Config {
        start_retries: 1,
        max_retries: 2,
    };
    let steps = [bytes(&[C]), Step::Timeout, Step::Timeout, Step::Timeout];
    let (result, transport) = send_scripted(steps, b"f", &payload(1), config);
    assert_eq!(result, Err(SendError::Timeout));
    assert_eq!(transport.written.len(), 3 * 133);
}

#[test]
fn start_retries_bound_the_wait_for_the_receiver() {
    let config = Config {
        start_retries: 3,
        max_retries: 16,
    };
    let steps = [Step::Timeout, Step::Timeout, Step::Timeout, bytes(&[C])];
    let (result, transport) = send_scripted(steps, b"f", &payload(1), config);
    assert_eq!(result, Err(SendError::Timeout));
    assert!(transport.written.is_empty());

    let config = Config {
        start_retries: 0,
        max_retries: 16,
    };
    let (result, _) = send_scripted([bytes(&[C])], b"f", &payload(1), config);
    assert_eq!(result, Err(SendError::Timeout));
}

#[test]
fn receiver_cancel_is_reported() {
    // While waiting for the initial C.
    let (result, _) = send_scripted([bytes(&[CAN])], b"f", &payload(1), Config::default());
    assert_eq!(result, Err(SendError::Cancelled));
    // In reply to a data block.
    let steps = [bytes(&[C]), bytes(&[ACK]), bytes(&[C]), bytes(&[CAN, CAN])];
    let (result, _) = send_scripted(steps, b"f", &payload(1), Config::default());
    assert_eq!(result, Err(SendError::Cancelled));
}

#[test]
fn unexpected_reply_is_a_protocol_error() {
    let steps = [bytes(&[C]), bytes(b"?")];
    let (result, _) = send_scripted(steps, b"f", &payload(1), Config::default());
    assert_eq!(result, Err(SendError::Protocol));

    // The first EOT must be NAKed; an immediate ACK is not the canonical exchange.
    let steps = [
        bytes(&[C]),
        bytes(&[ACK]),
        bytes(&[C]),
        bytes(&[ACK]),
        bytes(&[ACK]),
    ];
    let (result, _) = send_scripted(steps, b"f", &payload(1), Config::default());
    assert_eq!(result, Err(SendError::Protocol));
}

#[test]
fn closed_line_is_end_of_stream() {
    let (result, _) = send_scripted([Step::Eof], b"f", &payload(1), Config::default());
    assert_eq!(result, Err(SendError::EndOfStream));
    let (result, _) = send_scripted(
        [bytes(&[C]), Step::Eof],
        b"f",
        &payload(1),
        Config::default(),
    );
    assert_eq!(result, Err(SendError::EndOfStream));
}

#[test]
fn short_source_is_unexpected_eof() {
    let mut transport = Script::new(happy_receiver(1));
    let data = payload(10);
    let mut source = Source::new(&data, usize::MAX);
    let metadata = Metadata {
        filename: b"f",
        file_size: 20,
    };
    let result = run(send(
        &mut transport,
        &mut source,
        metadata,
        Config::default(),
    ));
    assert_eq!(result, Err(SendError::UnexpectedEof));
}
