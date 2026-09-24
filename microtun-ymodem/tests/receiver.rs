//! The receiver against a scripted sender, asserting exact control bytes on the wire.

mod support;

use std::convert::Infallible;

use embedded_io_async::ErrorKind;
use microtun_ymodem::{Config, Error, Metadata, Transfer, receive, receive_with};

use crate::support::{
    ACK, C, CAN, EOT, NAK, SOH, STX, Script, Sink, Step, data_frame, end_of_batch_frame, frame,
    header_frame, payload, run,
};

type ReceiveResult = Result<Transfer, Error<ErrorKind, ErrorKind>>;

fn bytes(bytes: &[u8]) -> Step {
    Step::Bytes(bytes.to_vec())
}

fn receive_scripted(
    steps: impl IntoIterator<Item = Step>,
    config: Config,
) -> (ReceiveResult, Script, Vec<u8>) {
    let mut transport = Script::new(steps);
    let mut sink = Sink::default();
    let result = run(receive(&mut transport, &mut sink, config));
    (result, transport, sink.0)
}

/// The sender's side of a clean transfer of `data` in 1K blocks.
fn clean_sender(metadata: &[u8], data: &[u8]) -> Vec<Step> {
    let mut steps = vec![Step::Bytes(header_frame(metadata))];
    for (index, chunk) in data.chunks(1024).enumerate() {
        steps.push(Step::Bytes(data_frame(index as u8 + 1, chunk)));
    }
    steps.extend([
        bytes(&[EOT]),
        bytes(&[EOT]),
        Step::Bytes(end_of_batch_frame()),
    ]);
    steps
}

#[test]
fn answers_a_clean_transfer_with_the_canonical_control_bytes() {
    let data = payload(1500);
    let (result, transport, output) =
        receive_scripted(clean_sender(b"fw.bin\x001500", &data), Config::default());
    assert_eq!(result, Ok(Transfer { file_size: 1500 }));
    assert_eq!(output, data, "padding in the last block is discarded");
    assert_eq!(transport.written, [C, ACK, C, ACK, ACK, NAK, ACK, C, ACK]);
    assert!(transport.exhausted());
}

#[test]
fn accepts_128_byte_data_blocks() {
    let data = payload(200);
    let mut steps = vec![Step::Bytes(header_frame(b"f\x00200"))];
    steps.push(Step::Bytes(frame(SOH, 1, &data[..128])));
    let mut tail = [0x1a; 128];
    tail[..72].copy_from_slice(&data[128..]);
    steps.push(Step::Bytes(frame(SOH, 2, &tail)));
    steps.extend([
        bytes(&[EOT]),
        bytes(&[EOT]),
        Step::Bytes(end_of_batch_frame()),
    ]);
    let (result, _, output) = receive_scripted(steps, Config::default());
    assert_eq!(result, Ok(Transfer { file_size: 200 }));
    assert_eq!(output, data);
}

#[test]
fn parses_optional_header_fields_after_the_size() {
    // `name NUL size SP mtime SP mode`, as written by lrzsz.
    let data = payload(3);
    let (result, _, output) = receive_scripted(
        clean_sender(b"fw.bin\x003 14706712040 100644", &data),
        Config::default(),
    );
    assert_eq!(result, Ok(Transfer { file_size: 3 }));
    assert_eq!(output, data);
}

#[test]
fn metadata_borrowed_from_block_zero_is_visible_to_the_callback() {
    let data = payload(1);
    let mut transport = Script::new(clean_sender(b"microtun.bin\x001", &data));
    let mut sink = Sink::default();
    let mut seen = Vec::new();
    let result = run(receive_with(
        &mut transport,
        &mut sink,
        Config::default(),
        |metadata: Metadata<'_>| {
            seen.extend_from_slice(metadata.filename);
            Ok::<(), Infallible>(())
        },
    ));
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(seen, b"microtun.bin");
}

#[test]
fn malformed_metadata_cancels() {
    for metadata in [
        &b"\x005"[..],                        // empty filename
        b"fw.bin\x00",                        // missing size
        b"fw.bin\x0012x",                     // non-decimal size
        b"fw.bin\x0099999999999999999999999", // overflows usize
    ] {
        let (result, transport, output) =
            receive_scripted([Step::Bytes(header_frame(metadata))], Config::default());
        assert_eq!(result, Err(Error::Protocol), "{metadata:?}");
        assert_eq!(transport.written, [C, CAN, CAN], "{metadata:?}");
        assert!(output.is_empty());
    }
}

#[test]
fn duplicate_block_is_acknowledged_but_not_written_twice() {
    let data = payload(1500);
    let block_1 = data_frame(1, &data[..1024]);
    let steps = [
        Step::Bytes(header_frame(b"f\x001500")),
        Step::Bytes(block_1.clone()),
        Step::Bytes(block_1),
        Step::Bytes(data_frame(2, &data[1024..])),
        bytes(&[EOT]),
        bytes(&[EOT]),
        Step::Bytes(end_of_batch_frame()),
    ];
    let (result, transport, output) = receive_scripted(steps, Config::default());
    assert_eq!(result, Ok(Transfer { file_size: 1500 }));
    assert_eq!(output, data);
    assert_eq!(
        transport.written,
        [C, ACK, C, ACK, ACK, ACK, NAK, ACK, C, ACK]
    );
}

#[test]
fn bad_crc_and_out_of_sequence_blocks_are_naked() {
    let data = payload(1024);
    let mut corrupt = data_frame(1, &data);
    corrupt[500] ^= 0x40;
    let steps = [
        Step::Bytes(header_frame(b"f\x001024")),
        Step::Bytes(corrupt),
        Step::Bytes(data_frame(3, &data)),
        Step::Bytes(data_frame(1, &data)),
        bytes(&[EOT]),
        bytes(&[EOT]),
        Step::Bytes(end_of_batch_frame()),
    ];
    let (result, transport, output) = receive_scripted(steps, Config::default());
    assert_eq!(result, Ok(Transfer { file_size: 1024 }));
    assert_eq!(output, data);
    assert_eq!(
        transport.written,
        [C, ACK, C, NAK, NAK, ACK, NAK, ACK, C, ACK]
    );
}

#[test]
fn gives_up_after_max_retries_bad_frames() {
    let config = Config {
        start_retries: 1,
        max_retries: 2,
    };
    let mut bad_header = header_frame(b"f\x001");
    bad_header[10] ^= 1;
    let steps = (0..3).map(|_| Step::Bytes(bad_header.clone()));
    let (result, transport, _) = receive_scripted(steps, config);
    assert_eq!(result, Err(Error::Protocol));
    assert_eq!(transport.written, [C, NAK, NAK, CAN, CAN]);
}

#[test]
fn eot_before_the_advertised_size_cancels() {
    let data = payload(10);
    let steps = [
        Step::Bytes(header_frame(b"f\x002000")),
        Step::Bytes(data_frame(1, &data)),
        bytes(&[EOT]),
    ];
    let (result, transport, _) = receive_scripted(steps, Config::default());
    assert_eq!(result, Err(Error::Protocol));
    assert_eq!(transport.written, [C, ACK, C, ACK, CAN, CAN]);
}

#[test]
fn data_beyond_the_advertised_size_cancels() {
    let data = payload(1024);
    let steps = [
        Step::Bytes(header_frame(b"f\x001024")),
        Step::Bytes(data_frame(1, &data)),
        Step::Bytes(data_frame(2, &data)),
    ];
    let (result, transport, output) = receive_scripted(steps, Config::default());
    assert_eq!(result, Err(Error::Protocol));
    assert_eq!(transport.written, [C, ACK, C, ACK, CAN, CAN]);
    assert_eq!(output.len(), 1024);
}

#[test]
fn second_eot_is_required() {
    let steps = [
        Step::Bytes(header_frame(b"f\x000")),
        bytes(&[EOT]),
        bytes(&[STX]),
    ];
    let (result, transport, _) = receive_scripted(steps, Config::default());
    assert_eq!(result, Err(Error::Protocol));
    assert_eq!(transport.written, [C, ACK, C, NAK, CAN, CAN]);
}

#[test]
fn start_retries_bound_the_crc_requests() {
    let config = Config {
        start_retries: 3,
        max_retries: 16,
    };
    let steps = [Step::Timeout, Step::Timeout, Step::Timeout];
    let (result, transport, _) = receive_scripted(steps, config);
    assert_eq!(result, Err(Error::Timeout));
    assert_eq!(transport.written, [C, C, C], "one C per start attempt");
}

#[test]
fn sender_cancel_is_reported() {
    let (result, _, _) = receive_scripted([bytes(&[CAN])], Config::default());
    assert_eq!(result, Err(Error::Cancelled));

    let steps = [Step::Bytes(header_frame(b"f\x0010")), bytes(&[CAN])];
    let (result, _, _) = receive_scripted(steps, Config::default());
    assert_eq!(result, Err(Error::Cancelled));
}

#[test]
fn closed_line_is_end_of_stream() {
    let (result, _, _) = receive_scripted([Step::Eof], Config::default());
    assert_eq!(result, Err(Error::EndOfStream));

    // Mid-frame.
    let header = header_frame(b"f\x0010");
    let (result, _, _) = receive_scripted([Step::Bytes(header[..50].to_vec())], Config::default());
    assert_eq!(result, Err(Error::EndOfStream));
}

#[test]
fn timeout_mid_transfer_is_reported() {
    let steps = [Step::Bytes(header_frame(b"f\x0010")), Step::Timeout];
    let (result, transport, _) = receive_scripted(steps, Config::default());
    assert_eq!(result, Err(Error::Timeout));
    assert_eq!(transport.written, [C, ACK, C]);
}
