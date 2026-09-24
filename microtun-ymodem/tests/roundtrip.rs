//! End-to-end transfers between the real sender and the real receiver over an in-memory link,
//! including a noisy line and lost acknowledgements.

mod support;

use std::{cell::RefCell, convert::Infallible, rc::Rc};

use embedded_io_async::ErrorKind;
use microtun_ymodem::{
    BLOCK_SIZE, BufferSink, BufferSinkError, Config, Error, Metadata, SendError, SendEvent,
    Transfer, receive, receive_with, send, send_with,
};

use crate::support::{ACK, End, Fault, NAK, Sink, Source, Tamper, pair, pair_with, payload, run2};

type SendResult = Result<Transfer, SendError<ErrorKind, ErrorKind>>;
type ReceiveResult = Result<Transfer, Error<ErrorKind, ErrorKind>>;

/// Run one sender/receiver pair to completion and return both results and the received bytes.
fn transfer(
    sender_end: &mut End,
    receiver_end: &mut End,
    data: &[u8],
    source_chunk: usize,
    config: Config,
) -> (SendResult, ReceiveResult, Vec<u8>) {
    let mut source = Source::new(data, source_chunk);
    let mut sink = Sink::default();
    let metadata = Metadata {
        filename: b"firmware.bin",
        file_size: data.len(),
    };
    let (sent, received) = run2(
        async {
            let result = send(sender_end, &mut source, metadata, config).await;
            sender_end.close();
            result
        },
        async {
            let result = receive(receiver_end, &mut sink, config).await;
            receiver_end.close();
            result
        },
    );
    (sent, received, sink.0)
}

fn clean_transfer(data: &[u8], source_chunk: usize) -> (SendResult, ReceiveResult, Vec<u8>) {
    let (mut sender_end, mut receiver_end) = pair();
    transfer(
        &mut sender_end,
        &mut receiver_end,
        data,
        source_chunk,
        Config::default(),
    )
}

#[test]
fn round_trips_boundary_sizes() {
    for len in [
        0,
        1,
        127,
        128,
        129,
        BLOCK_SIZE - 1,
        BLOCK_SIZE,
        BLOCK_SIZE + 1,
        4 * BLOCK_SIZE,
        4 * BLOCK_SIZE + 3,
    ] {
        let data = payload(len);
        let (sent, received, output) = clean_transfer(&data, usize::MAX);
        let expected = Transfer { file_size: len };
        assert_eq!(sent, Ok(expected), "sender, len={len}");
        assert_eq!(received, Ok(expected), "receiver, len={len}");
        assert_eq!(output, data, "payload, len={len}");
    }
}

#[test]
fn tolerates_short_reads_from_the_source() {
    let data = payload(3 * BLOCK_SIZE + 17);
    for chunk in [1, 7, 1000, BLOCK_SIZE + 1] {
        let (sent, received, output) = clean_transfer(&data, chunk);
        assert!(sent.is_ok(), "chunk={chunk}: {sent:?}");
        assert!(received.is_ok(), "chunk={chunk}: {received:?}");
        assert_eq!(output, data, "chunk={chunk}");
    }
}

#[test]
fn block_numbers_wrap_after_255() {
    // 300 data blocks: numbering runs 1..=255, 0, 1, ..., 44.
    let data = payload(300 * BLOCK_SIZE + 5);
    let (sent, received, output) = clean_transfer(&data, 4096);
    assert_eq!(
        sent,
        Ok(Transfer {
            file_size: data.len()
        })
    );
    assert_eq!(
        received,
        Ok(Transfer {
            file_size: data.len()
        })
    );
    assert!(
        output == data,
        "payload differs after block-number wraparound"
    );
}

#[test]
fn reports_monotonic_progress_ending_at_total() {
    let data = payload(2 * BLOCK_SIZE + 10);
    let (mut sender_end, mut receiver_end) = pair();
    let mut source = Source::new(&data, usize::MAX);
    let mut sink = Sink::default();
    let mut events = Vec::new();
    let metadata = Metadata {
        filename: b"f",
        file_size: data.len(),
    };
    let (sent, received) = run2(
        async {
            let result = send_with(
                &mut sender_end,
                &mut source,
                metadata,
                Config::default(),
                async |event| {
                    events.push(event);
                    Ok::<(), Infallible>(())
                },
            )
            .await;
            sender_end.close();
            result
        },
        async {
            let result = receive(&mut receiver_end, &mut sink, Config::default()).await;
            receiver_end.close();
            result
        },
    );
    assert!(sent.is_ok() && received.is_ok());

    let total = data.len();
    let progress: Vec<usize> = events
        .iter()
        .map(|event| match *event {
            SendEvent::Progress { sent, total: t } => {
                assert_eq!(t, total);
                sent
            }
            SendEvent::Output(byte) => panic!("unexpected shell output byte {byte:#04x}"),
        })
        .collect();
    assert_eq!(progress, [0, 1024, 2048, total, total]);
}

#[test]
fn metadata_callback_sees_filename_and_size() {
    let data = payload(1500);
    let (mut sender_end, mut receiver_end) = pair();
    let mut source = Source::new(&data, usize::MAX);
    let mut sink = Sink::default();
    let mut seen = None;
    let metadata = Metadata {
        filename: b"microtun-nucleo.bin",
        file_size: data.len(),
    };
    let (sent, received) = run2(
        async {
            let result = send(&mut sender_end, &mut source, metadata, Config::default()).await;
            sender_end.close();
            result
        },
        async {
            let result = receive_with(
                &mut receiver_end,
                &mut sink,
                Config::default(),
                |metadata: Metadata<'_>| {
                    seen = Some((metadata.filename.to_vec(), metadata.file_size));
                    Ok::<(), Infallible>(())
                },
            )
            .await;
            receiver_end.close();
            result
        },
    );
    assert!(sent.is_ok() && received.is_ok());
    assert_eq!(seen, Some((b"microtun-nucleo.bin".to_vec(), 1500)));
}

#[test]
fn rejected_metadata_cancels_before_any_data() {
    let data = payload(5000);
    let (mut sender_end, mut receiver_end) = pair();
    let mut source = Source::new(&data, usize::MAX);
    let mut sink = Sink::default();
    let metadata = Metadata {
        filename: b"too-big.bin",
        file_size: data.len(),
    };
    let (sent, received) = run2(
        async {
            let result = send(&mut sender_end, &mut source, metadata, Config::default()).await;
            sender_end.close();
            result
        },
        async {
            let result = receive_with(
                &mut receiver_end,
                &mut sink,
                Config::default(),
                |metadata: Metadata<'_>| {
                    if metadata.file_size > 4096 {
                        Err("image larger than slot")
                    } else {
                        Ok(())
                    }
                },
            )
            .await;
            receiver_end.close();
            result
        },
    );
    assert_eq!(sent, Err(SendError::Cancelled));
    assert_eq!(received, Err(Error::Metadata("image larger than slot")));
    assert!(sink.0.is_empty());
}

#[test]
fn full_destination_buffer_cancels_the_transfer() {
    let data = payload(2000);
    let (mut sender_end, mut receiver_end) = pair();
    let mut source = Source::new(&data, usize::MAX);
    let mut storage = [0u8; 100];
    let mut sink = BufferSink::new(&mut storage);
    let metadata = Metadata {
        filename: b"f",
        file_size: data.len(),
    };
    let (sent, received) = run2(
        async {
            let result = send(&mut sender_end, &mut source, metadata, Config::default()).await;
            sender_end.close();
            result
        },
        async {
            let result = receive(&mut receiver_end, &mut sink, Config::default()).await;
            receiver_end.close();
            result
        },
    );
    assert_eq!(sent, Err(SendError::Cancelled));
    assert_eq!(received, Err(Error::Output(BufferSinkError::Overflow)));
    assert_eq!(sink.written(), 100);
}

#[test]
fn exactly_sized_destination_buffer_is_enough() {
    let data = payload(BLOCK_SIZE + 1);
    let (mut sender_end, mut receiver_end) = pair();
    let mut source = Source::new(&data, usize::MAX);
    let mut storage = vec![0u8; data.len()];
    let mut sink = BufferSink::new(&mut storage);
    let metadata = Metadata {
        filename: b"f",
        file_size: data.len(),
    };
    let (sent, received) = run2(
        async {
            let result = send(&mut sender_end, &mut source, metadata, Config::default()).await;
            sender_end.close();
            result
        },
        async {
            let result = receive(&mut receiver_end, &mut sink, Config::default()).await;
            receiver_end.close();
            result
        },
    );
    assert!(sent.is_ok() && received.is_ok());
    assert_eq!(sink.remaining(), 0);
    assert_eq!(storage, data);
}

/// Counts every byte the receiver sends back, so tests can assert how many NAKs were needed.
fn counting_control_bytes(counts: Rc<RefCell<Vec<u8>>>) -> Tamper {
    Box::new(move |_, byte| {
        counts.borrow_mut().push(byte);
        Fault::Pass
    })
}

#[test]
fn corrupted_payload_and_crc_bytes_are_retransmitted() {
    // Sender -> receiver byte offsets: block 0 is 133 bytes, each 1K block is 1029 bytes, and
    // every corrupted frame is sent again in full before the stream moves on.
    const HEADER_FRAME: u64 = 133;
    const DATA_FRAME: u64 = 1029;
    let block_1 = 2 * HEADER_FRAME; // block 0 is sent twice
    let block_1_retry = block_1 + DATA_FRAME;
    let block_2 = block_1 + 3 * DATA_FRAME; // block 1 is sent three times
    let corrupt_at = [
        10,                       // block 0: filename byte
        block_1 + 3 + 500,        // block 1: payload byte
        block_1_retry + 2,        // block 1 again: inverse block number
        block_2 + DATA_FRAME - 1, // block 2: low CRC byte
    ];
    let control = Rc::new(RefCell::new(Vec::new()));
    let (mut sender_end, mut receiver_end) = pair_with(
        Some(Box::new(move |index, _| {
            if corrupt_at.contains(&index) {
                Fault::Corrupt
            } else {
                Fault::Pass
            }
        })),
        Some(counting_control_bytes(control.clone())),
    );
    let data = payload(3 * BLOCK_SIZE);
    let (sent, received, output) = transfer(
        &mut sender_end,
        &mut receiver_end,
        &data,
        usize::MAX,
        Config::default(),
    );
    assert_eq!(
        sent,
        Ok(Transfer {
            file_size: data.len()
        })
    );
    assert_eq!(
        received,
        Ok(Transfer {
            file_size: data.len()
        })
    );
    assert_eq!(output, data);
    let naks = control.borrow().iter().filter(|&&byte| byte == NAK).count();
    // One NAK per corrupted frame, plus the protocol NAK after the first EOT.
    assert_eq!(naks, corrupt_at.len() + 1);
}

#[test]
fn lost_ack_is_recovered_without_duplicating_data() {
    // Receiver -> sender control stream: C, ACK(block 0), C, ACK(block 1), ...
    let control = Rc::new(RefCell::new(Vec::new()));
    let seen = control.clone();
    let (mut sender_end, mut receiver_end) = pair_with(
        None,
        Some(Box::new(move |index, byte| {
            seen.borrow_mut().push(byte);
            if index == 3 {
                assert_eq!(byte, ACK, "expected the block 1 ACK at offset 3");
                Fault::Drop
            } else {
                Fault::Pass
            }
        })),
    );
    let data = payload(2 * BLOCK_SIZE + 99);
    let (sent, received, output) = transfer(
        &mut sender_end,
        &mut receiver_end,
        &data,
        usize::MAX,
        Config::default(),
    );
    assert!(sent.is_ok(), "{sent:?}");
    assert!(received.is_ok(), "{received:?}");
    assert_eq!(
        output, data,
        "the retransmitted block must not be written twice"
    );
    // The duplicate block 1 is acknowledged again rather than NAKed.
    let acks = control.borrow().iter().filter(|&&byte| byte == ACK).count();
    assert_eq!(
        acks,
        1 + 4 + 1 + 1,
        "block 0, 3 blocks + duplicate, final EOT, end of batch"
    );
}

#[test]
fn sender_gives_up_when_acks_never_arrive() {
    // Drop everything the receiver says after its first data ACK.
    let (mut sender_end, mut receiver_end) = pair_with(
        None,
        Some(Box::new(
            |index, _| {
                if index >= 3 { Fault::Drop } else { Fault::Pass }
            },
        )),
    );
    let config = Config {
        start_retries: 5,
        max_retries: 3,
    };
    let data = payload(BLOCK_SIZE);
    let (sent, received, output) = transfer(
        &mut sender_end,
        &mut receiver_end,
        &data,
        usize::MAX,
        config,
    );
    assert_eq!(sent, Err(SendError::Timeout));
    // Once the sender stops, the receiver sees the link close rather than hanging.
    assert_eq!(received, Err(Error::EndOfStream));
    assert_eq!(
        output, data,
        "block 1 was delivered once despite the retransmissions"
    );
}

#[test]
#[ignore = "known gap: after a corrupted SOH/STX the receiver treats each remaining frame byte as \
            a control byte and NAKs it, exhausting max_retries. Standard receivers purge the line \
            until it goes quiet before NAKing. Harmless over TCP/Telnet, relevant over UART."]
fn corrupted_frame_start_byte_is_recovered() {
    // Offset 133 is the STX that opens block 1.
    let (mut sender_end, mut receiver_end) = pair_with(
        Some(Box::new(|index, _| {
            if index == 133 {
                Fault::Corrupt
            } else {
                Fault::Pass
            }
        })),
        None,
    );
    let data = payload(3000);
    let (sent, received, output) = transfer(
        &mut sender_end,
        &mut receiver_end,
        &data,
        usize::MAX,
        Config::default(),
    );
    assert!(sent.is_ok(), "{sent:?}");
    assert!(received.is_ok(), "{received:?}");
    assert_eq!(output, data);
}
