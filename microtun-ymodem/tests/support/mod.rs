//! In-memory transports for exercising the YMODEM sender and receiver on the host.
//!
//! [`pair`] connects a sender and a receiver through two byte queues. Neither side has a real
//! clock, so timeouts are modelled deterministically: when both ends are blocked reading with
//! nothing in flight, the end that started waiting first receives [`ErrorKind::TimedOut`], which
//! is what equal wall-clock timeouts would produce. Each direction can be given a [`Tamper`]
//! hook that corrupts or drops individual bytes to simulate a noisy line.
//!
//! [`Script`] is a one-sided transport that replays canned peer bytes, timeouts, and EOF, and
//! records everything written to it, for tests that need to see exact protocol bytes.

#![allow(dead_code)]

use std::{
    cell::RefCell,
    collections::VecDeque,
    future::{Future, poll_fn},
    rc::Rc,
    task::{Poll, Waker},
};

use embedded_io_async::{ErrorKind, ErrorType, Read, Write};
use microtun_ymodem::{BLOCK_SIZE, HEADER_BLOCK_SIZE, crc16};

pub const SOH: u8 = 0x01;
pub const STX: u8 = 0x02;
pub const EOT: u8 = 0x04;
pub const ACK: u8 = 0x06;
pub const NAK: u8 = 0x15;
pub const CAN: u8 = 0x18;
pub const C: u8 = b'C';

/// What happens to one byte written into a tampered direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Pass,
    /// Deliver the byte with every bit inverted.
    Corrupt,
    /// Silently lose the byte.
    Drop,
}

/// Decides the fate of each byte, given its zero-based index within that direction.
pub type Tamper = Box<dyn FnMut(u64, u8) -> Fault>;

#[derive(Default)]
struct Side {
    inbox: VecDeque<u8>,
    /// Ordering stamp taken when this end started blocking on an empty inbox.
    waiting_since: Option<u64>,
    timed_out: bool,
    closed: bool,
    waker: Option<Waker>,
    bytes_written: u64,
}

#[derive(Default)]
struct Shared {
    sides: [Side; 2],
    clock: u64,
    tamper: [Option<Tamper>; 2],
}

/// One end of an in-memory duplex link.
pub struct End {
    shared: Rc<RefCell<Shared>>,
    me: usize,
}

pub fn pair() -> (End, End) {
    pair_with(None, None)
}

/// Build a link whose `a -> b` and `b -> a` directions are filtered by the given hooks.
pub fn pair_with(a_to_b: Option<Tamper>, b_to_a: Option<Tamper>) -> (End, End) {
    let shared = Rc::new(RefCell::new(Shared {
        tamper: [a_to_b, b_to_a],
        ..Shared::default()
    }));
    (
        End {
            shared: shared.clone(),
            me: 0,
        },
        End { shared, me: 1 },
    )
}

impl End {
    fn peer(&self) -> usize {
        1 - self.me
    }

    /// Signal EOF to the other end once this side's protocol run has finished.
    pub fn close(&self) {
        let mut shared = self.shared.borrow_mut();
        shared.sides[self.me].closed = true;
        if let Some(waker) = shared.sides[self.peer()].waker.take() {
            waker.wake();
        }
    }
}

impl ErrorType for End {
    type Error = ErrorKind;
}

impl Read for End {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        let (me, peer) = (self.me, self.peer());
        poll_fn(|cx| {
            let mut shared = self.shared.borrow_mut();
            let shared = &mut *shared;
            if !shared.sides[me].inbox.is_empty() {
                let side = &mut shared.sides[me];
                let count = buf.len().min(side.inbox.len());
                for (slot, byte) in buf.iter_mut().zip(side.inbox.drain(..count)) {
                    *slot = byte;
                }
                side.waiting_since = None;
                side.timed_out = false;
                return Poll::Ready(Ok(count));
            }
            if shared.sides[me].timed_out {
                shared.sides[me].timed_out = false;
                shared.sides[me].waiting_since = None;
                return Poll::Ready(Err(ErrorKind::TimedOut));
            }
            if shared.sides[peer].closed {
                return Poll::Ready(Ok(0));
            }
            let mine = match shared.sides[me].waiting_since {
                Some(stamp) => stamp,
                None => {
                    shared.clock += 1;
                    shared.sides[me].waiting_since = Some(shared.clock);
                    shared.clock
                }
            };
            shared.sides[me].waker = Some(cx.waker().clone());
            if let Some(theirs) = shared.sides[peer].waiting_since {
                // Both ends are idle with nothing in flight: the earlier wait expires first.
                if mine < theirs {
                    shared.sides[me].waiting_since = None;
                    return Poll::Ready(Err(ErrorKind::TimedOut));
                }
                shared.sides[peer].timed_out = true;
                if let Some(waker) = shared.sides[peer].waker.take() {
                    waker.wake();
                }
            }
            Poll::Pending
        })
        .await
    }
}

impl Write for End {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let mut shared = self.shared.borrow_mut();
        let shared = &mut *shared;
        let (me, peer) = (self.me, self.peer());
        let mut delivered = false;
        for &byte in buf {
            let index = shared.sides[me].bytes_written;
            shared.sides[me].bytes_written += 1;
            let fault = shared.tamper[me]
                .as_mut()
                .map_or(Fault::Pass, |tamper| tamper(index, byte));
            match fault {
                Fault::Pass => shared.sides[peer].inbox.push_back(byte),
                Fault::Corrupt => shared.sides[peer].inbox.push_back(!byte),
                Fault::Drop => continue,
            }
            delivered = true;
        }
        if delivered {
            // The peer has work now, so it no longer counts as idle for timeout ordering.
            shared.sides[peer].waiting_since = None;
            if let Some(waker) = shared.sides[peer].waker.take() {
                waker.wake();
            }
        }
        Ok(buf.len())
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// One scripted event seen by the code under test when it reads from a [`Script`].
#[derive(Clone, Debug)]
pub enum Step {
    Bytes(Vec<u8>),
    Timeout,
    Eof,
}

/// A transport that replays scripted peer input and records all output.
#[derive(Default)]
pub struct Script {
    steps: VecDeque<Step>,
    pending: VecDeque<u8>,
    pub written: Vec<u8>,
}

impl Script {
    pub fn new(steps: impl IntoIterator<Item = Step>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            ..Self::default()
        }
    }

    /// Whether every scripted byte and event was consumed.
    pub fn exhausted(&self) -> bool {
        self.steps.is_empty() && self.pending.is_empty()
    }
}

impl ErrorType for Script {
    type Error = ErrorKind;
}

impl Read for Script {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.pending.is_empty() {
            match self.steps.pop_front() {
                Some(Step::Bytes(bytes)) => self.pending.extend(bytes),
                Some(Step::Timeout) => return Err(ErrorKind::TimedOut),
                Some(Step::Eof) | None => return Ok(0),
            }
        }
        let count = buf.len().min(self.pending.len());
        for (slot, byte) in buf.iter_mut().zip(self.pending.drain(..count)) {
            *slot = byte;
        }
        Ok(count)
    }
}

impl Write for Script {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.written.extend_from_slice(buf);
        Ok(buf.len())
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// A file source that hands out at most `chunk` bytes per read, to exercise short reads.
pub struct Source<'a> {
    data: &'a [u8],
    chunk: usize,
}

impl<'a> Source<'a> {
    pub fn new(data: &'a [u8], chunk: usize) -> Self {
        Self { data, chunk }
    }
}

impl ErrorType for Source<'_> {
    type Error = ErrorKind;
}

impl Read for Source<'_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let count = buf.len().min(self.chunk).min(self.data.len());
        buf[..count].copy_from_slice(&self.data[..count]);
        self.data = &self.data[count..];
        Ok(count)
    }
}

/// A growable output sink.
#[derive(Default)]
pub struct Sink(pub Vec<u8>);

impl ErrorType for Sink {
    type Error = ErrorKind;
}

impl Write for Sink {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Deterministic, non-repeating-looking test payload.
pub fn payload(len: usize) -> Vec<u8> {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

/// Encode one YMODEM frame with CRC-16.
pub fn frame(control: u8, block: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![control, block, !block];
    out.extend_from_slice(data);
    out.extend_from_slice(&crc16(data).to_be_bytes());
    out
}

/// Encode a 128-byte block 0 from raw metadata text (`name\0size...`).
pub fn header_frame(metadata: &[u8]) -> Vec<u8> {
    let mut data = [0u8; HEADER_BLOCK_SIZE];
    data[..metadata.len()].copy_from_slice(metadata);
    frame(SOH, 0, &data)
}

/// Encode a 1K data block, padding the payload with `SUB` like the sender does.
pub fn data_frame(block: u8, payload: &[u8]) -> Vec<u8> {
    let mut data = [0x1a; BLOCK_SIZE];
    data[..payload.len()].copy_from_slice(payload);
    frame(STX, block, &data)
}

/// The empty block 0 that terminates a batch.
pub fn end_of_batch_frame() -> Vec<u8> {
    frame(SOH, 0, &[0u8; HEADER_BLOCK_SIZE])
}

/// Drive two futures to completion on the current thread.
pub fn run2<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    futures_lite::future::block_on(futures_lite::future::zip(a, b))
}

pub fn run<F: Future>(future: F) -> F::Output {
    futures_lite::future::block_on(future)
}
