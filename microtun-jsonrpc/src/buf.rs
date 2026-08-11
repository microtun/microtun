//! Newline-delimited frame accumulation buffer.
//!
//! Backed by `heapless::Vec<u8, BUFFER_SIZE>` by default, or a growable
//! `alloc::vec::Vec<u8>` (with initial capacity `BUFFER_SIZE`) when the `alloc`
//! feature is enabled.

use crate::error::Error;

pub(crate) struct FrameBuf<const BUFFER_SIZE: usize> {
    #[cfg(feature = "alloc")]
    data: alloc::vec::Vec<u8>,
    #[cfg(not(feature = "alloc"))]
    data: heapless::Vec<u8, BUFFER_SIZE>,
    /// Index up to which we have already scanned for a newline.
    scan: usize,
    /// Number of leading bytes belonging to the previously yielded frame
    /// (including its `\n`); drained on the next [`Self::advance`].
    pending: usize,
}

impl<const BUFFER_SIZE: usize> FrameBuf<BUFFER_SIZE> {
    pub fn new() -> Self {
        FrameBuf {
            #[cfg(feature = "alloc")]
            data: alloc::vec::Vec::with_capacity(BUFFER_SIZE),
            #[cfg(not(feature = "alloc"))]
            data: heapless::Vec::new(),
            scan: 0,
            pending: 0,
        }
    }

    /// Drop the previously yielded frame, if any.
    pub fn advance(&mut self) {
        if self.pending == 0 {
            return;
        }
        let p = self.pending;
        #[cfg(feature = "alloc")]
        {
            self.data.drain(..p);
        }
        #[cfg(not(feature = "alloc"))]
        {
            let len = self.data.len();
            self.data.copy_within(p..len, 0);
            self.data.truncate(len - p);
        }
        self.scan = 0;
        self.pending = 0;
    }

    /// Look for a complete frame. Returns the index of the terminating `\n`;
    /// the frame is `&data[..end]`. Marks the frame as pending so the next
    /// [`Self::advance`] removes it.
    pub fn find_frame(&mut self) -> Option<usize> {
        match self.data[self.scan..].iter().position(|&b| b == b'\n') {
            Some(pos) => {
                let end = self.scan + pos;
                self.pending = end + 1;
                Some(end)
            }
            None => {
                self.scan = self.data.len();
                None
            }
        }
    }

    pub fn frame(&self, end: usize) -> &[u8] {
        &self.data[..end]
    }

    /// How many more bytes may be buffered before the backing store is full.
    ///
    /// With `alloc` the buffer grows, so nothing bounds a single read.
    pub fn remaining_capacity(&self) -> usize {
        #[cfg(feature = "alloc")]
        {
            usize::MAX
        }
        #[cfg(not(feature = "alloc"))]
        {
            BUFFER_SIZE.saturating_sub(self.data.len())
        }
    }

    pub fn push_chunk(&mut self, chunk: &[u8]) -> Result<(), Error> {
        #[cfg(feature = "alloc")]
        {
            self.data.extend_from_slice(chunk);
            Ok(())
        }
        #[cfg(not(feature = "alloc"))]
        {
            self.data
                .extend_from_slice(chunk)
                .map_err(|_| Error::Overflow)
        }
    }
}

/// Trim ASCII whitespace (incl. `\r` of CRLF framing) around a frame.
pub(crate) fn trim(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if first.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = s {
        if last.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    s
}
