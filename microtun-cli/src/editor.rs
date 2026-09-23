use heapless::Vec;
#[cfg(feature = "history")]
use heapless::{Deque, String};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EditorEvent {
    None,
    /// Fast-path for appending one byte at the end of the line.
    Echo(u8),
    /// Fast-path for erasing one single-column ASCII character at end-of-line.
    Backspace,
    Redraw,
    Submit,
    Complete,
    Interrupt,
    ClearScreen,
}

#[derive(Clone, Debug)]
enum EscapeState {
    Normal,
    Esc,
    /// `ESC [` (CSI) or `ESC O` (SS3). Terminals in application cursor-key mode send arrows as
    /// SS3, so both introducers have to be accepted.
    Csi(Vec<u8, 8>),
}

pub struct Editor<const LINE: usize, const HISTORY: usize> {
    line: Vec<u8, LINE>,
    cursor: usize,
    escape: EscapeState,
    #[cfg(feature = "history")]
    history: Deque<String<LINE>, HISTORY>,
    #[cfg(feature = "history")]
    history_index: Option<usize>,
    last_was_cr: bool,
}

impl<const LINE: usize, const HISTORY: usize> Default for Editor<LINE, HISTORY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const LINE: usize, const HISTORY: usize> Editor<LINE, HISTORY> {
    pub const fn new() -> Self {
        Self {
            line: Vec::new(),
            cursor: 0,
            escape: EscapeState::Normal,
            #[cfg(feature = "history")]
            history: Deque::new(),
            #[cfg(feature = "history")]
            history_index: None,
            last_was_cr: false,
        }
    }

    pub fn line(&self) -> &[u8] {
        self.line.as_slice()
    }

    pub fn line_mut(&mut self) -> &mut [u8] {
        self.line.as_mut_slice()
    }

    pub fn len(&self) -> usize {
        self.line.len()
    }

    pub fn is_empty(&self) -> bool {
        self.line.is_empty()
    }

    pub const fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn clear(&mut self) {
        self.line.clear();
        self.cursor = 0;
        #[cfg(feature = "history")]
        {
            self.history_index = None;
        }
    }

    fn prev_boundary(&self, mut index: usize) -> usize {
        if index == 0 {
            return 0;
        }
        index -= 1;
        while index > 0 && self.line[index] & 0b1100_0000 == 0b1000_0000 {
            index -= 1;
        }
        index
    }

    fn next_boundary(&self, mut index: usize) -> usize {
        if index >= self.line.len() {
            return self.line.len();
        }
        index += 1;
        while index < self.line.len() && self.line[index] & 0b1100_0000 == 0b1000_0000 {
            index += 1;
        }
        index
    }

    fn insert(&mut self, byte: u8) -> bool {
        if self.line.len() == LINE {
            return false;
        }
        if self.cursor == self.line.len() {
            if self.line.push(byte).is_ok() {
                self.cursor += 1;
                return true;
            }
            return false;
        }
        if self.line.push(0).is_err() {
            return false;
        }
        let len = self.line.len();
        self.line.copy_within(self.cursor..len - 1, self.cursor + 1);
        self.line[self.cursor] = byte;
        self.cursor += 1;
        true
    }

    fn backspace(&mut self) -> bool {
        if self.cursor == 0 {
            return false;
        }
        let start = self.prev_boundary(self.cursor);
        let count = self.cursor - start;
        let len = self.line.len();
        self.line.copy_within(self.cursor..len, start);
        for _ in 0..count {
            let _ = self.line.pop();
        }
        self.cursor = start;
        true
    }

    fn delete(&mut self) -> bool {
        if self.cursor >= self.line.len() {
            return false;
        }
        let end = self.next_boundary(self.cursor);
        let count = end - self.cursor;
        let len = self.line.len();
        self.line.copy_within(end..len, self.cursor);
        for _ in 0..count {
            let _ = self.line.pop();
        }
        true
    }

    #[cfg(feature = "history")]
    fn load_history(&mut self, index: usize) {
        if let Some(entry) = self.history.get(index) {
            self.line.clear();
            let _ = self.line.extend_from_slice(entry.as_bytes());
            self.cursor = self.line.len();
        }
    }

    #[cfg(feature = "history")]
    fn history_up(&mut self) -> bool {
        if self.history.is_empty() {
            return false;
        }
        let index = match self.history_index {
            None => self.history.len() - 1,
            Some(0) => 0,
            Some(index) => index - 1,
        };
        self.history_index = Some(index);
        self.load_history(index);
        true
    }

    #[cfg(feature = "history")]
    fn history_down(&mut self) -> bool {
        let Some(index) = self.history_index else {
            return false;
        };
        if index + 1 >= self.history.len() {
            self.history_index = None;
            self.line.clear();
            self.cursor = 0;
        } else {
            self.history_index = Some(index + 1);
            self.load_history(index + 1);
        }
        true
    }

    #[cfg(not(feature = "history"))]
    fn history_up(&mut self) -> bool {
        false
    }

    #[cfg(not(feature = "history"))]
    fn history_down(&mut self) -> bool {
        false
    }

    pub fn remember(&mut self) {
        #[cfg(feature = "history")]
        {
            let Ok(text) = core::str::from_utf8(self.line.as_slice()) else {
                return;
            };
            if text.trim().is_empty() {
                return;
            }
            if self
                .history
                .back()
                .is_some_and(|last| last.as_str() == text)
            {
                return;
            }
            let mut item = String::<LINE>::new();
            if item.push_str(text).is_err() {
                return;
            }
            if self.history.is_full() {
                let _ = self.history.pop_front();
            }
            let _ = self.history.push_back(item);
        }
    }

    /// Replace the text between `start` and the cursor with `prefix` + `value`.
    ///
    /// `start` is an absolute byte offset supplied by the completer, which tokenizes the line
    /// itself. Scanning back from the cursor over whitespace cannot find the start of a quoted
    /// token, so the offset has to come from the same code that did the quoting-aware split.
    ///
    /// When `quote` is set the value is wrapped in double quotes so that it lexes back as one
    /// token. Returns `false` if the line ran out of capacity, leaving the text truncated at that
    /// point rather than silently corrupted.
    pub fn replace_range(
        &mut self,
        start: usize,
        prefix: &str,
        value: &str,
        quote: bool,
        trailing_space: bool,
    ) -> bool {
        let start = start.min(self.cursor);
        let remove = self.cursor - start;
        self.line.copy_within(self.cursor.., start);
        for _ in 0..remove {
            let _ = self.line.pop();
        }
        self.cursor = start;

        let quote_byte = quote.then_some(b'"');
        for byte in prefix
            .bytes()
            .chain(quote_byte)
            .chain(value.bytes())
            .chain(quote_byte)
            .chain(trailing_space.then_some(b' '))
        {
            if !self.insert(byte) {
                return false;
            }
        }
        true
    }

    fn finish_csi(&mut self, sequence: &[u8]) -> EditorEvent {
        match sequence {
            b"A" => {
                if self.history_up() {
                    EditorEvent::Redraw
                } else {
                    EditorEvent::None
                }
            }
            b"B" => {
                if self.history_down() {
                    EditorEvent::Redraw
                } else {
                    EditorEvent::None
                }
            }
            b"C" => {
                self.cursor = self.next_boundary(self.cursor);
                EditorEvent::Redraw
            }
            b"D" => {
                self.cursor = self.prev_boundary(self.cursor);
                EditorEvent::Redraw
            }
            b"H" | b"1~" => {
                self.cursor = 0;
                EditorEvent::Redraw
            }
            b"F" | b"4~" => {
                self.cursor = self.line.len();
                EditorEvent::Redraw
            }
            b"3~" => {
                if self.delete() {
                    EditorEvent::Redraw
                } else {
                    EditorEvent::None
                }
            }
            _ => EditorEvent::None,
        }
    }

    pub fn feed(&mut self, byte: u8) -> EditorEvent {
        let state = core::mem::replace(&mut self.escape, EscapeState::Normal);
        match state {
            EscapeState::Esc => {
                if matches!(byte, b'[' | b'O') {
                    self.escape = EscapeState::Csi(Vec::new());
                    return EditorEvent::None;
                }
                // Not a sequence we recognize. Fall through and treat the byte as ordinary
                // input rather than swallowing it.
            }
            EscapeState::Csi(mut sequence) => {
                let _ = sequence.push(byte);
                if byte.is_ascii_alphabetic() || byte == b'~' {
                    return self.finish_csi(sequence.as_slice());
                }
                self.escape = EscapeState::Csi(sequence);
                return EditorEvent::None;
            }
            EscapeState::Normal => {}
        }

        if self.last_was_cr && matches!(byte, b'\n' | 0) {
            self.last_was_cr = false;
            return EditorEvent::None;
        }
        self.last_was_cr = false;

        match byte {
            b'\r' => {
                self.last_was_cr = true;
                EditorEvent::Submit
            }
            b'\n' => EditorEvent::Submit,
            b'\t' => EditorEvent::Complete,
            0x1b => {
                self.escape = EscapeState::Esc;
                EditorEvent::None
            }
            0x03 => EditorEvent::Interrupt,
            0x0c => EditorEvent::ClearScreen,
            0x01 => {
                self.cursor = 0;
                EditorEvent::Redraw
            }
            0x05 => {
                self.cursor = self.line.len();
                EditorEvent::Redraw
            }
            0x15 => {
                if self.cursor == 0 {
                    EditorEvent::None
                } else {
                    let count = self.cursor;
                    self.line.copy_within(self.cursor.., 0);
                    for _ in 0..count {
                        let _ = self.line.pop();
                    }
                    self.cursor = 0;
                    EditorEvent::Redraw
                }
            }
            0x0b => {
                self.line.truncate(self.cursor);
                EditorEvent::Redraw
            }
            0x17 => {
                let mut changed = false;
                while self.cursor > 0 && self.line[self.cursor - 1].is_ascii_whitespace() {
                    changed |= self.backspace();
                }
                while self.cursor > 0 && !self.line[self.cursor - 1].is_ascii_whitespace() {
                    changed |= self.backspace();
                }
                if changed {
                    EditorEvent::Redraw
                } else {
                    EditorEvent::None
                }
            }
            0x08 | 0x7f => {
                let fast = self.cursor == self.line.len()
                    && self.cursor > 0
                    && self.line[self.cursor - 1].is_ascii();
                match self.backspace() {
                    true if fast => EditorEvent::Backspace,
                    true => EditorEvent::Redraw,
                    false => EditorEvent::None,
                }
            }
            byte if byte >= 0x20 => {
                let append = self.cursor == self.line.len();
                match self.insert(byte) {
                    true if append => EditorEvent::Echo(byte),
                    true => EditorEvent::Redraw,
                    false => EditorEvent::None,
                }
            }
            _ => EditorEvent::None,
        }
    }
}
