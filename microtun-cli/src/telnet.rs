use embedded_io_async::{Read, Write};
use heapless::{String, Vec};

pub const IAC: u8 = 255;
pub const DONT: u8 = 254;
pub const DO: u8 = 253;
pub const WONT: u8 = 252;
pub const WILL: u8 = 251;
pub const SB: u8 = 250;
pub const SE: u8 = 240;
pub const NOP: u8 = 241;
pub const BRK: u8 = 243;
pub const IP: u8 = 244;
pub const AYT: u8 = 246;
pub const EC: u8 = 247;
pub const EL: u8 = 248;

pub const OPT_BINARY: u8 = 0;
pub const OPT_ECHO: u8 = 1;
pub const OPT_SUPPRESS_GO_AHEAD: u8 = 3;
pub const OPT_TERMINAL_TYPE: u8 = 24;
pub const OPT_NAWS: u8 = 31;

/// Write TELNET application data, escaping IAC bytes on the wire.
pub async fn write_data<T: Write + ?Sized>(io: &mut T, bytes: &[u8]) -> Result<(), T::Error> {
    let mut start = 0;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte != IAC {
            continue;
        }
        if start < index {
            io.write_all(&bytes[start..index]).await?;
        }
        io.write_all(&[IAC, IAC]).await?;
        start = index + 1;
    }
    if start < bytes.len() {
        io.write_all(&bytes[start..]).await?;
    }
    io.flush().await
}

/// Format into bounded stack storage and write the result as TELNET application data.
///
/// The `FMT` const parameter is the scratch capacity in bytes. Overflow is reported rather than
/// silently truncating the message, which is the failure mode of formatting into a fixed
/// `heapless::String` by hand at each call site.
pub async fn write_fmt<const FMT: usize, T>(
    io: &mut T,
    args: core::fmt::Arguments<'_>,
) -> Result<(), crate::Error>
where
    T: Write + ?Sized,
    T::Error: embedded_io::Error,
{
    let mut scratch = String::<FMT>::new();
    core::fmt::Write::write_fmt(&mut scratch, args).map_err(|_| crate::Error::FormatOverflow)?;
    write_data(io, scratch.as_bytes())
        .await
        .map_err(crate::Error::io)
}

const TTYPE_IS: u8 = 0;
const TTYPE_SEND: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelnetEvent {
    Data(u8),
    Interrupt,
    Break,
    AreYouThere,
    EraseCharacter,
    EraseLine,
    WindowSizeChanged,
    TerminalTypeChanged,
}

/// Error while entering or using TELNET Binary Transmission mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BinaryModeError<E> {
    /// The underlying transport returned an I/O error.
    Io(E),
    /// The underlying byte stream ended.
    Disconnected,
    /// The peer explicitly rejected BINARY in at least one direction.
    Refused,
    /// Application data arrived before BINARY had been agreed in both directions.
    UnexpectedData,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RxState {
    Data,
    Iac,
    Verb(u8),
    SubnegOption,
    Subneg,
    SubnegIac,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QState {
    No,
    Yes,
    WantNo,
    WantNoOpposite,
    WantYes,
    WantYesOpposite,
}

#[derive(Clone, Copy, Debug)]
struct OptionSlot {
    option: u8,
    us: QState,
    him: QState,
}

impl OptionSlot {
    const fn new(option: u8) -> Self {
        Self {
            option,
            us: QState::No,
            him: QState::No,
        }
    }
}

/// Stateful RFC 854 codec with RFC 1143 Q-method option tracking.
///
/// Each direction uses the six effective Q-method states: NO, YES, WANTNO, WANTYES, and the
/// two corresponding states with an opposite request queued. This avoids negotiation loops while
/// still allowing a desired state to change during an outstanding negotiation.
pub struct Telnet<const SB_CAP: usize = 64, const TERM_CAP: usize = 32> {
    rx: RxState,
    subneg_option: u8,
    subneg: Vec<u8, SB_CAP>,
    options: Vec<OptionSlot, 8>,
    terminal_type: String<TERM_CAP>,
    window_size: Option<(u16, u16)>,
    /// A TERMINAL-TYPE `SEND` that did not fit in the caller's reply buffer and must be retried.
    ttype_send_pending: bool,
}

impl<const SB_CAP: usize, const TERM_CAP: usize> Default for Telnet<SB_CAP, TERM_CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SB_CAP: usize, const TERM_CAP: usize> Telnet<SB_CAP, TERM_CAP> {
    /// Largest reply a single [`Telnet::feed`] call can produce.
    ///
    /// A `WILL TERMINAL-TYPE` is answered with `DO TERMINAL-TYPE` (3 bytes) followed by an
    /// `IAC SB TERMINAL-TYPE SEND IAC SE` request (6 bytes). Callers should size their reply
    /// buffer at least this large; anything that does not fit is retried on the next byte rather
    /// than silently dropped.
    pub const MIN_REPLY: usize = 9;

    /// Bytes emitted by [`Telnet::initial_negotiation`].
    pub const INITIAL_NEGOTIATION: usize = 15;

    pub const fn new() -> Self {
        Self {
            rx: RxState::Data,
            subneg_option: 0,
            subneg: Vec::new(),
            options: Vec::new(),
            terminal_type: String::new(),
            window_size: None,
            ttype_send_pending: false,
        }
    }

    /// Whether `option` is currently enabled on our side of the link.
    pub fn us_enabled(&self, option: u8) -> bool {
        self.slot(option).is_some_and(|slot| slot.us == QState::Yes)
    }

    /// Whether `option` is currently enabled on the peer's side of the link.
    pub fn him_enabled(&self, option: u8) -> bool {
        self.slot(option)
            .is_some_and(|slot| slot.him == QState::Yes)
    }

    /// Whether a request about `option` on our side is still awaiting a reply.
    ///
    /// Callers that must act before negotiation settles (echo, for instance) can use this to
    /// distinguish "not agreed yet" from "declined".
    pub fn us_pending(&self, option: u8) -> bool {
        self.slot(option).is_some_and(|slot| {
            matches!(
                slot.us,
                QState::WantYes | QState::WantYesOpposite | QState::WantNo | QState::WantNoOpposite
            )
        })
    }

    /// Whether a request about `option` on the peer's side is still awaiting a reply.
    pub fn him_pending(&self, option: u8) -> bool {
        self.slot(option).is_some_and(|slot| {
            matches!(
                slot.him,
                QState::WantYes | QState::WantYesOpposite | QState::WantNo | QState::WantNoOpposite
            )
        })
    }

    /// Request TELNET Binary Transmission in both directions.
    ///
    /// The generated bytes are protocol commands and must be written to the underlying transport
    /// without IAC escaping. [`Telnet::binary_mode_enabled`] becomes true once the peer has
    /// accepted both directions.
    pub fn request_binary_mode<const N: usize>(&mut self, out: &mut Vec<u8, N>) {
        self.request_us(OPT_BINARY, out);
        self.request_him(OPT_BINARY, out);
    }

    /// Whether TELNET Binary Transmission is active in both directions.
    pub fn binary_mode_enabled(&self) -> bool {
        self.us_enabled(OPT_BINARY) && self.him_enabled(OPT_BINARY)
    }

    fn slot(&self, option: u8) -> Option<&OptionSlot> {
        self.options.iter().find(|slot| slot.option == option)
    }

    pub fn terminal_type(&self) -> Option<&str> {
        (!self.terminal_type.is_empty()).then_some(self.terminal_type.as_str())
    }

    pub const fn window_size(&self) -> Option<(u16, u16)> {
        self.window_size
    }

    fn slot_mut(&mut self, option: u8) -> &mut OptionSlot {
        if let Some(index) = self.options.iter().position(|slot| slot.option == option) {
            return &mut self.options[index];
        }
        // Capacity is larger than the set of options this crate negotiates. If it is ever
        // exhausted, reuse the final slot rather than panic; unsupported options are rejected.
        if self.options.push(OptionSlot::new(option)).is_err() {
            let index = self.options.len().saturating_sub(1);
            self.options[index] = OptionSlot::new(option);
            return &mut self.options[index];
        }
        let index = self.options.len() - 1;
        &mut self.options[index]
    }

    #[must_use]
    fn push_cmd<const N: usize>(out: &mut Vec<u8, N>, verb: u8, option: u8) -> bool {
        out.extend_from_slice(&[IAC, verb, option]).is_ok()
    }

    pub fn initial_negotiation<const N: usize>(&mut self, out: &mut Vec<u8, N>) {
        self.request_us(OPT_ECHO, out);
        self.request_us(OPT_SUPPRESS_GO_AHEAD, out);
        self.request_him(OPT_SUPPRESS_GO_AHEAD, out);
        self.request_him(OPT_NAWS, out);
        self.request_him(OPT_TERMINAL_TYPE, out);
    }

    fn request_state<const N: usize>(
        state: &mut QState,
        enable: bool,
        positive_verb: u8,
        negative_verb: u8,
        option: u8,
        out: &mut Vec<u8, N>,
    ) {
        *state = match (*state, enable) {
            (QState::No, true) => {
                if !Self::push_cmd(out, positive_verb, option) {
                    // The request never left the buffer; stay put so it can be retried.
                    return;
                }
                QState::WantYes
            }
            (QState::Yes, false) => {
                if !Self::push_cmd(out, negative_verb, option) {
                    return;
                }
                QState::WantNo
            }
            (QState::WantNo, true) => QState::WantNoOpposite,
            (QState::WantNoOpposite, false) => QState::WantNo,
            (QState::WantYes, false) => QState::WantYesOpposite,
            (QState::WantYesOpposite, true) => QState::WantYes,
            (state, _) => state,
        };
    }

    fn receive_positive<const N: usize>(
        state: &mut QState,
        supported: bool,
        positive_verb: u8,
        negative_verb: u8,
        option: u8,
        out: &mut Vec<u8, N>,
    ) {
        *state = match *state {
            QState::No => {
                let verb = if supported {
                    positive_verb
                } else {
                    negative_verb
                };
                if !Self::push_cmd(out, verb, option) {
                    return;
                }
                if supported { QState::Yes } else { QState::No }
            }
            QState::Yes => QState::Yes,
            QState::WantNo => QState::No,
            QState::WantNoOpposite => QState::Yes,
            QState::WantYes => QState::Yes,
            QState::WantYesOpposite => {
                if !Self::push_cmd(out, negative_verb, option) {
                    return;
                }
                QState::WantNo
            }
        };
    }

    fn receive_negative<const N: usize>(
        state: &mut QState,
        positive_verb: u8,
        negative_verb: u8,
        option: u8,
        out: &mut Vec<u8, N>,
    ) {
        *state = match *state {
            QState::No => QState::No,
            QState::Yes => {
                if !Self::push_cmd(out, negative_verb, option) {
                    return;
                }
                QState::No
            }
            QState::WantNo => QState::No,
            QState::WantNoOpposite => {
                if !Self::push_cmd(out, positive_verb, option) {
                    return;
                }
                QState::WantYes
            }
            QState::WantYes => QState::No,
            QState::WantYesOpposite => QState::No,
        };
    }

    fn request_us<const N: usize>(&mut self, option: u8, out: &mut Vec<u8, N>) {
        let slot = self.slot_mut(option);
        Self::request_state(&mut slot.us, true, WILL, WONT, option, out);
    }

    #[allow(dead_code)]
    fn disable_us<const N: usize>(&mut self, option: u8, out: &mut Vec<u8, N>) {
        let slot = self.slot_mut(option);
        Self::request_state(&mut slot.us, false, WILL, WONT, option, out);
    }

    fn request_him<const N: usize>(&mut self, option: u8, out: &mut Vec<u8, N>) {
        let slot = self.slot_mut(option);
        Self::request_state(&mut slot.him, true, DO, DONT, option, out);
    }

    #[allow(dead_code)]
    fn disable_him<const N: usize>(&mut self, option: u8, out: &mut Vec<u8, N>) {
        let slot = self.slot_mut(option);
        Self::request_state(&mut slot.him, false, DO, DONT, option, out);
    }

    fn support_us(option: u8) -> bool {
        matches!(option, OPT_BINARY | OPT_ECHO | OPT_SUPPRESS_GO_AHEAD)
    }

    fn support_him(option: u8) -> bool {
        matches!(
            option,
            OPT_BINARY | OPT_SUPPRESS_GO_AHEAD | OPT_NAWS | OPT_TERMINAL_TYPE
        )
    }

    fn negotiate<const N: usize>(&mut self, verb: u8, option: u8, out: &mut Vec<u8, N>) {
        match verb {
            DO => {
                let supported = Self::support_us(option);
                let slot = self.slot_mut(option);
                Self::receive_positive(&mut slot.us, supported, WILL, WONT, option, out);
            }
            DONT => {
                let slot = self.slot_mut(option);
                Self::receive_negative(&mut slot.us, WILL, WONT, option, out);
            }
            WILL => {
                let supported = Self::support_him(option);
                let became_enabled = {
                    let slot = self.slot_mut(option);
                    let was_enabled = slot.him == QState::Yes;
                    Self::receive_positive(&mut slot.him, supported, DO, DONT, option, out);
                    !was_enabled && slot.him == QState::Yes
                };
                if option == OPT_TERMINAL_TYPE && supported && became_enabled {
                    self.ttype_send_pending = true;
                    self.flush_pending(out);
                }
            }
            WONT => {
                let slot = self.slot_mut(option);
                Self::receive_negative(&mut slot.him, DO, DONT, option, out);
            }
            _ => {}
        }
    }

    /// Re-emit anything that previously did not fit in a caller's reply buffer.
    fn flush_pending<const N: usize>(&mut self, out: &mut Vec<u8, N>) {
        if !self.ttype_send_pending {
            return;
        }
        if out
            .extend_from_slice(&[IAC, SB, OPT_TERMINAL_TYPE, TTYPE_SEND, IAC, SE])
            .is_ok()
        {
            self.ttype_send_pending = false;
        }
    }

    fn finish_subneg(&mut self) -> Option<TelnetEvent> {
        match self.subneg_option {
            OPT_NAWS if self.subneg.len() >= 4 => {
                let columns = u16::from_be_bytes([self.subneg[0], self.subneg[1]]);
                let rows = u16::from_be_bytes([self.subneg[2], self.subneg[3]]);
                // RFC 1073: a zero dimension means "unknown", not a zero-sized terminal.
                self.window_size = (columns != 0 && rows != 0).then_some((columns, rows));
                Some(TelnetEvent::WindowSizeChanged)
            }
            OPT_TERMINAL_TYPE if self.subneg.first().copied() == Some(TTYPE_IS) => {
                self.terminal_type.clear();
                if let Ok(value) = core::str::from_utf8(&self.subneg[1..]) {
                    let _ = self.terminal_type.push_str(value);
                }
                Some(TelnetEvent::TerminalTypeChanged)
            }
            _ => None,
        }
    }

    pub fn feed<const N: usize>(
        &mut self,
        byte: u8,
        reply: &mut Vec<u8, N>,
    ) -> Option<TelnetEvent> {
        self.flush_pending(reply);
        match self.rx {
            RxState::Data => {
                if byte == IAC {
                    self.rx = RxState::Iac;
                    None
                } else {
                    Some(TelnetEvent::Data(byte))
                }
            }
            RxState::Iac => {
                self.rx = RxState::Data;
                match byte {
                    IAC => Some(TelnetEvent::Data(IAC)),
                    DO | DONT | WILL | WONT => {
                        self.rx = RxState::Verb(byte);
                        None
                    }
                    SB => {
                        self.rx = RxState::SubnegOption;
                        None
                    }
                    IP => Some(TelnetEvent::Interrupt),
                    BRK => Some(TelnetEvent::Break),
                    AYT => Some(TelnetEvent::AreYouThere),
                    EC => Some(TelnetEvent::EraseCharacter),
                    EL => Some(TelnetEvent::EraseLine),
                    NOP => None,
                    _ => None,
                }
            }
            RxState::Verb(verb) => {
                self.rx = RxState::Data;
                self.negotiate(verb, byte, reply);
                None
            }
            RxState::SubnegOption => {
                self.subneg_option = byte;
                self.subneg.clear();
                self.rx = RxState::Subneg;
                None
            }
            RxState::Subneg => {
                if byte == IAC {
                    self.rx = RxState::SubnegIac;
                } else {
                    let _ = self.subneg.push(byte);
                }
                None
            }
            RxState::SubnegIac => match byte {
                SE => {
                    self.rx = RxState::Data;
                    self.finish_subneg()
                }
                IAC => {
                    let _ = self.subneg.push(IAC);
                    self.rx = RxState::Subneg;
                    None
                }
                _ => {
                    self.rx = RxState::Data;
                    None
                }
            },
        }
    }
}

/// A TELNET byte-stream adapter for Binary Transmission in both directions.
///
/// Call [`BinaryMode::negotiate`] before exchanging application data. `BinaryMode` owns the
/// TELNET framing state for the duration of a binary protocol such as
/// YMODEM. Reads discard TELNET commands and unescape doubled IAC bytes; writes escape IAC while
/// otherwise preserving every payload byte. The caller owns timeout policy, so the type stays
/// runtime-agnostic and works with any `embedded-io-async` transport.
pub struct BinaryMode<'a, T: ?Sized> {
    io: &'a mut T,
    telnet: Telnet<64, 32>,
    wire: [u8; 64],
    wire_start: usize,
    wire_end: usize,
}

impl<'a, T> BinaryMode<'a, T>
where
    T: Read + Write + ?Sized,
{
    /// Create a binary-mode adapter without sending any TELNET commands yet.
    pub fn new(io: &'a mut T) -> Self {
        Self {
            io,
            telnet: Telnet::new(),
            wire: [0; 64],
            wire_start: 0,
            wire_end: 0,
        }
    }

    /// Request BINARY in both directions and wait until the peer has accepted it.
    ///
    /// No timeout is imposed here. Embedded runtimes have different timer APIs, so callers that
    /// need a deadline should wrap this future with their runtime's timeout primitive. Keeping the
    /// adapter outside that timeout future lets the caller run [`BinaryMode::abort`] if the
    /// deadline expires.
    pub async fn negotiate(&mut self) -> Result<(), BinaryModeError<T::Error>> {
        let mut request = Vec::<u8, 6>::new();
        self.telnet.request_binary_mode(&mut request);
        if !request.is_empty() {
            self.raw_write(request.as_slice()).await?;
        }

        while !self.telnet.binary_mode_enabled() {
            if self.binary_refused() {
                return Err(BinaryModeError::Refused);
            }

            // Read exactly one wire byte while negotiating. Callers commonly wrap this future in
            // a timeout; avoiding read-ahead means cancellation cannot discard bytes that belong
            // to the following shell or binary protocol.
            let mut byte = [0u8; 1];
            let read = self.io.read(&mut byte).await.map_err(BinaryModeError::Io)?;
            if read == 0 {
                return Err(BinaryModeError::Disconnected);
            }
            if self.feed_wire_byte(byte[0]).await?.is_some() {
                return Err(BinaryModeError::UnexpectedData);
            }
        }

        Ok(())
    }

    fn binary_refused(&self) -> bool {
        (!self.telnet.us_enabled(OPT_BINARY) && !self.telnet.us_pending(OPT_BINARY))
            || (!self.telnet.him_enabled(OPT_BINARY) && !self.telnet.him_pending(OPT_BINARY))
    }

    async fn raw_write(&mut self, bytes: &[u8]) -> Result<(), BinaryModeError<T::Error>> {
        self.io
            .write_all(bytes)
            .await
            .map_err(BinaryModeError::Io)?;
        self.io.flush().await.map_err(BinaryModeError::Io)
    }

    async fn wire_byte(&mut self) -> Result<u8, BinaryModeError<T::Error>> {
        if self.wire_start == self.wire_end {
            let read = self
                .io
                .read(&mut self.wire)
                .await
                .map_err(BinaryModeError::Io)?;
            if read == 0 {
                return Err(BinaryModeError::Disconnected);
            }
            self.wire_start = 0;
            self.wire_end = read;
        }

        let byte = self.wire[self.wire_start];
        self.wire_start += 1;
        Ok(byte)
    }

    async fn feed_wire_byte(&mut self, byte: u8) -> Result<Option<u8>, BinaryModeError<T::Error>> {
        let mut reply = Vec::<u8, 32>::new();
        let event = self.telnet.feed(byte, &mut reply);
        if !reply.is_empty() {
            self.raw_write(reply.as_slice()).await?;
        }

        Ok(match event {
            Some(TelnetEvent::Data(byte)) => Some(byte),
            _ => None,
        })
    }

    async fn step(&mut self) -> Result<Option<u8>, BinaryModeError<T::Error>> {
        let byte = self.wire_byte().await?;
        self.feed_wire_byte(byte).await
    }

    /// Read one application byte, removing TELNET command framing.
    pub async fn read_byte(&mut self) -> Result<u8, BinaryModeError<T::Error>> {
        loop {
            if let Some(byte) = self.step().await? {
                return Ok(byte);
            }
        }
    }

    /// Write application bytes, escaping IAC as required by TELNET even in BINARY mode.
    pub async fn write_all(&mut self, bytes: &[u8]) -> Result<(), BinaryModeError<T::Error>> {
        write_data(self.io, bytes)
            .await
            .map_err(BinaryModeError::Io)
    }

    /// Ask the peer to leave BINARY mode in both directions.
    ///
    /// This sends the disable requests but deliberately does not wait for acknowledgements. A
    /// following interactive [`crate::Session`] will consume those TELNET replies normally.
    pub async fn finish(mut self) -> Result<(), BinaryModeError<T::Error>> {
        let mut request = Vec::<u8, 6>::new();
        self.telnet.disable_us(OPT_BINARY, &mut request);
        self.telnet.disable_him(OPT_BINARY, &mut request);
        if request.is_empty() {
            Ok(())
        } else {
            self.raw_write(request.as_slice()).await
        }
    }

    /// Cancel a partial BINARY negotiation and explicitly request NVT mode in both directions.
    ///
    /// Unlike [`BinaryMode::finish`], this deliberately sends `WONT`/`DONT` even when the
    /// RFC-1143 state machine is still waiting for an earlier response. It is intended for timeout
    /// and error cleanup immediately before returning ownership of the transport to a text shell.
    pub async fn abort(mut self) -> Result<(), BinaryModeError<T::Error>> {
        self.raw_write(&[IAC, WONT, OPT_BINARY, IAC, DONT, OPT_BINARY])
            .await
    }
}
