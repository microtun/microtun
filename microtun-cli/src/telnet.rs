use embedded_io_async::Write;
use heapless::{String, Vec};
pub use microtun_telnet_proto::{
    AYT, BRK, BinaryMode, BinaryModeError, DO, DONT, EC, EL, IAC, IP, NOP, OPT_BINARY, OPT_ECHO,
    OPT_NAWS, OPT_SUPPRESS_GO_AHEAD, OPT_TERMINAL_TYPE, SB, SE, WILL, WONT, write_data,
    write_data_unflushed,
};
use microtun_telnet_proto::{Policy, Side, Telnet as Protocol, TelnetEvent as ProtocolEvent};

/// Format into bounded stack storage and write the result as TELNET application data.
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

#[derive(Clone, Copy, Debug, Default)]
struct ServerPolicy;

impl Policy for ServerPolicy {
    fn support_us(&self, option: u8) -> bool {
        matches!(option, OPT_BINARY | OPT_ECHO | OPT_SUPPRESS_GO_AHEAD)
    }

    fn support_him(&self, option: u8) -> bool {
        matches!(
            option,
            OPT_BINARY | OPT_SUPPRESS_GO_AHEAD | OPT_NAWS | OPT_TERMINAL_TYPE
        )
    }
}

/// Microtun shell Telnet endpoint.
///
/// RFC 854 framing and RFC 1143 negotiation live in `microtun-telnet-proto`; this wrapper only
/// supplies the shell's server-side option policy and interprets NAWS/TERMINAL-TYPE payloads.
pub struct Telnet<const SB_CAP: usize = 64, const TERM_CAP: usize = 32> {
    protocol: Protocol<ServerPolicy, SB_CAP, 12>,
    terminal_type: String<TERM_CAP>,
    window_size: Option<(u16, u16)>,
    ttype_send_pending: bool,
}

impl<const SB_CAP: usize, const TERM_CAP: usize> Default for Telnet<SB_CAP, TERM_CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SB_CAP: usize, const TERM_CAP: usize> Telnet<SB_CAP, TERM_CAP> {
    /// Largest reply a single [`Telnet::feed`] call can produce.
    pub const MIN_REPLY: usize = 9;

    /// Bytes emitted by [`Telnet::initial_negotiation`].
    pub const INITIAL_NEGOTIATION: usize = 15;

    pub const fn new() -> Self {
        Self {
            protocol: Protocol::new(ServerPolicy),
            terminal_type: String::new(),
            window_size: None,
            ttype_send_pending: false,
        }
    }

    pub fn us_enabled(&self, option: u8) -> bool {
        self.protocol.us_enabled(option)
    }

    pub fn him_enabled(&self, option: u8) -> bool {
        self.protocol.him_enabled(option)
    }

    pub fn us_pending(&self, option: u8) -> bool {
        self.protocol.us_pending(option)
    }

    pub fn him_pending(&self, option: u8) -> bool {
        self.protocol.him_pending(option)
    }

    pub fn terminal_type(&self) -> Option<&str> {
        (!self.terminal_type.is_empty()).then_some(self.terminal_type.as_str())
    }

    pub const fn window_size(&self) -> Option<(u16, u16)> {
        self.window_size
    }

    pub fn request_binary_mode<const N: usize>(&mut self, out: &mut Vec<u8, N>) {
        self.protocol.request_binary_mode(out);
    }

    pub fn binary_mode_enabled(&self) -> bool {
        self.protocol.binary_mode_enabled()
    }

    pub fn initial_negotiation<const N: usize>(&mut self, out: &mut Vec<u8, N>) {
        self.protocol.request_us(OPT_ECHO, out);
        self.protocol.request_us(OPT_SUPPRESS_GO_AHEAD, out);
        self.protocol.request_him(OPT_SUPPRESS_GO_AHEAD, out);
        self.protocol.request_him(OPT_NAWS, out);
        self.protocol.request_him(OPT_TERMINAL_TYPE, out);
    }

    fn flush_pending<const N: usize>(&mut self, out: &mut Vec<u8, N>) {
        if !self.ttype_send_pending {
            return;
        }
        if microtun_telnet_proto::push_subnegotiation(out, OPT_TERMINAL_TYPE, &[TTYPE_SEND]) {
            self.ttype_send_pending = false;
        }
    }

    fn finish_subnegotiation(&mut self, option: u8) -> Option<TelnetEvent> {
        let (_, body) = self.protocol.subnegotiation();
        match option {
            OPT_NAWS if body.len() >= 4 => {
                let columns = u16::from_be_bytes([body[0], body[1]]);
                let rows = u16::from_be_bytes([body[2], body[3]]);
                self.window_size = (columns != 0 && rows != 0).then_some((columns, rows));
                Some(TelnetEvent::WindowSizeChanged)
            }
            OPT_TERMINAL_TYPE if body.first().copied() == Some(TTYPE_IS) => {
                self.terminal_type.clear();
                if let Ok(value) = core::str::from_utf8(&body[1..]) {
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
        match self.protocol.feed(byte, reply) {
            Some(ProtocolEvent::Data(byte)) => Some(TelnetEvent::Data(byte)),
            Some(ProtocolEvent::Interrupt) => Some(TelnetEvent::Interrupt),
            Some(ProtocolEvent::Break) => Some(TelnetEvent::Break),
            Some(ProtocolEvent::AreYouThere) => Some(TelnetEvent::AreYouThere),
            Some(ProtocolEvent::EraseCharacter) => Some(TelnetEvent::EraseCharacter),
            Some(ProtocolEvent::EraseLine) => Some(TelnetEvent::EraseLine),
            Some(ProtocolEvent::OptionEnabled {
                side: Side::Him,
                option: OPT_TERMINAL_TYPE,
            }) => {
                self.ttype_send_pending = true;
                self.flush_pending(reply);
                None
            }
            Some(ProtocolEvent::Subnegotiation(option)) => self.finish_subnegotiation(option),
            Some(
                ProtocolEvent::OptionEnabled { .. }
                | ProtocolEvent::OptionDisabled { .. }
                | ProtocolEvent::OptionRefused { .. },
            )
            | None => None,
        }
    }
}
