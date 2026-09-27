//! Reusable TELNET client-side protocol state.
//!
//! This module layers client policy and serial COM-PORT-OPTION state on top of the runtime-
//! agnostic [`crate::Telnet`] codec. It deliberately owns no socket and applies no timeouts: host
//! and embedded runtimes feed wire bytes in, write the returned reply bytes out, and decide when
//! to wait or give up.

use heapless::Vec;

use crate::{
    OPT_BINARY, OPT_COM_PORT, OPT_ECHO, OPT_SUPPRESS_GO_AHEAD, Policy, Side, Telnet, TelnetEvent,
    serial,
};

/// Maximum bytes emitted when entering or leaving serial mode.
pub const SERIAL_MODE_NEGOTIATION_MAX: usize = 18;

/// Maximum bytes emitted by [`ClientSession::queue_initial_serial_query`].
pub const SERIAL_INITIAL_QUERY_MAX: usize = 88;

#[derive(Clone, Copy, Debug)]
struct ClientPolicy {
    serial_mode: bool,
}

impl Policy for ClientPolicy {
    fn support_us(&self, option: u8) -> bool {
        matches!(option, OPT_BINARY | OPT_SUPPRESS_GO_AHEAD)
            || (self.serial_mode && option == OPT_COM_PORT)
    }

    fn support_him(&self, option: u8) -> bool {
        matches!(option, OPT_BINARY | OPT_SUPPRESS_GO_AHEAD)
            || (!self.serial_mode && option == OPT_ECHO)
    }
}

#[derive(Clone, Copy, Debug)]
struct TelnetModeSnapshot {
    us_binary: bool,
    him_binary: bool,
    us_sga: bool,
    him_sga: bool,
    him_echo: bool,
}

/// Serial COM-PORT-OPTION negotiation status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SerialStatus {
    Negotiating,
    Active,
    Refused,
}

/// Owned serial server event suitable for queuing outside the parser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SerialEvent<const SIGNATURE_CAP: usize = 256> {
    Signature(Vec<u8, SIGNATURE_CAP>),
    BaudRate(u32),
    DataSize(u8),
    Parity(u8),
    StopSize(u8),
    Control(u8),
    LineState(u8),
    ModemState(u8),
    FlowControlSuspend,
    FlowControlResume,
    LineStateMask(u8),
    ModemStateMask(u8),
    PurgeData(u8),
}

impl<const SIGNATURE_CAP: usize> SerialEvent<SIGNATURE_CAP> {
    fn from_server_message(message: serial::Message<'_>) -> Option<Self> {
        use serial::Message;

        if !matches!(message, Message::Signature { .. })
            && message.origin() != serial::Origin::Server
        {
            return None;
        }

        Some(match message {
            Message::Signature { text, .. } => {
                let mut signature = Vec::new();
                let count = text.len().min(SIGNATURE_CAP);
                let _ = signature.extend_from_slice(&text[..count]);
                Self::Signature(signature)
            }
            Message::SetBaudRate { value, .. } => Self::BaudRate(value),
            Message::SetDataSize { value, .. } => Self::DataSize(value),
            Message::SetParity { value, .. } => Self::Parity(value),
            Message::SetStopSize { value, .. } => Self::StopSize(value),
            Message::SetControl { value, .. } => Self::Control(value),
            Message::NotifyLineState { value, .. } => Self::LineState(value),
            Message::NotifyModemState { value, .. } => Self::ModemState(value),
            Message::FlowControlSuspend { .. } => Self::FlowControlSuspend,
            Message::FlowControlResume { .. } => Self::FlowControlResume,
            Message::SetLineStateMask { value, .. } => Self::LineStateMask(value),
            Message::SetModemStateMask { value, .. } => Self::ModemStateMask(value),
            Message::PurgeData { value, .. } => Self::PurgeData(value),
        })
    }
}

/// Current serial state learned from serial server messages.
///
/// `SIGNATURE_CAP` bounds the optional server signature so this type remains `no_std` and does not
/// allocate. Oversized signatures are truncated to the configured capacity; all serial settings
/// continue to be tracked normally.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SerialConsoleState<const SIGNATURE_CAP: usize = 256> {
    pub status: SerialStatus,
    pub signature: Option<Vec<u8, SIGNATURE_CAP>>,
    pub baud: Option<u32>,
    pub data_bits: Option<u8>,
    pub parity: Option<u8>,
    pub stop_bits: Option<u8>,
    pub flow_out: Option<u8>,
    pub flow_in: Option<u8>,
    pub dtr: Option<bool>,
    pub rts: Option<bool>,
    pub break_state: Option<bool>,
    pub line_state: u8,
    pub modem_state: u8,
    pub tx_suspended: bool,
}

impl<const SIGNATURE_CAP: usize> Default for SerialConsoleState<SIGNATURE_CAP> {
    fn default() -> Self {
        Self {
            status: SerialStatus::Negotiating,
            signature: None,
            baud: None,
            data_bits: None,
            parity: None,
            stop_bits: None,
            flow_out: None,
            flow_in: None,
            dtr: None,
            rts: None,
            break_state: None,
            line_state: 0,
            modem_state: 0,
            tx_suspended: false,
        }
    }
}

impl<const SIGNATURE_CAP: usize> SerialConsoleState<SIGNATURE_CAP> {
    /// Apply a decoded serial server event to the tracked serial state.
    pub fn update(&mut self, event: &SerialEvent<SIGNATURE_CAP>) {
        match event {
            SerialEvent::Signature(text) => self.signature = Some(text.clone()),
            SerialEvent::BaudRate(value) if *value != 0 => self.baud = Some(*value),
            SerialEvent::DataSize(value) if (5..=8).contains(value) => {
                self.data_bits = Some(*value);
            }
            SerialEvent::Parity(value)
                if matches!(
                    *value,
                    serial::parity::NONE
                        | serial::parity::ODD
                        | serial::parity::EVEN
                        | serial::parity::MARK
                        | serial::parity::SPACE
                ) =>
            {
                self.parity = Some(*value);
            }
            SerialEvent::StopSize(value)
                if matches!(
                    *value,
                    serial::stop_size::ONE
                        | serial::stop_size::TWO
                        | serial::stop_size::ONE_AND_A_HALF
                ) =>
            {
                self.stop_bits = Some(*value);
            }
            SerialEvent::Control(value) => match *value {
                serial::control::NO_OUTBOUND_FLOW
                | serial::control::XON_XOFF_OUTBOUND
                | serial::control::HARDWARE_OUTBOUND
                | serial::control::DCD_OUTBOUND
                | serial::control::DSR_OUTBOUND => self.flow_out = Some(*value),
                serial::control::NO_INBOUND_FLOW
                | serial::control::XON_XOFF_INBOUND
                | serial::control::HARDWARE_INBOUND
                | serial::control::DTR_INBOUND => self.flow_in = Some(*value),
                serial::control::BREAK_ON => self.break_state = Some(true),
                serial::control::BREAK_OFF => self.break_state = Some(false),
                serial::control::DTR_ON => self.dtr = Some(true),
                serial::control::DTR_OFF => self.dtr = Some(false),
                serial::control::RTS_ON => self.rts = Some(true),
                serial::control::RTS_OFF => self.rts = Some(false),
                _ => {}
            },
            SerialEvent::LineState(value) => self.line_state = *value,
            SerialEvent::ModemState(value) => self.modem_state = *value,
            SerialEvent::FlowControlSuspend => self.tx_suspended = true,
            SerialEvent::FlowControlResume => self.tx_suspended = false,
            SerialEvent::LineStateMask(_)
            | SerialEvent::ModemStateMask(_)
            | SerialEvent::PurgeData(_)
            | SerialEvent::BaudRate(_)
            | SerialEvent::DataSize(_)
            | SerialEvent::Parity(_)
            | SerialEvent::StopSize(_) => {}
        }
    }
}

/// A high-level event produced by [`ClientSession::feed`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientEvent<const SIGNATURE_CAP: usize = 256> {
    Data(u8),
    /// Serial COM-PORT-OPTION became active for this client.
    SerialModeActive,
    /// Serial COM-PORT-OPTION was refused or disabled by the peer.
    SerialModeRefused,
    Telnet(TelnetEvent),
    Serial(SerialEvent<SIGNATURE_CAP>),
    MalformedSerial(serial::DecodeError),
}

/// Failure to encode a client-side protocol action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientEncodeError {
    /// The caller-provided output buffer cannot hold the complete action.
    BufferFull,
    /// Serial COM-PORT-OPTION is not currently active.
    SerialInactive,
    /// A server-origin message was passed to a client-command encoder.
    InvalidOrigin,
}

/// TELNET client protocol state shared by interactive clients and serial bridges.
///
/// The session starts in ordinary terminal mode. [`ClientSession::enter_serial_mode`] switches its
/// option policy to serial, remembers the prior TELNET option state, and emits the negotiation
/// commands required for a binary serial stream. [`ClientSession::leave_serial_mode`] restores the
/// remembered terminal-mode options.
pub struct ClientSession<
    const SB_CAP: usize = 256,
    const OPTION_CAP: usize = 12,
    const SIGNATURE_CAP: usize = 256,
> {
    protocol: Telnet<ClientPolicy, SB_CAP, OPTION_CAP>,
    serial: Option<SerialConsoleState<SIGNATURE_CAP>>,
    serial_queried: bool,
    telnet_snapshot: Option<TelnetModeSnapshot>,
}

impl<const SB_CAP: usize, const OPTION_CAP: usize, const SIGNATURE_CAP: usize> Default
    for ClientSession<SB_CAP, OPTION_CAP, SIGNATURE_CAP>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const SB_CAP: usize, const OPTION_CAP: usize, const SIGNATURE_CAP: usize>
    ClientSession<SB_CAP, OPTION_CAP, SIGNATURE_CAP>
{
    pub const fn new() -> Self {
        Self {
            protocol: Telnet::new(ClientPolicy { serial_mode: false }),
            serial: None,
            serial_queried: false,
            telnet_snapshot: None,
        }
    }

    pub fn serial_state(&self) -> Option<&SerialConsoleState<SIGNATURE_CAP>> {
        self.serial.as_ref()
    }

    pub fn serial_active(&self) -> bool {
        self.serial
            .as_ref()
            .is_some_and(|serial| serial.status == SerialStatus::Active)
    }

    pub const fn serial_mode(&self) -> bool {
        self.serial.is_some()
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

    /// Enter binary serial-console mode.
    ///
    /// Returns `Ok(false)` when already in serial mode. On success, `out` contains only protocol
    /// bytes to write to the peer; the caller owns I/O and flush policy.
    pub fn enter_serial_mode<const N: usize>(
        &mut self,
        out: &mut Vec<u8, N>,
    ) -> Result<bool, ClientEncodeError> {
        if self.serial.is_some() {
            return Ok(false);
        }
        if N.saturating_sub(out.len()) < SERIAL_MODE_NEGOTIATION_MAX {
            return Err(ClientEncodeError::BufferFull);
        }

        self.telnet_snapshot = Some(TelnetModeSnapshot {
            us_binary: self.protocol.us_enabled(OPT_BINARY),
            him_binary: self.protocol.him_enabled(OPT_BINARY),
            us_sga: self.protocol.us_enabled(OPT_SUPPRESS_GO_AHEAD),
            him_sga: self.protocol.him_enabled(OPT_SUPPRESS_GO_AHEAD),
            him_echo: self.protocol.him_enabled(OPT_ECHO),
        });
        self.protocol.policy_mut().serial_mode = true;
        self.serial = Some(SerialConsoleState::default());
        self.serial_queried = false;

        self.protocol.request_binary_mode(out);
        self.protocol.request_us(OPT_SUPPRESS_GO_AHEAD, out);
        self.protocol.request_him(OPT_SUPPRESS_GO_AHEAD, out);
        self.protocol.disable_him(OPT_ECHO, out);
        self.protocol.request_us(OPT_COM_PORT, out);
        Ok(true)
    }

    /// Leave serial mode and restore the TELNET option state from before entry.
    pub fn leave_serial_mode<const N: usize>(
        &mut self,
        out: &mut Vec<u8, N>,
    ) -> Result<bool, ClientEncodeError> {
        if self.serial.is_none() {
            return Ok(false);
        }
        if N.saturating_sub(out.len()) < SERIAL_MODE_NEGOTIATION_MAX {
            return Err(ClientEncodeError::BufferFull);
        }

        self.protocol.policy_mut().serial_mode = false;
        self.protocol.disable_us(OPT_COM_PORT, out);
        if let Some(snapshot) = self.telnet_snapshot.take() {
            restore_us_option(&mut self.protocol, OPT_BINARY, snapshot.us_binary, out);
            restore_him_option(&mut self.protocol, OPT_BINARY, snapshot.him_binary, out);
            restore_us_option(
                &mut self.protocol,
                OPT_SUPPRESS_GO_AHEAD,
                snapshot.us_sga,
                out,
            );
            restore_him_option(
                &mut self.protocol,
                OPT_SUPPRESS_GO_AHEAD,
                snapshot.him_sga,
                out,
            );
            restore_him_option(&mut self.protocol, OPT_ECHO, snapshot.him_echo, out);
        }

        self.serial = None;
        self.serial_queried = false;
        Ok(true)
    }

    /// Feed one wire byte into the TELNET/serial state machine.
    ///
    /// Any negotiation response bytes are appended to `reply`. serial server messages update
    /// [`SerialConsoleState`] before the corresponding [`ClientEvent::Serial`] is returned.
    pub fn feed<const N: usize>(
        &mut self,
        byte: u8,
        reply: &mut Vec<u8, N>,
    ) -> Option<ClientEvent<SIGNATURE_CAP>> {
        let event = self.protocol.feed(byte, reply)?;
        match event {
            TelnetEvent::Data(byte) => Some(ClientEvent::Data(byte)),
            TelnetEvent::OptionEnabled {
                side: Side::Us,
                option: OPT_COM_PORT,
            } => {
                if let Some(serial) = self.serial.as_mut() {
                    serial.status = SerialStatus::Active;
                }
                Some(ClientEvent::SerialModeActive)
            }
            TelnetEvent::OptionDisabled {
                side: Side::Us,
                option: OPT_COM_PORT,
            }
            | TelnetEvent::OptionRefused {
                side: Side::Us,
                option: OPT_COM_PORT,
            } => {
                if let Some(serial) = self.serial.as_mut() {
                    serial.status = SerialStatus::Refused;
                }
                self.serial_queried = false;
                Some(ClientEvent::SerialModeRefused)
            }
            TelnetEvent::Subnegotiation(OPT_COM_PORT) => {
                let (_, payload) = self.protocol.subnegotiation();
                match serial::decode_from(serial::Origin::Server, payload) {
                    Ok(message) => {
                        let event = SerialEvent::from_server_message(message)?;
                        if let Some(serial) = self.serial.as_mut() {
                            serial.update(&event);
                        }
                        Some(ClientEvent::Serial(event))
                    }
                    Err(error) => Some(ClientEvent::MalformedSerial(error)),
                }
            }
            _ => Some(ClientEvent::Telnet(event)),
        }
    }

    /// Queue the standard serial client discovery query once per serial-mode activation.
    ///
    /// The query asks for signature, framing, flow-control and modem-control state and subscribes
    /// to line/modem notifications. Returns `Ok(false)` when the query has already been queued.
    pub fn queue_initial_serial_query<const N: usize>(
        &mut self,
        out: &mut Vec<u8, N>,
    ) -> Result<bool, ClientEncodeError> {
        if !self.serial_active() {
            return Err(ClientEncodeError::SerialInactive);
        }
        if self.serial_queried {
            return Ok(false);
        }
        if !append_initial_serial_query(out) {
            return Err(ClientEncodeError::BufferFull);
        }
        self.serial_queried = true;
        Ok(true)
    }

    /// Queue one typed serial client command.
    pub fn queue_serial<const N: usize>(
        &self,
        message: serial::Message<'_>,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ClientEncodeError> {
        if !self.serial_active() {
            return Err(ClientEncodeError::SerialInactive);
        }
        if message.origin() != serial::Origin::Client {
            return Err(ClientEncodeError::InvalidOrigin);
        }
        if serial::encode(message, out) {
            Ok(())
        } else {
            Err(ClientEncodeError::BufferFull)
        }
    }

    pub fn set_baud<const N: usize>(
        &self,
        value: u32,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ClientEncodeError> {
        self.queue_serial(
            serial::Message::SetBaudRate {
                origin: serial::Origin::Client,
                value,
            },
            out,
        )
    }

    pub fn set_data_bits<const N: usize>(
        &self,
        value: u8,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ClientEncodeError> {
        self.queue_serial(
            serial::Message::SetDataSize {
                origin: serial::Origin::Client,
                value,
            },
            out,
        )
    }

    pub fn set_parity<const N: usize>(
        &self,
        value: u8,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ClientEncodeError> {
        self.queue_serial(
            serial::Message::SetParity {
                origin: serial::Origin::Client,
                value,
            },
            out,
        )
    }

    pub fn set_stop_bits<const N: usize>(
        &self,
        value: u8,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ClientEncodeError> {
        self.queue_serial(
            serial::Message::SetStopSize {
                origin: serial::Origin::Client,
                value,
            },
            out,
        )
    }

    pub fn set_flow<const N: usize>(
        &self,
        outbound: u8,
        inbound: u8,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ClientEncodeError> {
        let start = out.len();
        let result = self
            .queue_serial(
                serial::Message::SetControl {
                    origin: serial::Origin::Client,
                    value: outbound,
                },
                out,
            )
            .and_then(|_| {
                self.queue_serial(
                    serial::Message::SetControl {
                        origin: serial::Origin::Client,
                        value: inbound,
                    },
                    out,
                )
            });
        if let Err(error) = result {
            out.truncate(start);
            return Err(error);
        }
        Ok(())
    }

    pub fn set_dtr<const N: usize>(
        &self,
        on: bool,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ClientEncodeError> {
        self.set_control(
            if on {
                serial::control::DTR_ON
            } else {
                serial::control::DTR_OFF
            },
            out,
        )
    }

    pub fn set_rts<const N: usize>(
        &self,
        on: bool,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ClientEncodeError> {
        self.set_control(
            if on {
                serial::control::RTS_ON
            } else {
                serial::control::RTS_OFF
            },
            out,
        )
    }

    pub fn set_break<const N: usize>(
        &self,
        on: bool,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ClientEncodeError> {
        self.set_control(
            if on {
                serial::control::BREAK_ON
            } else {
                serial::control::BREAK_OFF
            },
            out,
        )
    }

    fn set_control<const N: usize>(
        &self,
        value: u8,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ClientEncodeError> {
        self.queue_serial(
            serial::Message::SetControl {
                origin: serial::Origin::Client,
                value,
            },
            out,
        )
    }
}

fn append_initial_serial_query<const N: usize>(out: &mut Vec<u8, N>) -> bool {
    use serial::{Message, Origin};

    if N.saturating_sub(out.len()) < SERIAL_INITIAL_QUERY_MAX {
        return false;
    }

    let messages = [
        Message::Signature {
            origin: Origin::Client,
            text: &[],
        },
        Message::SetBaudRate {
            origin: Origin::Client,
            value: 0,
        },
        Message::SetDataSize {
            origin: Origin::Client,
            value: serial::data_size::REQUEST,
        },
        Message::SetParity {
            origin: Origin::Client,
            value: serial::parity::REQUEST,
        },
        Message::SetStopSize {
            origin: Origin::Client,
            value: serial::stop_size::REQUEST,
        },
        Message::SetControl {
            origin: Origin::Client,
            value: serial::control::REQUEST_OUTBOUND_FLOW,
        },
        Message::SetControl {
            origin: Origin::Client,
            value: serial::control::REQUEST_INBOUND_FLOW,
        },
        Message::SetControl {
            origin: Origin::Client,
            value: serial::control::REQUEST_BREAK,
        },
        Message::SetControl {
            origin: Origin::Client,
            value: serial::control::REQUEST_DTR,
        },
        Message::SetControl {
            origin: Origin::Client,
            value: serial::control::REQUEST_RTS,
        },
        Message::SetLineStateMask {
            origin: Origin::Client,
            value: u8::MAX,
        },
        Message::SetModemStateMask {
            origin: Origin::Client,
            value: u8::MAX,
        },
    ];

    let start = out.len();
    for message in messages {
        if !serial::encode(message, out) {
            out.truncate(start);
            return false;
        }
    }
    true
}

fn restore_us_option<P: Policy, const SB_CAP: usize, const OPTION_CAP: usize, const N: usize>(
    protocol: &mut Telnet<P, SB_CAP, OPTION_CAP>,
    option: u8,
    enabled: bool,
    out: &mut Vec<u8, N>,
) {
    if enabled {
        protocol.request_us(option, out);
    } else {
        protocol.disable_us(option, out);
    }
}

fn restore_him_option<P: Policy, const SB_CAP: usize, const OPTION_CAP: usize, const N: usize>(
    protocol: &mut Telnet<P, SB_CAP, OPTION_CAP>,
    option: u8,
    enabled: bool,
    out: &mut Vec<u8, N>,
) {
    if enabled {
        protocol.request_him(option, out);
    } else {
        protocol.disable_him(option, out);
    }
}

/// Compact label for a serial parity value.
pub const fn parity_label(value: u8) -> &'static str {
    match value {
        serial::parity::NONE => "N",
        serial::parity::ODD => "O",
        serial::parity::EVEN => "E",
        serial::parity::MARK => "M",
        serial::parity::SPACE => "S",
        _ => "?",
    }
}

/// Compact label for a serial stop-size value.
pub const fn stop_label(value: u8) -> &'static str {
    match value {
        serial::stop_size::ONE => "1",
        serial::stop_size::TWO => "2",
        serial::stop_size::ONE_AND_A_HALF => "1.5",
        _ => "?",
    }
}

/// Human-readable label for the common paired serial flow-control modes.
pub const fn flow_label(outbound: Option<u8>, inbound: Option<u8>) -> &'static str {
    match (outbound, inbound) {
        (None, _) | (_, None) => "?",
        (Some(serial::control::NO_OUTBOUND_FLOW), Some(serial::control::NO_INBOUND_FLOW)) => {
            "no-flow"
        }
        (Some(serial::control::XON_XOFF_OUTBOUND), Some(serial::control::XON_XOFF_INBOUND)) => {
            "XON/XOFF"
        }
        (Some(serial::control::HARDWARE_OUTBOUND), Some(serial::control::HARDWARE_INBOUND)) => {
            "RTS/CTS"
        }
        _ => "mixed-flow",
    }
}
