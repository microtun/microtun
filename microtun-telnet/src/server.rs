//! Reusable TELNET RFC 2217 server-side protocol state.
//!
//! This module is the server-side counterpart to [`crate::client::ClientSession`]. It owns the
//! RFC 854/RFC 1143 option state required for an RFC 2217 access server, decodes client
//! COM-PORT-OPTION requests into typed operations, and tracks protocol-only serial state such as
//! notification masks and flow-control suspension. It deliberately owns no socket, UART, task,
//! timeout, or hardware policy.

use heapless::Vec;

use crate::{
    OPT_BINARY, OPT_COM_PORT, OPT_SUPPRESS_GO_AHEAD, Policy, Side, Telnet, TelnetEvent, serial,
};

/// Maximum bytes emitted by [`ServerSession::start`].
pub const SERIAL_SERVER_NEGOTIATION_MAX: usize = 15;

#[derive(Clone, Copy, Debug, Default)]
struct ServerPolicy;

impl Policy for ServerPolicy {
    fn support_us(&self, option: u8) -> bool {
        matches!(option, OPT_BINARY | OPT_SUPPRESS_GO_AHEAD)
    }

    fn support_him(&self, option: u8) -> bool {
        matches!(option, OPT_BINARY | OPT_SUPPRESS_GO_AHEAD | OPT_COM_PORT)
    }
}

/// Serial COM-PORT-OPTION negotiation status for the server endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SerialStatus {
    Negotiating,
    Active,
    Refused,
}

/// A query or requested setting from an RFC 2217 client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryOrSet<T> {
    Query,
    Set(T),
}

/// RFC 2217 data-size values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataBits {
    Five,
    Six,
    Seven,
    Eight,
}

impl DataBits {
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::Five => serial::data_size::FIVE,
            Self::Six => serial::data_size::SIX,
            Self::Seven => serial::data_size::SEVEN,
            Self::Eight => serial::data_size::EIGHT,
        }
    }
}

/// RFC 2217 parity values. MARK and SPACE remain representable even if the backing UART cannot
/// apply them; hardware policy can reject those settings and confirm the actual setting instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Parity {
    None,
    Odd,
    Even,
    Mark,
    Space,
}

impl Parity {
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::None => serial::parity::NONE,
            Self::Odd => serial::parity::ODD,
            Self::Even => serial::parity::EVEN,
            Self::Mark => serial::parity::MARK,
            Self::Space => serial::parity::SPACE,
        }
    }
}

/// RFC 2217 stop-size values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopBits {
    One,
    Two,
    OneAndAHalf,
}

impl StopBits {
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::One => serial::stop_size::ONE,
            Self::Two => serial::stop_size::TWO,
            Self::OneAndAHalf => serial::stop_size::ONE_AND_A_HALF,
        }
    }
}

/// RFC 2217 outbound flow-control values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundFlow {
    None,
    XonXoff,
    RtsCts,
    Dcd,
    Dsr,
}

impl OutboundFlow {
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::None => serial::control::NO_OUTBOUND_FLOW,
            Self::XonXoff => serial::control::XON_XOFF_OUTBOUND,
            Self::RtsCts => serial::control::HARDWARE_OUTBOUND,
            Self::Dcd => serial::control::DCD_OUTBOUND,
            Self::Dsr => serial::control::DSR_OUTBOUND,
        }
    }
}

/// RFC 2217 inbound flow-control values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboundFlow {
    None,
    XonXoff,
    RtsCts,
    Dtr,
}

impl InboundFlow {
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::None => serial::control::NO_INBOUND_FLOW,
            Self::XonXoff => serial::control::XON_XOFF_INBOUND,
            Self::RtsCts => serial::control::HARDWARE_INBOUND,
            Self::Dtr => serial::control::DTR_INBOUND,
        }
    }
}

/// RFC 2217 purge target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Purge {
    Receive,
    Transmit,
    Both,
}

impl Purge {
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::Receive => serial::purge::RECEIVE,
            Self::Transmit => serial::purge::TRANSMIT,
            Self::Both => serial::purge::BOTH,
        }
    }
}

/// A typed RFC 2217 request received from a client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SerialRequest<'a> {
    Signature(&'a [u8]),
    Baud(QueryOrSet<u32>),
    DataBits(QueryOrSet<DataBits>),
    Parity(QueryOrSet<Parity>),
    StopBits(QueryOrSet<StopBits>),
    OutboundFlow(QueryOrSet<OutboundFlow>),
    InboundFlow(QueryOrSet<InboundFlow>),
    Rts(QueryOrSet<bool>),
    Dtr(QueryOrSet<bool>),
    Break(QueryOrSet<bool>),
    LineStateMask(u8),
    ModemStateMask(u8),
    Purge(Purge),
    Suspend,
    Resume,
}

/// A semantically invalid serial request whose Telnet framing was otherwise valid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SerialRequestError {
    /// A server-origin confirmation/notification was received on the server endpoint.
    InvalidOrigin(serial::Origin),
    /// The command is not valid as a client-to-server request.
    InvalidCommand(serial::Command),
    /// The command was valid but its value is outside the RFC 2217 value set.
    InvalidValue { command: serial::Command, value: u8 },
}

impl<'a> SerialRequest<'a> {
    /// Convert a wire-level client message into a typed server request.
    pub fn from_message(message: serial::Message<'a>) -> Result<Self, SerialRequestError> {
        use serial::{Command, Message, Origin};

        if message.origin() != Origin::Client {
            return Err(SerialRequestError::InvalidOrigin(message.origin()));
        }

        match message {
            Message::Signature { text, .. } => Ok(Self::Signature(text)),
            Message::SetBaudRate { value, .. } => Ok(Self::Baud(if value == 0 {
                QueryOrSet::Query
            } else {
                QueryOrSet::Set(value)
            })),
            Message::SetDataSize { value, .. } => {
                let value = match value {
                    serial::data_size::REQUEST => return Ok(Self::DataBits(QueryOrSet::Query)),
                    serial::data_size::FIVE => DataBits::Five,
                    serial::data_size::SIX => DataBits::Six,
                    serial::data_size::SEVEN => DataBits::Seven,
                    serial::data_size::EIGHT => DataBits::Eight,
                    value => {
                        return Err(SerialRequestError::InvalidValue {
                            command: Command::SetDataSize,
                            value,
                        });
                    }
                };
                Ok(Self::DataBits(QueryOrSet::Set(value)))
            }
            Message::SetParity { value, .. } => {
                let value = match value {
                    serial::parity::REQUEST => return Ok(Self::Parity(QueryOrSet::Query)),
                    serial::parity::NONE => Parity::None,
                    serial::parity::ODD => Parity::Odd,
                    serial::parity::EVEN => Parity::Even,
                    serial::parity::MARK => Parity::Mark,
                    serial::parity::SPACE => Parity::Space,
                    value => {
                        return Err(SerialRequestError::InvalidValue {
                            command: Command::SetParity,
                            value,
                        });
                    }
                };
                Ok(Self::Parity(QueryOrSet::Set(value)))
            }
            Message::SetStopSize { value, .. } => {
                let value = match value {
                    serial::stop_size::REQUEST => return Ok(Self::StopBits(QueryOrSet::Query)),
                    serial::stop_size::ONE => StopBits::One,
                    serial::stop_size::TWO => StopBits::Two,
                    serial::stop_size::ONE_AND_A_HALF => StopBits::OneAndAHalf,
                    value => {
                        return Err(SerialRequestError::InvalidValue {
                            command: Command::SetStopSize,
                            value,
                        });
                    }
                };
                Ok(Self::StopBits(QueryOrSet::Set(value)))
            }
            Message::SetControl { value, .. } => match value {
                serial::control::REQUEST_OUTBOUND_FLOW => Ok(Self::OutboundFlow(QueryOrSet::Query)),
                serial::control::NO_OUTBOUND_FLOW => {
                    Ok(Self::OutboundFlow(QueryOrSet::Set(OutboundFlow::None)))
                }
                serial::control::XON_XOFF_OUTBOUND => {
                    Ok(Self::OutboundFlow(QueryOrSet::Set(OutboundFlow::XonXoff)))
                }
                serial::control::HARDWARE_OUTBOUND => {
                    Ok(Self::OutboundFlow(QueryOrSet::Set(OutboundFlow::RtsCts)))
                }
                serial::control::DCD_OUTBOUND => {
                    Ok(Self::OutboundFlow(QueryOrSet::Set(OutboundFlow::Dcd)))
                }
                serial::control::DSR_OUTBOUND => {
                    Ok(Self::OutboundFlow(QueryOrSet::Set(OutboundFlow::Dsr)))
                }
                serial::control::REQUEST_INBOUND_FLOW => Ok(Self::InboundFlow(QueryOrSet::Query)),
                serial::control::NO_INBOUND_FLOW => {
                    Ok(Self::InboundFlow(QueryOrSet::Set(InboundFlow::None)))
                }
                serial::control::XON_XOFF_INBOUND => {
                    Ok(Self::InboundFlow(QueryOrSet::Set(InboundFlow::XonXoff)))
                }
                serial::control::HARDWARE_INBOUND => {
                    Ok(Self::InboundFlow(QueryOrSet::Set(InboundFlow::RtsCts)))
                }
                serial::control::DTR_INBOUND => {
                    Ok(Self::InboundFlow(QueryOrSet::Set(InboundFlow::Dtr)))
                }
                serial::control::REQUEST_BREAK => Ok(Self::Break(QueryOrSet::Query)),
                serial::control::BREAK_ON => Ok(Self::Break(QueryOrSet::Set(true))),
                serial::control::BREAK_OFF => Ok(Self::Break(QueryOrSet::Set(false))),
                serial::control::REQUEST_DTR => Ok(Self::Dtr(QueryOrSet::Query)),
                serial::control::DTR_ON => Ok(Self::Dtr(QueryOrSet::Set(true))),
                serial::control::DTR_OFF => Ok(Self::Dtr(QueryOrSet::Set(false))),
                serial::control::REQUEST_RTS => Ok(Self::Rts(QueryOrSet::Query)),
                serial::control::RTS_ON => Ok(Self::Rts(QueryOrSet::Set(true))),
                serial::control::RTS_OFF => Ok(Self::Rts(QueryOrSet::Set(false))),
                value => Err(SerialRequestError::InvalidValue {
                    command: Command::SetControl,
                    value,
                }),
            },
            Message::FlowControlSuspend { .. } => Ok(Self::Suspend),
            Message::FlowControlResume { .. } => Ok(Self::Resume),
            Message::SetLineStateMask { value, .. } => Ok(Self::LineStateMask(value)),
            Message::SetModemStateMask { value, .. } => Ok(Self::ModemStateMask(value)),
            Message::PurgeData { value, .. } => {
                let value = match value {
                    serial::purge::RECEIVE => Purge::Receive,
                    serial::purge::TRANSMIT => Purge::Transmit,
                    serial::purge::BOTH => Purge::Both,
                    value => {
                        return Err(SerialRequestError::InvalidValue {
                            command: Command::PurgeData,
                            value,
                        });
                    }
                };
                Ok(Self::Purge(value))
            }
            Message::NotifyLineState { .. } | Message::NotifyModemState { .. } => {
                Err(SerialRequestError::InvalidCommand(message.command()))
            }
        }
    }
}

/// Generic RFC 2217 server state that does not depend on a UART implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerSerialState {
    status: SerialStatus,
    line_state_mask: u8,
    modem_state_mask: u8,
    tx_suspended: bool,
    previous_modem_state: Option<u8>,
}

impl Default for ServerSerialState {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerSerialState {
    pub const fn new() -> Self {
        Self {
            status: SerialStatus::Negotiating,
            // RFC 2217 defines an initial LINESTATE-MASK of 0 and MODEMSTATE-MASK of 255.
            line_state_mask: 0,
            modem_state_mask: u8::MAX,
            tx_suspended: false,
            previous_modem_state: None,
        }
    }

    pub const fn status(&self) -> SerialStatus {
        self.status
    }

    pub const fn line_state_mask(&self) -> u8 {
        self.line_state_mask
    }

    pub const fn modem_state_mask(&self) -> u8 {
        self.modem_state_mask
    }

    pub const fn tx_suspended(&self) -> bool {
        self.tx_suspended
    }

    pub fn set_line_state_mask(&mut self, mask: u8) {
        self.line_state_mask = mask;
    }

    pub fn set_modem_state_mask(&mut self, mask: u8) {
        self.modem_state_mask = mask;
    }

    /// Apply the parts of a client request that are pure RFC 2217 protocol state.
    pub fn apply_request(&mut self, request: &SerialRequest<'_>) {
        match *request {
            SerialRequest::LineStateMask(mask) => self.set_line_state_mask(mask),
            SerialRequest::ModemStateMask(mask) => self.set_modem_state_mask(mask),
            SerialRequest::Suspend => self.tx_suspended = true,
            SerialRequest::Resume => self.tx_suspended = false,
            _ => {}
        }
    }

    /// Build a masked line-state notification, if any requested bit is present.
    pub fn line_state(&self, raw_state: u8) -> Option<serial::Message<'static>> {
        let value = raw_state & self.line_state_mask;
        (value != 0).then_some(serial::Message::NotifyLineState {
            origin: serial::Origin::Server,
            value,
        })
    }

    /// Track modem input state, calculate RFC 2217 delta flags, apply the client's notification
    /// mask, and return a notification only when a masked state/delta is relevant.
    ///
    /// The first observation establishes the baseline. Subsequent observations report masked
    /// state changes, including trailing-edge RING.
    pub fn modem_state_changed(&mut self, raw_state: u8) -> Option<serial::Message<'static>> {
        const CURRENT_MASK: u8 = serial::modem_state::CTS
            | serial::modem_state::DSR
            | serial::modem_state::RING_INDICATOR
            | serial::modem_state::CARRIER_DETECT;

        let current = raw_state & CURRENT_MASK;
        let previous = self.previous_modem_state.replace(current);

        let mut delta = 0;
        let changed = previous.map_or(0, |previous| previous ^ current);
        if changed & serial::modem_state::CTS != 0 {
            delta |= serial::modem_state::DELTA_CTS;
        }
        if changed & serial::modem_state::DSR != 0 {
            delta |= serial::modem_state::DELTA_DSR;
        }
        if previous.is_some_and(|previous| {
            previous & serial::modem_state::RING_INDICATOR != 0
                && current & serial::modem_state::RING_INDICATOR == 0
        }) {
            delta |= serial::modem_state::TRAILING_EDGE_RING;
        }
        if changed & serial::modem_state::CARRIER_DETECT != 0 {
            delta |= serial::modem_state::DELTA_CARRIER_DETECT;
        }

        // The first sample is a baseline. After that, RFC 2217 says to AND the new MODEMSTATE
        // (current state plus delta bits) with MODEMSTATE-MASK and notify only when non-zero.
        previous?;
        let value = (current | delta) & self.modem_state_mask;
        (value != 0).then_some(serial::Message::NotifyModemState {
            origin: serial::Origin::Server,
            value,
        })
    }

    /// Forget the modem-state baseline, for example when the underlying UART is replaced.
    pub fn reset_modem_state(&mut self) {
        self.previous_modem_state = None;
    }
}

/// A high-level event produced by [`ServerSession::feed`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerEvent<'a> {
    Data(u8),
    /// BINARY is enabled both ways and the client COM-PORT-OPTION is active.
    SerialModeActive,
    /// Required RFC 2217 negotiation was refused or disabled by the peer.
    SerialModeRefused,
    Telnet(TelnetEvent),
    Serial(SerialRequest<'a>),
    MalformedSerial(serial::DecodeError),
    InvalidSerialRequest(SerialRequestError),
}

/// Failure to encode a server-side protocol action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ServerEncodeError {
    /// The caller-provided output buffer cannot hold the complete action.
    BufferFull,
    /// Serial COM-PORT-OPTION is not currently active.
    SerialInactive,
    /// A client-origin message was passed to a server-response encoder.
    InvalidOrigin,
}

/// Runtime-independent RFC 2217 access-server session.
pub struct ServerSession<const SB_CAP: usize = 256, const OPTION_CAP: usize = 12> {
    protocol: Telnet<ServerPolicy, SB_CAP, OPTION_CAP>,
    serial: ServerSerialState,
    started: bool,
}

impl<const SB_CAP: usize, const OPTION_CAP: usize> Default for ServerSession<SB_CAP, OPTION_CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SB_CAP: usize, const OPTION_CAP: usize> ServerSession<SB_CAP, OPTION_CAP> {
    pub const fn new() -> Self {
        Self {
            protocol: Telnet::new(ServerPolicy),
            serial: ServerSerialState::new(),
            started: false,
        }
    }

    pub const fn serial_state(&self) -> &ServerSerialState {
        &self.serial
    }

    pub fn serial_state_mut(&mut self) -> &mut ServerSerialState {
        &mut self.serial
    }

    pub fn serial_active(&self) -> bool {
        self.protocol.binary_mode_enabled() && self.protocol.him_enabled(OPT_COM_PORT)
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

    /// Start RFC 2217 server negotiation.
    ///
    /// Returns `Ok(false)` when negotiation has already been started. The operation is atomic with
    /// respect to `out`: if the complete negotiation does not fit, no bytes are appended and the
    /// session remains unstarted.
    pub fn start<const N: usize>(
        &mut self,
        out: &mut Vec<u8, N>,
    ) -> Result<bool, ServerEncodeError> {
        if self.started {
            return Ok(false);
        }
        if N.saturating_sub(out.len()) < SERIAL_SERVER_NEGOTIATION_MAX {
            return Err(ServerEncodeError::BufferFull);
        }

        self.protocol.request_binary_mode(out);
        self.protocol.request_us(OPT_SUPPRESS_GO_AHEAD, out);
        self.protocol.request_him(OPT_SUPPRESS_GO_AHEAD, out);
        // RFC 2217 clients perform COM-PORT-OPTION; the access server asks the client to enable it.
        self.protocol.request_him(OPT_COM_PORT, out);
        self.started = true;
        self.serial.status = SerialStatus::Negotiating;
        Ok(true)
    }

    /// Feed one wire byte into the TELNET/RFC 2217 state machine.
    ///
    /// Negotiation responses are appended to `reply`. Protocol-only requests (notification masks
    /// and suspend/resume) are applied to [`ServerSerialState`] before the event is returned.
    pub fn feed<'a, const N: usize>(
        &'a mut self,
        byte: u8,
        reply: &mut Vec<u8, N>,
    ) -> Option<ServerEvent<'a>> {
        let was_active = self.serial_active();
        let event = self.protocol.feed(byte, reply)?;
        let active = self.serial_active();

        if !was_active && active {
            self.serial.status = SerialStatus::Active;
            return Some(ServerEvent::SerialModeActive);
        }

        if was_active && !active || required_option_refused(event) {
            self.serial.status = SerialStatus::Refused;
            return Some(ServerEvent::SerialModeRefused);
        }

        match event {
            TelnetEvent::Data(byte) => Some(ServerEvent::Data(byte)),
            TelnetEvent::Subnegotiation(OPT_COM_PORT) => {
                let (_, payload) = self.protocol.subnegotiation();
                match serial::decode_from(serial::Origin::Client, payload) {
                    Ok(message) => match SerialRequest::from_message(message) {
                        Ok(request) => {
                            self.serial.apply_request(&request);
                            Some(ServerEvent::Serial(request))
                        }
                        Err(error) => Some(ServerEvent::InvalidSerialRequest(error)),
                    },
                    Err(error) => Some(ServerEvent::MalformedSerial(error)),
                }
            }
            _ => Some(ServerEvent::Telnet(event)),
        }
    }

    /// Queue one server-origin serial confirmation or notification.
    pub fn queue_serial<const N: usize>(
        &self,
        message: serial::Message<'_>,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        if !self.serial_active() {
            return Err(ServerEncodeError::SerialInactive);
        }
        if message.origin() != serial::Origin::Server {
            return Err(ServerEncodeError::InvalidOrigin);
        }
        if serial::encode(message, out) {
            Ok(())
        } else {
            Err(ServerEncodeError::BufferFull)
        }
    }

    pub fn confirm_signature<const N: usize>(
        &self,
        text: &[u8],
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        self.queue_serial(
            serial::Message::Signature {
                origin: serial::Origin::Server,
                text,
            },
            out,
        )
    }

    pub fn confirm_baud<const N: usize>(
        &self,
        value: u32,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        self.queue_serial(
            serial::Message::SetBaudRate {
                origin: serial::Origin::Server,
                value,
            },
            out,
        )
    }

    pub fn confirm_data_bits<const N: usize>(
        &self,
        value: DataBits,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        self.confirm_data_bits_raw(value.wire_value(), out)
    }

    pub fn confirm_data_bits_raw<const N: usize>(
        &self,
        value: u8,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        self.queue_serial(
            serial::Message::SetDataSize {
                origin: serial::Origin::Server,
                value,
            },
            out,
        )
    }

    pub fn confirm_parity<const N: usize>(
        &self,
        value: Parity,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        self.confirm_parity_raw(value.wire_value(), out)
    }

    pub fn confirm_parity_raw<const N: usize>(
        &self,
        value: u8,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        self.queue_serial(
            serial::Message::SetParity {
                origin: serial::Origin::Server,
                value,
            },
            out,
        )
    }

    pub fn confirm_stop_bits<const N: usize>(
        &self,
        value: StopBits,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        self.confirm_stop_bits_raw(value.wire_value(), out)
    }

    pub fn confirm_stop_bits_raw<const N: usize>(
        &self,
        value: u8,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        self.queue_serial(
            serial::Message::SetStopSize {
                origin: serial::Origin::Server,
                value,
            },
            out,
        )
    }

    pub fn confirm_outbound_flow<const N: usize>(
        &self,
        value: OutboundFlow,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        self.confirm_control(value.wire_value(), out)
    }

    pub fn confirm_inbound_flow<const N: usize>(
        &self,
        value: InboundFlow,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        self.confirm_control(value.wire_value(), out)
    }

    pub fn confirm_rts<const N: usize>(
        &self,
        on: bool,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        self.confirm_control(
            if on {
                serial::control::RTS_ON
            } else {
                serial::control::RTS_OFF
            },
            out,
        )
    }

    pub fn confirm_dtr<const N: usize>(
        &self,
        on: bool,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        self.confirm_control(
            if on {
                serial::control::DTR_ON
            } else {
                serial::control::DTR_OFF
            },
            out,
        )
    }

    pub fn confirm_break<const N: usize>(
        &self,
        on: bool,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        self.confirm_control(
            if on {
                serial::control::BREAK_ON
            } else {
                serial::control::BREAK_OFF
            },
            out,
        )
    }

    pub fn confirm_control<const N: usize>(
        &self,
        value: u8,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        self.queue_serial(
            serial::Message::SetControl {
                origin: serial::Origin::Server,
                value,
            },
            out,
        )
    }

    pub fn confirm_line_state_mask<const N: usize>(
        &self,
        value: u8,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        self.queue_serial(
            serial::Message::SetLineStateMask {
                origin: serial::Origin::Server,
                value,
            },
            out,
        )
    }

    pub fn confirm_modem_state_mask<const N: usize>(
        &self,
        value: u8,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        self.queue_serial(
            serial::Message::SetModemStateMask {
                origin: serial::Origin::Server,
                value,
            },
            out,
        )
    }

    pub fn confirm_purge<const N: usize>(
        &self,
        value: Purge,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        self.queue_serial(
            serial::Message::PurgeData {
                origin: serial::Origin::Server,
                value: value.wire_value(),
            },
            out,
        )
    }

    pub fn notify_line_state<const N: usize>(
        &self,
        value: u8,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        self.queue_serial(
            serial::Message::NotifyLineState {
                origin: serial::Origin::Server,
                value,
            },
            out,
        )
    }

    pub fn notify_modem_state<const N: usize>(
        &self,
        value: u8,
        out: &mut Vec<u8, N>,
    ) -> Result<(), ServerEncodeError> {
        self.queue_serial(
            serial::Message::NotifyModemState {
                origin: serial::Origin::Server,
                value,
            },
            out,
        )
    }
}

fn required_option_refused(event: TelnetEvent) -> bool {
    matches!(
        event,
        TelnetEvent::OptionRefused {
            side: Side::Him,
            option: OPT_COM_PORT | OPT_BINARY,
        } | TelnetEvent::OptionRefused {
            side: Side::Us,
            option: OPT_BINARY,
        } | TelnetEvent::OptionDisabled {
            side: Side::Him,
            option: OPT_COM_PORT | OPT_BINARY,
        } | TelnetEvent::OptionDisabled {
            side: Side::Us,
            option: OPT_BINARY,
        }
    )
}
