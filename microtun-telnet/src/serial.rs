//! Serial Telnet COM-PORT-OPTION helpers.
//!
//! This module deliberately separates wire representation from serial-driver policy. A caller can
//! decode requests/confirmations into [`Message`] values, apply them to its UART or serial API,
//! then encode the actual resulting value as an acknowledgement.

use heapless::Vec;

use crate::{IAC, OPT_COM_PORT, SB, SE};

pub const SIGNATURE: u8 = 0;
pub const SET_BAUDRATE: u8 = 1;
pub const SET_DATASIZE: u8 = 2;
pub const SET_PARITY: u8 = 3;
pub const SET_STOPSIZE: u8 = 4;
pub const SET_CONTROL: u8 = 5;
pub const NOTIFY_LINESTATE: u8 = 6;
pub const NOTIFY_MODEMSTATE: u8 = 7;
pub const FLOWCONTROL_SUSPEND: u8 = 8;
pub const FLOWCONTROL_RESUME: u8 = 9;
pub const SET_LINESTATE_MASK: u8 = 10;
pub const SET_MODEMSTATE_MASK: u8 = 11;
pub const PURGE_DATA: u8 = 12;

const SERVER_OFFSET: u8 = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Origin {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Signature,
    SetBaudRate,
    SetDataSize,
    SetParity,
    SetStopSize,
    SetControl,
    NotifyLineState,
    NotifyModemState,
    FlowControlSuspend,
    FlowControlResume,
    SetLineStateMask,
    SetModemStateMask,
    PurgeData,
}

impl Command {
    pub const fn client_code(self) -> u8 {
        match self {
            Self::Signature => SIGNATURE,
            Self::SetBaudRate => SET_BAUDRATE,
            Self::SetDataSize => SET_DATASIZE,
            Self::SetParity => SET_PARITY,
            Self::SetStopSize => SET_STOPSIZE,
            Self::SetControl => SET_CONTROL,
            Self::NotifyLineState => NOTIFY_LINESTATE,
            Self::NotifyModemState => NOTIFY_MODEMSTATE,
            Self::FlowControlSuspend => FLOWCONTROL_SUSPEND,
            Self::FlowControlResume => FLOWCONTROL_RESUME,
            Self::SetLineStateMask => SET_LINESTATE_MASK,
            Self::SetModemStateMask => SET_MODEMSTATE_MASK,
            Self::PurgeData => PURGE_DATA,
        }
    }

    pub const fn wire_code(self, origin: Origin) -> u8 {
        match (self, origin) {
            (Self::Signature, Origin::Client) => SIGNATURE,
            (Self::Signature, Origin::Server) => SIGNATURE + SERVER_OFFSET,
            (_, Origin::Client) => self.client_code(),
            (_, Origin::Server) => self.client_code() + SERVER_OFFSET,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    Empty,
    UnknownCommand(u8),
    InvalidLength,
}

/// A decoded serial COM-PORT-OPTION command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Message<'a> {
    Signature { origin: Origin, text: &'a [u8] },
    SetBaudRate { origin: Origin, value: u32 },
    SetDataSize { origin: Origin, value: u8 },
    SetParity { origin: Origin, value: u8 },
    SetStopSize { origin: Origin, value: u8 },
    SetControl { origin: Origin, value: u8 },
    NotifyLineState { origin: Origin, value: u8 },
    NotifyModemState { origin: Origin, value: u8 },
    FlowControlSuspend { origin: Origin },
    FlowControlResume { origin: Origin },
    SetLineStateMask { origin: Origin, value: u8 },
    SetModemStateMask { origin: Origin, value: u8 },
    PurgeData { origin: Origin, value: u8 },
}

impl Message<'_> {
    pub const fn origin(&self) -> Origin {
        match *self {
            Self::Signature { origin, .. }
            | Self::SetBaudRate { origin, .. }
            | Self::SetDataSize { origin, .. }
            | Self::SetParity { origin, .. }
            | Self::SetStopSize { origin, .. }
            | Self::SetControl { origin, .. }
            | Self::NotifyLineState { origin, .. }
            | Self::NotifyModemState { origin, .. }
            | Self::FlowControlSuspend { origin }
            | Self::FlowControlResume { origin }
            | Self::SetLineStateMask { origin, .. }
            | Self::SetModemStateMask { origin, .. }
            | Self::PurgeData { origin, .. } => origin,
        }
    }

    pub const fn command(&self) -> Command {
        match *self {
            Self::Signature { .. } => Command::Signature,
            Self::SetBaudRate { .. } => Command::SetBaudRate,
            Self::SetDataSize { .. } => Command::SetDataSize,
            Self::SetParity { .. } => Command::SetParity,
            Self::SetStopSize { .. } => Command::SetStopSize,
            Self::SetControl { .. } => Command::SetControl,
            Self::NotifyLineState { .. } => Command::NotifyLineState,
            Self::NotifyModemState { .. } => Command::NotifyModemState,
            Self::FlowControlSuspend { .. } => Command::FlowControlSuspend,
            Self::FlowControlResume { .. } => Command::FlowControlResume,
            Self::SetLineStateMask { .. } => Command::SetLineStateMask,
            Self::SetModemStateMask { .. } => Command::SetModemStateMask,
            Self::PurgeData { .. } => Command::PurgeData,
        }
    }
}

pub fn decode(payload: &[u8]) -> Result<Message<'_>, DecodeError> {
    let (&wire_code, value) = payload.split_first().ok_or(DecodeError::Empty)?;
    let (origin, code) = if wire_code == SIGNATURE {
        (Origin::Client, SIGNATURE)
    } else if (100..=112).contains(&wire_code) {
        (Origin::Server, wire_code - SERVER_OFFSET)
    } else {
        (Origin::Client, wire_code)
    };

    let command = command_from_code(code).ok_or(DecodeError::UnknownCommand(wire_code))?;
    match command {
        Command::Signature => Ok(Message::Signature {
            // RFC 2217 server replies use the 100 offset for SIGNATURE too. A code-0
            // signature is still accepted as a client/legacy form and decode_from() can
            // supply server context for peers that use the older ambiguous encoding.
            origin,
            text: value,
        }),
        Command::SetBaudRate => {
            if value.len() != 4 {
                return Err(DecodeError::InvalidLength);
            }
            Ok(Message::SetBaudRate {
                origin,
                value: u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
            })
        }
        Command::FlowControlSuspend => {
            require_empty(value)?;
            Ok(Message::FlowControlSuspend { origin })
        }
        Command::FlowControlResume => {
            require_empty(value)?;
            Ok(Message::FlowControlResume { origin })
        }
        _ => {
            if value.len() != 1 {
                return Err(DecodeError::InvalidLength);
            }
            let value = value[0];
            Ok(match command {
                Command::SetDataSize => Message::SetDataSize { origin, value },
                Command::SetParity => Message::SetParity { origin, value },
                Command::SetStopSize => Message::SetStopSize { origin, value },
                Command::SetControl => Message::SetControl { origin, value },
                Command::NotifyLineState => Message::NotifyLineState { origin, value },
                Command::NotifyModemState => Message::NotifyModemState { origin, value },
                Command::SetLineStateMask => Message::SetLineStateMask { origin, value },
                Command::SetModemStateMask => Message::SetModemStateMask { origin, value },
                Command::PurgeData => Message::PurgeData { origin, value },
                Command::Signature
                | Command::SetBaudRate
                | Command::FlowControlSuspend
                | Command::FlowControlResume => unreachable!(),
            })
        }
    }
}

/// Decode a COM-PORT-OPTION payload while supplying the contextual origin needed by SIGNATURE.
pub fn decode_from(origin: Origin, payload: &[u8]) -> Result<Message<'_>, DecodeError> {
    let message = decode(payload)?;
    Ok(match message {
        Message::Signature { text, .. } => Message::Signature { origin, text },
        other => other,
    })
}

/// Encode a typed serial message as a complete Telnet subnegotiation.
///
/// IAC bytes in signature text are escaped as required by Telnet. The function is atomic: when
/// `out` is too small it returns `false` without appending a partial command.
pub fn encode<const N: usize>(message: Message<'_>, out: &mut Vec<u8, N>) -> bool {
    let code = message.command().wire_code(message.origin());
    match message {
        Message::Signature { text, .. } => encode_value(out, code, text),
        Message::SetBaudRate { value, .. } => encode_value(out, code, &value.to_be_bytes()),
        Message::FlowControlSuspend { .. } | Message::FlowControlResume { .. } => {
            encode_value(out, code, &[])
        }
        Message::SetDataSize { value, .. }
        | Message::SetParity { value, .. }
        | Message::SetStopSize { value, .. }
        | Message::SetControl { value, .. }
        | Message::NotifyLineState { value, .. }
        | Message::NotifyModemState { value, .. }
        | Message::SetLineStateMask { value, .. }
        | Message::SetModemStateMask { value, .. }
        | Message::PurgeData { value, .. } => encode_value(out, code, &[value]),
    }
}

fn encode_value<const N: usize>(out: &mut Vec<u8, N>, code: u8, value: &[u8]) -> bool {
    let escaped = value.iter().filter(|&&byte| byte == IAC).count();
    // IAC SB OPT code ... IAC SE
    let required = 6usize.saturating_add(value.len()).saturating_add(escaped);
    if N.saturating_sub(out.len()) < required {
        return false;
    }

    let _ = out.extend_from_slice(&[IAC, SB, OPT_COM_PORT, code]);
    for &byte in value {
        let _ = out.push(byte);
        if byte == IAC {
            let _ = out.push(IAC);
        }
    }
    let _ = out.extend_from_slice(&[IAC, SE]);
    true
}

const fn command_from_code(code: u8) -> Option<Command> {
    Some(match code {
        SIGNATURE => Command::Signature,
        SET_BAUDRATE => Command::SetBaudRate,
        SET_DATASIZE => Command::SetDataSize,
        SET_PARITY => Command::SetParity,
        SET_STOPSIZE => Command::SetStopSize,
        SET_CONTROL => Command::SetControl,
        NOTIFY_LINESTATE => Command::NotifyLineState,
        NOTIFY_MODEMSTATE => Command::NotifyModemState,
        FLOWCONTROL_SUSPEND => Command::FlowControlSuspend,
        FLOWCONTROL_RESUME => Command::FlowControlResume,
        SET_LINESTATE_MASK => Command::SetLineStateMask,
        SET_MODEMSTATE_MASK => Command::SetModemStateMask,
        PURGE_DATA => Command::PurgeData,
        _ => return None,
    })
}

fn require_empty(value: &[u8]) -> Result<(), DecodeError> {
    if value.is_empty() {
        Ok(())
    } else {
        Err(DecodeError::InvalidLength)
    }
}

pub mod data_size {
    pub const REQUEST: u8 = 0;
    pub const FIVE: u8 = 5;
    pub const SIX: u8 = 6;
    pub const SEVEN: u8 = 7;
    pub const EIGHT: u8 = 8;
}

pub mod parity {
    pub const REQUEST: u8 = 0;
    pub const NONE: u8 = 1;
    pub const ODD: u8 = 2;
    pub const EVEN: u8 = 3;
    pub const MARK: u8 = 4;
    pub const SPACE: u8 = 5;
}

pub mod stop_size {
    pub const REQUEST: u8 = 0;
    pub const ONE: u8 = 1;
    pub const TWO: u8 = 2;
    pub const ONE_AND_A_HALF: u8 = 3;
}

pub mod control {
    pub const REQUEST_OUTBOUND_FLOW: u8 = 0;
    pub const NO_OUTBOUND_FLOW: u8 = 1;
    pub const XON_XOFF_OUTBOUND: u8 = 2;
    pub const HARDWARE_OUTBOUND: u8 = 3;
    pub const REQUEST_BREAK: u8 = 4;
    pub const BREAK_ON: u8 = 5;
    pub const BREAK_OFF: u8 = 6;
    pub const REQUEST_DTR: u8 = 7;
    pub const DTR_ON: u8 = 8;
    pub const DTR_OFF: u8 = 9;
    pub const REQUEST_RTS: u8 = 10;
    pub const RTS_ON: u8 = 11;
    pub const RTS_OFF: u8 = 12;
    pub const REQUEST_INBOUND_FLOW: u8 = 13;
    pub const NO_INBOUND_FLOW: u8 = 14;
    pub const XON_XOFF_INBOUND: u8 = 15;
    pub const HARDWARE_INBOUND: u8 = 16;
    pub const DCD_OUTBOUND: u8 = 17;
    pub const DTR_INBOUND: u8 = 18;
    pub const DSR_OUTBOUND: u8 = 19;
}

pub mod purge {
    pub const RECEIVE: u8 = 1;
    pub const TRANSMIT: u8 = 2;
    pub const BOTH: u8 = 3;
}

pub mod line_state {
    pub const DATA_READY: u8 = 1 << 0;
    pub const OVERRUN_ERROR: u8 = 1 << 1;
    pub const PARITY_ERROR: u8 = 1 << 2;
    pub const FRAMING_ERROR: u8 = 1 << 3;
    pub const BREAK_DETECT: u8 = 1 << 4;
    pub const TX_HOLDING_REGISTER_EMPTY: u8 = 1 << 5;
    pub const TX_SHIFT_REGISTER_EMPTY: u8 = 1 << 6;
    pub const TIMEOUT_ERROR: u8 = 1 << 7;
}

pub mod modem_state {
    pub const DELTA_CTS: u8 = 1 << 0;
    pub const DELTA_DSR: u8 = 1 << 1;
    pub const TRAILING_EDGE_RING: u8 = 1 << 2;
    pub const DELTA_CARRIER_DETECT: u8 = 1 << 3;
    pub const CTS: u8 = 1 << 4;
    pub const DSR: u8 = 1 << 5;
    pub const RING_INDICATOR: u8 = 1 << 6;
    pub const CARRIER_DETECT: u8 = 1 << 7;
}
