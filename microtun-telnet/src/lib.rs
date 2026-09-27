#![no_std]
#![forbid(unsafe_code)]

use heapless::Vec;

pub mod binary;
pub mod client;
pub mod serial;
pub mod server;

pub use binary::{BinaryMode, BinaryModeError, write_data, write_data_unflushed};

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
pub const OPT_COM_PORT: u8 = 44;

/// Which half of a Telnet option negotiation changed state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    /// Our endpoint's WILL/WONT state.
    Us,
    /// The peer endpoint's WILL/WONT state.
    Him,
}

/// Endpoint-specific option policy.
///
/// Telnet option negotiation is directional: accepting `DO ECHO` means our endpoint promises to
/// echo, while accepting `WILL ECHO` means the peer may echo. Keeping those decisions in a policy
/// prevents a client from accidentally advertising server-only capabilities (and vice versa).
pub trait Policy {
    fn support_us(&self, option: u8) -> bool;
    fn support_him(&self, option: u8) -> bool;
}

/// Policy that rejects every option. Useful for framing-only consumers and tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct RejectAll;

impl Policy for RejectAll {
    fn support_us(&self, _option: u8) -> bool {
        false
    }

    fn support_him(&self, _option: u8) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelnetEvent {
    Data(u8),
    Interrupt,
    Break,
    AreYouThere,
    EraseCharacter,
    EraseLine,
    OptionEnabled {
        side: Side,
        option: u8,
    },
    OptionDisabled {
        side: Side,
        option: u8,
    },
    /// A locally requested option enable was explicitly rejected by the peer.
    ///
    /// Unlike [`TelnetEvent::OptionDisabled`], the option never reached the enabled state.
    OptionRefused {
        side: Side,
        option: u8,
    },
    /// A complete `IAC SB ... IAC SE` sequence was received.
    ///
    /// Call [`Telnet::subnegotiation`] before feeding another subnegotiation to inspect its body.
    Subnegotiation(u8),
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
/// `P` decides which options this endpoint is actually capable of performing. The protocol core
/// owns only framing and negotiation state; NAWS, TERMINAL-TYPE, serial and application policy
/// are handled by callers when the corresponding events arrive.
pub struct Telnet<P, const SB_CAP: usize = 64, const OPTION_CAP: usize = 12> {
    policy: P,
    rx: RxState,
    subneg_option: u8,
    subneg: Vec<u8, SB_CAP>,
    options: Vec<OptionSlot, OPTION_CAP>,
}

impl<P: Policy + Default, const SB_CAP: usize, const OPTION_CAP: usize> Default
    for Telnet<P, SB_CAP, OPTION_CAP>
{
    fn default() -> Self {
        Self::new(P::default())
    }
}

impl<P, const SB_CAP: usize, const OPTION_CAP: usize> Telnet<P, SB_CAP, OPTION_CAP>
where
    P: Policy,
{
    pub const fn new(policy: P) -> Self {
        Self {
            policy,
            rx: RxState::Data,
            subneg_option: 0,
            subneg: Vec::new(),
            options: Vec::new(),
        }
    }

    pub const fn policy(&self) -> &P {
        &self.policy
    }

    pub fn policy_mut(&mut self) -> &mut P {
        &mut self.policy
    }

    pub fn us_enabled(&self, option: u8) -> bool {
        self.slot(option).is_some_and(|slot| slot.us == QState::Yes)
    }

    pub fn him_enabled(&self, option: u8) -> bool {
        self.slot(option)
            .is_some_and(|slot| slot.him == QState::Yes)
    }

    pub fn us_pending(&self, option: u8) -> bool {
        self.slot(option).is_some_and(|slot| is_pending(slot.us))
    }

    pub fn him_pending(&self, option: u8) -> bool {
        self.slot(option).is_some_and(|slot| is_pending(slot.him))
    }

    /// Whether RFC 856 BINARY is enabled in both directions.
    pub fn binary_mode_enabled(&self) -> bool {
        self.us_enabled(OPT_BINARY) && self.him_enabled(OPT_BINARY)
    }

    /// Request RFC 856 BINARY in both directions.
    pub fn request_binary_mode<const N: usize>(&mut self, out: &mut Vec<u8, N>) {
        self.request_us(OPT_BINARY, out);
        self.request_him(OPT_BINARY, out);
    }

    /// Request a return to NVT mode in both directions.
    pub fn disable_binary_mode<const N: usize>(&mut self, out: &mut Vec<u8, N>) {
        self.disable_us(OPT_BINARY, out);
        self.disable_him(OPT_BINARY, out);
    }

    /// Whether a previously requested BINARY negotiation has been rejected in either direction.
    ///
    /// This is intended to be checked after [`Telnet::request_binary_mode`]. Before a request is
    /// made, both halves are naturally disabled and therefore also satisfy this predicate.
    pub fn binary_mode_refused(&self) -> bool {
        (!self.us_enabled(OPT_BINARY) && !self.us_pending(OPT_BINARY))
            || (!self.him_enabled(OPT_BINARY) && !self.him_pending(OPT_BINARY))
    }

    /// Body of the most recently completed subnegotiation, excluding the option byte.
    pub fn subnegotiation(&self) -> (u8, &[u8]) {
        (self.subneg_option, self.subneg.as_slice())
    }

    pub fn request_us<const N: usize>(&mut self, option: u8, out: &mut Vec<u8, N>) {
        let slot = self.slot_mut(option);
        Self::request_state(&mut slot.us, true, WILL, WONT, option, out);
    }

    pub fn disable_us<const N: usize>(&mut self, option: u8, out: &mut Vec<u8, N>) {
        let slot = self.slot_mut(option);
        Self::request_state(&mut slot.us, false, WILL, WONT, option, out);
    }

    pub fn request_him<const N: usize>(&mut self, option: u8, out: &mut Vec<u8, N>) {
        let slot = self.slot_mut(option);
        Self::request_state(&mut slot.him, true, DO, DONT, option, out);
    }

    pub fn disable_him<const N: usize>(&mut self, option: u8, out: &mut Vec<u8, N>) {
        let slot = self.slot_mut(option);
        Self::request_state(&mut slot.him, false, DO, DONT, option, out);
    }

    fn slot(&self, option: u8) -> Option<&OptionSlot> {
        self.options.iter().find(|slot| slot.option == option)
    }

    fn slot_mut(&mut self, option: u8) -> &mut OptionSlot {
        if let Some(index) = self.options.iter().position(|slot| slot.option == option) {
            return &mut self.options[index];
        }
        if self.options.push(OptionSlot::new(option)).is_err() {
            // OPTION_CAP is selected by the embedding application. If it is exhausted, recycle a
            // disabled slot before falling back to the last entry. Supported options should size
            // OPTION_CAP so this path is only relevant to repeated unknown-option probes.
            let index = self
                .options
                .iter()
                .position(|slot| slot.us == QState::No && slot.him == QState::No)
                .unwrap_or_else(|| self.options.len().saturating_sub(1));
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

    fn negotiate<const N: usize>(
        &mut self,
        verb: u8,
        option: u8,
        out: &mut Vec<u8, N>,
    ) -> Option<TelnetEvent> {
        match verb {
            DO => {
                let supported = self.policy.support_us(option);
                let slot = self.slot_mut(option);
                let was_enabled = slot.us == QState::Yes;
                Self::receive_positive(&mut slot.us, supported, WILL, WONT, option, out);
                transition_event(Side::Us, option, was_enabled, slot.us == QState::Yes)
            }
            DONT => {
                let slot = self.slot_mut(option);
                let was_enabled = slot.us == QState::Yes;
                let was_requested = slot.us == QState::WantYes;
                Self::receive_negative(&mut slot.us, WILL, WONT, option, out);
                transition_event(Side::Us, option, was_enabled, slot.us == QState::Yes).or_else(
                    || {
                        (was_requested && slot.us == QState::No).then_some(
                            TelnetEvent::OptionRefused {
                                side: Side::Us,
                                option,
                            },
                        )
                    },
                )
            }
            WILL => {
                let supported = self.policy.support_him(option);
                let slot = self.slot_mut(option);
                let was_enabled = slot.him == QState::Yes;
                Self::receive_positive(&mut slot.him, supported, DO, DONT, option, out);
                transition_event(Side::Him, option, was_enabled, slot.him == QState::Yes)
            }
            WONT => {
                let slot = self.slot_mut(option);
                let was_enabled = slot.him == QState::Yes;
                let was_requested = slot.him == QState::WantYes;
                Self::receive_negative(&mut slot.him, DO, DONT, option, out);
                transition_event(Side::Him, option, was_enabled, slot.him == QState::Yes).or_else(
                    || {
                        (was_requested && slot.him == QState::No).then_some(
                            TelnetEvent::OptionRefused {
                                side: Side::Him,
                                option,
                            },
                        )
                    },
                )
            }
            _ => None,
        }
    }

    pub fn feed<const N: usize>(
        &mut self,
        byte: u8,
        reply: &mut Vec<u8, N>,
    ) -> Option<TelnetEvent> {
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
                self.negotiate(verb, byte, reply)
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
                    Some(TelnetEvent::Subnegotiation(self.subneg_option))
                }
                IAC => {
                    let _ = self.subneg.push(IAC);
                    self.rx = RxState::Subneg;
                    None
                }
                _ => {
                    // RFC 854 only assigns IAC IAC and IAC SE inside subnegotiation. Treat any
                    // other IAC command as a malformed SB and resynchronize at normal data mode.
                    self.rx = RxState::Data;
                    None
                }
            },
        }
    }
}

fn is_pending(state: QState) -> bool {
    matches!(
        state,
        QState::WantYes | QState::WantYesOpposite | QState::WantNo | QState::WantNoOpposite
    )
}

fn transition_event(
    side: Side,
    option: u8,
    was_enabled: bool,
    enabled: bool,
) -> Option<TelnetEvent> {
    match (was_enabled, enabled) {
        (false, true) => Some(TelnetEvent::OptionEnabled { side, option }),
        (true, false) => Some(TelnetEvent::OptionDisabled { side, option }),
        _ => None,
    }
}

/// Append a Telnet subnegotiation atomically, doubling IAC bytes in the payload.
///
/// Returns `false` without modifying `out` when the complete frame does not fit.
pub fn push_subnegotiation<const N: usize>(
    out: &mut Vec<u8, N>,
    option: u8,
    payload: &[u8],
) -> bool {
    let escaped = payload.iter().filter(|&&byte| byte == IAC).count();
    let required = 5usize.saturating_add(payload.len()).saturating_add(escaped);
    if N.saturating_sub(out.len()) < required {
        return false;
    }

    let _ = out.extend_from_slice(&[IAC, SB, option]);
    for &byte in payload {
        let _ = out.push(byte);
        if byte == IAC {
            let _ = out.push(IAC);
        }
    }
    let _ = out.extend_from_slice(&[IAC, SE]);
    true
}
