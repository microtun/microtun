use clap::ValueEnum;
use heapless::Vec as HeaplessVec;
use microtun_telnet::{
    client::{ClientEncodeError, ClientSession},
    serial,
};

pub(crate) type SerialProtocol = ClientSession<256, 12, 256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum Parity {
    None,
    Odd,
    Even,
    Mark,
    Space,
}

impl Parity {
    pub(crate) const fn protocol_value(self) -> u8 {
        match self {
            Self::None => serial::parity::NONE,
            Self::Odd => serial::parity::ODD,
            Self::Even => serial::parity::EVEN,
            Self::Mark => serial::parity::MARK,
            Self::Space => serial::parity::SPACE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum StopBits {
    #[value(name = "1")]
    One,
    #[value(name = "1.5")]
    OneAndAHalf,
    #[value(name = "2")]
    Two,
}

impl StopBits {
    pub(crate) const fn protocol_value(self) -> u8 {
        match self {
            Self::One => serial::stop_size::ONE,
            Self::OneAndAHalf => serial::stop_size::ONE_AND_A_HALF,
            Self::Two => serial::stop_size::TWO,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum FlowControl {
    None,
    #[value(name = "xon-xoff")]
    XonXoff,
    #[value(name = "rts-cts")]
    RtsCts,
}

impl FlowControl {
    pub(crate) const fn protocol_value(self) -> (u8, u8) {
        match self {
            Self::None => SerialSettings::no_flow(),
            Self::XonXoff => SerialSettings::software_flow(),
            Self::RtsCts => SerialSettings::hardware_flow(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SerialSettings {
    pub(crate) baud: Option<u32>,
    pub(crate) data_bits: Option<u8>,
    pub(crate) parity: Option<u8>,
    pub(crate) stop_bits: Option<u8>,
    pub(crate) flow: Option<(u8, u8)>,
}

impl SerialSettings {
    pub(crate) fn queue(
        self,
        protocol: &SerialProtocol,
        out: &mut HeaplessVec<u8, 64>,
    ) -> Result<(), ClientEncodeError> {
        if let Some(value) = self.baud {
            protocol.set_baud(value, out)?;
        }
        if let Some(value) = self.data_bits {
            protocol.set_data_bits(value, out)?;
        }
        if let Some(value) = self.parity {
            protocol.set_parity(value, out)?;
        }
        if let Some(value) = self.stop_bits {
            protocol.set_stop_bits(value, out)?;
        }
        if let Some((outbound, inbound)) = self.flow {
            protocol.set_flow(outbound, inbound, out)?;
        }
        Ok(())
    }

    pub(crate) const fn no_flow() -> (u8, u8) {
        (
            serial::control::NO_OUTBOUND_FLOW,
            serial::control::NO_INBOUND_FLOW,
        )
    }

    pub(crate) const fn software_flow() -> (u8, u8) {
        (
            serial::control::XON_XOFF_OUTBOUND,
            serial::control::XON_XOFF_INBOUND,
        )
    }

    pub(crate) const fn hardware_flow() -> (u8, u8) {
        (
            serial::control::HARDWARE_OUTBOUND,
            serial::control::HARDWARE_INBOUND,
        )
    }
}
