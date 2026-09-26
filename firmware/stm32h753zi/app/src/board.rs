//! Board profile for the original NUCLEO-H753ZI hardware.
//!
//! The firmware target is the STM32H753ZI MCU. All assumptions that belong to
//! the currently supported physical board live here: user LED/button wiring,
//! the LAN8742 PHY, and the Nucleo RMII pinout.

use core::{cell::RefCell, task::Context};

use embassy_stm32::{
    eth::{self, Ethernet, GenericPhy, Sma, StationManagement},
    gpio::{Input, Output},
    peripherals::{ETH, ETH_SMA},
};
use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use microtun_firmware_common::board::{IdentifyLed, ResetButton, monitor_reset};

use crate::storage::Storage;

pub(crate) const DEVICE_MODEL: &str = "STM32H753ZI";

// B1 is a plain user button rather than a boot strap, so the default reset
// policy applies.
const USER_BUTTON: ResetButton = ResetButton::DEFAULT;

/// The Nucleo LD1 user LED reserved by the firmware for `identify`.
///
/// LD1 is active-high on PB0. LD2/PE1 and LD3/PB14 are deliberately left
/// unconfigured so other application code can claim them independently.
pub(crate) struct IdentifyLedPin {
    led: Output<'static>,
}

impl IdentifyLedPin {
    pub(crate) fn new(led: Output<'static>) -> Self {
        Self { led }
    }
}

impl IdentifyLed for IdentifyLedPin {
    fn is_on(&self) -> bool {
        self.led.is_set_high()
    }

    fn set_on(&mut self, on: bool) {
        if on {
            self.led.set_high();
        } else {
            self.led.set_low();
        }
    }
}

/// Monitor the Nucleo B1 USER button while the device is configured.
#[embassy_executor::task]
pub(crate) async fn user_button_reset_task(button: Input<'static>, storage: &'static Storage) -> ! {
    monitor_reset(button, USER_BUTTON, storage, crate::reset).await
}

pub(crate) type OuterPhy = Lan8742Phy<Sma<'static, ETH_SMA>>;
pub(crate) type OuterDevice = Ethernet<'static, ETH, OuterPhy>;

// Keep the concrete Nucleo RMII routing here. Embassy peripherals are move-only
// tokens, so the macro consumes exactly the board-owned tokens at the call site.
macro_rules! ethernet {
    ($p:ident, $mac:expr) => {{
        static ETH_PACKETS: static_cell::StaticCell<embassy_stm32::eth::PacketQueue<4, 4>> =
            static_cell::StaticCell::new();
        let sma = embassy_stm32::eth::Sma::new(
            $p.ETH_SMA, $p.PA2, // RMII MDIO
            $p.PC1, // RMII MDC
        );
        embassy_stm32::eth::Ethernet::new_with_phy(
            ETH_PACKETS.init(embassy_stm32::eth::PacketQueue::new()),
            $p.ETH,
            $crate::Irqs,
            $p.PA1,  // RMII REF_CLK (50 MHz from LAN8742A)
            $p.PA7,  // RMII CRS_DV
            $p.PC4,  // RMII RXD0
            $p.PC5,  // RMII RXD1
            $p.PG13, // RMII TXD0
            $p.PB13, // RMII TXD1
            $p.PG11, // RMII TX_EN
            $mac,
            $crate::board::Lan8742Phy::new(sma),
        )
    }};
}

pub(crate) use ethernet;

// Likewise keep the concrete board GPIO choices out of main.rs.
macro_rules! io {
    ($p:ident) => {{
        let identify_led = $crate::board::IdentifyLedPin::new(embassy_stm32::gpio::Output::new(
            $p.PB0,
            embassy_stm32::gpio::Level::Low,
            embassy_stm32::gpio::Speed::Low,
        ));
        let user_button = embassy_stm32::gpio::Input::new($p.PC13, embassy_stm32::gpio::Pull::Down);
        (identify_led, user_button)
    }};
}

pub(crate) use io;

const LAN8742_PHY_ADDR: u8 = 0;
const LAN8742_BCR: u8 = 0x00;
const LAN8742_PHYSCSR: u8 = 0x1f;
const LAN8742_BCR_DUPLEX_MODE: u16 = 0x0100;
const LAN8742_BCR_AUTONEGO_EN: u16 = 0x1000;
const LAN8742_BCR_SPEED_SELECT: u16 = 0x2000;
const LAN8742_PHYSCSR_AUTONEGO_DONE: u16 = 0x1000;
const LAN8742_PHYSCSR_HCDSPEED_MASK: u16 = 0x001c;
const LAN8742_PHYSCSR_10BT_HD: u16 = 0x0004;
const LAN8742_PHYSCSR_10BT_FD: u16 = 0x0014;
const LAN8742_PHYSCSR_100BTX_HD: u16 = 0x0008;
const LAN8742_PHYSCSR_100BTX_FD: u16 = 0x0018;

#[derive(Clone, Copy)]
enum PhySpeed {
    Mbps10,
    Mbps100,
}

#[derive(Clone, Copy)]
enum PhyDuplex {
    Half,
    Full,
}

impl PhySpeed {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Mbps10 => "10 Mbps",
            Self::Mbps100 => "100 Mbps",
        }
    }
}

impl PhyDuplex {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Half => "half",
            Self::Full => "full",
        }
    }
}

#[derive(Clone, Copy)]
enum PhyAutoneg {
    Disabled,
    Negotiating,
    Complete,
}

impl PhyAutoneg {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Negotiating => "negotiating",
            Self::Complete => "complete",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PhyLinkSnapshot {
    speed: Option<PhySpeed>,
    duplex: Option<PhyDuplex>,
    autoneg: PhyAutoneg,
}

impl PhyLinkSnapshot {
    const fn empty() -> Self {
        Self {
            speed: None,
            duplex: None,
            autoneg: PhyAutoneg::Negotiating,
        }
    }

    pub(crate) const fn speed_name(self) -> Option<&'static str> {
        match self.speed {
            Some(speed) => Some(speed.as_str()),
            None => None,
        }
    }

    pub(crate) const fn duplex_name(self) -> Option<&'static str> {
        match self.duplex {
            Some(duplex) => Some(duplex.as_str()),
            None => None,
        }
    }

    pub(crate) const fn autoneg_name(self) -> &'static str {
        self.autoneg.as_str()
    }
}

static PHY_LINK: Mutex<CriticalSectionRawMutex, RefCell<PhyLinkSnapshot>> =
    Mutex::new(RefCell::new(PhyLinkSnapshot::empty()));

pub(crate) fn phy_link_snapshot() -> PhyLinkSnapshot {
    PHY_LINK.lock(|status| *status.borrow())
}

fn publish_phy_link(snapshot: PhyLinkSnapshot) {
    PHY_LINK.lock(|status| *status.borrow_mut() = snapshot);
}

/// LAN8742 wrapper that leaves Embassy's generic PHY behavior intact while
/// publishing the negotiated link mode for the diagnostic shell.
pub(crate) struct Lan8742Phy<SM: StationManagement> {
    inner: GenericPhy<SM>,
}

impl<SM: StationManagement> Lan8742Phy<SM> {
    pub(crate) fn new(sm: SM) -> Self {
        Self {
            inner: GenericPhy::new(sm, LAN8742_PHY_ADDR),
        }
    }

    fn publish_status(&mut self, link_up: bool) {
        let (bcr, physcsr) = {
            let sm = self.inner.station_management();
            (
                sm.smi_read(LAN8742_PHY_ADDR, LAN8742_BCR),
                sm.smi_read(LAN8742_PHY_ADDR, LAN8742_PHYSCSR),
            )
        };

        let autoneg_enabled = bcr & LAN8742_BCR_AUTONEGO_EN != 0;
        let autoneg = if !autoneg_enabled {
            PhyAutoneg::Disabled
        } else if link_up && physcsr & LAN8742_PHYSCSR_AUTONEGO_DONE != 0 {
            PhyAutoneg::Complete
        } else {
            PhyAutoneg::Negotiating
        };

        let (speed, duplex) = if !link_up {
            (None, None)
        } else if autoneg_enabled {
            match physcsr & LAN8742_PHYSCSR_HCDSPEED_MASK {
                LAN8742_PHYSCSR_10BT_HD => (Some(PhySpeed::Mbps10), Some(PhyDuplex::Half)),
                LAN8742_PHYSCSR_10BT_FD => (Some(PhySpeed::Mbps10), Some(PhyDuplex::Full)),
                LAN8742_PHYSCSR_100BTX_HD => (Some(PhySpeed::Mbps100), Some(PhyDuplex::Half)),
                LAN8742_PHYSCSR_100BTX_FD => (Some(PhySpeed::Mbps100), Some(PhyDuplex::Full)),
                _ => (None, None),
            }
        } else {
            let speed = if bcr & LAN8742_BCR_SPEED_SELECT != 0 {
                PhySpeed::Mbps100
            } else {
                PhySpeed::Mbps10
            };
            let duplex = if bcr & LAN8742_BCR_DUPLEX_MODE != 0 {
                PhyDuplex::Full
            } else {
                PhyDuplex::Half
            };
            (Some(speed), Some(duplex))
        };

        publish_phy_link(PhyLinkSnapshot {
            speed,
            duplex,
            autoneg,
        });
    }
}

impl<SM: StationManagement> eth::Phy for Lan8742Phy<SM> {
    fn phy_reset(&mut self) {
        eth::Phy::phy_reset(&mut self.inner);
        self.publish_status(false);
    }

    fn phy_init(&mut self) {
        eth::Phy::phy_init(&mut self.inner);
        self.publish_status(false);
    }

    fn poll_link(&mut self, cx: &mut Context<'_>) -> bool {
        let link_up = eth::Phy::poll_link(&mut self.inner, cx);
        self.publish_status(link_up);
        link_up
    }
}
