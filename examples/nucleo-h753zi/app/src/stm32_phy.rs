use core::{cell::RefCell, task::Context};

use embassy_stm32::eth::{self, GenericPhy, StationManagement};
use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};

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
