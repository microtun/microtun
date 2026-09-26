//! Board profile for the ESP32-C3 RS232 Adapter V1.1 example.
//!
//! This example intentionally ignores the external RS232 transceiver and its
//! handshake pins. The board's LED is a power LED wired directly between 3.3 V
//! and ground, so there is no software-controlled identify LED. Only the BOOT
//! button on GPIO9 is used by the application.

use esp_hal::gpio::Input;
use microtun_firmware_common::board::{IdentifyLed, ResetButton, monitor_reset};

use crate::storage::Storage;

pub(crate) const DEVICE_MODEL: &str = "ESP32-C3";
pub(crate) const CONFIGURATION_ADDRESS: u32 = 0x003f_0000;

// GPIO9 is the BOOT strap on the attached board. Resetting while it is held low
// would enter the ROM downloader, so erase the configuration while held and
// reset only after the button is released.
const USER_BUTTON: ResetButton = ResetButton {
    active_low: true,
    reset_on_release: true,
    ..ResetButton::DEFAULT
};

/// The attached board has no MCU-controlled LED; its LED is a 3.3 V power LED.
/// Keep the shared `identify` command available as a harmless no-op.
pub(crate) struct IdentifyLedPin;

impl IdentifyLedPin {
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl IdentifyLed for IdentifyLedPin {
    fn is_on(&self) -> bool {
        false
    }

    fn set_on(&mut self, _on: bool) {}
}

/// Monitor the BOOT button while the device is configured.
#[embassy_executor::task]
pub(crate) async fn user_button_reset_task(button: Input<'static>, storage: &'static Storage) -> ! {
    monitor_reset(
        button,
        USER_BUTTON,
        storage,
        esp_hal::system::software_reset,
    )
    .await
}

// Keep the concrete board pin selection here. GPIO0/GPIO1/GPIO4/GPIO5 are
// deliberately not configured so the RS232 hardware remains outside this
// example.
macro_rules! io {
    ($peripherals:ident) => {{
        let identify_led = $crate::board::IdentifyLedPin::new();
        let user_button = esp_hal::gpio::Input::new(
            $peripherals.GPIO9,
            esp_hal::gpio::InputConfig::default().with_pull(esp_hal::gpio::Pull::Up),
        );
        (identify_led, user_button)
    }};
}

pub(crate) use io;
