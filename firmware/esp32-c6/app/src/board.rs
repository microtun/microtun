//! Board profile for the original ESP32-C6 PLC-V hardware.
//!
//! The firmware target is the ESP32-C6 SoC. All assumptions that belong to
//! the currently supported physical board live here so another ESP32-C6 board
//! can replace this module without changing the application logic.

use esp_hal::gpio::{Input, Output};
use microtun_firmware_common::board::{IdentifyLed, ResetButton, monitor_reset};

use crate::storage::Storage;

pub(crate) const DEVICE_MODEL: &str = "ESP32-C6";
pub(crate) const CONFIGURATION_ADDRESS: u32 = 0x003f_0000;

// GPIO9 is the BOOT strap. Resetting while it is held low would enter the ROM
// downloader, so erase the configuration while held and reset only on release.
const USER_BUTTON: ResetButton = ResetButton {
    active_low: true,
    reset_on_release: true,
    ..ResetButton::DEFAULT
};

/// The PLC-V RUN LED reserved by the firmware for `identify`.
///
/// Relay outputs and field inputs are deliberately left unconfigured. The RUN
/// LED is wired from 3.3 V into GPIO8, so driving the pin low sinks current and
/// turns the LED on.
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
        !self.led.is_set_high()
    }

    fn set_on(&mut self, on: bool) {
        if on {
            self.led.set_low();
        } else {
            self.led.set_high();
        }
    }
}

/// Monitor the PLC-V BOOT/user button while the device is configured.
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

// Keep the concrete board pin selection here. The ESP HAL exposes each GPIO as
// a move-only peripheral token, so a small macro lets us consume those tokens
// without making the rest of the application board-aware.
macro_rules! io {
    ($peripherals:ident) => {{
        let identify_led = $crate::board::IdentifyLedPin::new(esp_hal::gpio::Output::new(
            $peripherals.GPIO8,
            esp_hal::gpio::Level::High,
            esp_hal::gpio::OutputConfig::default(),
        ));
        let user_button = esp_hal::gpio::Input::new(
            $peripherals.GPIO9,
            esp_hal::gpio::InputConfig::default().with_pull(esp_hal::gpio::Pull::Up),
        );
        (identify_led, user_button)
    }};
}

pub(crate) use io;
