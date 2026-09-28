//! Board profile for the LEOTRO ESP32-C3 RS232 Adapter V1.1.
//!
//! Schematic net mapping used by the firmware:
//! - GPIO10 -> MCU_TX -> SP3232 -> RS232_TX (DE-9 pin 3)
//! - GPIO4 <- MCU_RX <- SP3232 <- RS232_RX (DE-9 pin 2)
//! - GPIO0 -> MCU_RTS -> SP3232 -> RS232_RTS (DE-9 pin 7)
//! - GPIO1 <- MCU_CTS <- SP3232 <- RS232_CTS (DE-9 pin 8)
//! - GPIO9 -> BOOT button
//!
//! The board's LED is a power LED wired directly between 3.3 V and ground, so
//! there is no software-controlled identify LED.

use esp_hal::{
    Async,
    gpio::{Input, Output},
    uart::Uart,
};
use microtun_firmware_common::board::{IdentifyLed, ResetButton, monitor_reset};

use crate::storage::Storage;

pub(crate) const DEVICE_MODEL: &str = "ESP32-C3 RS232 Adapter V1.1";
pub(crate) const CONFIGURATION_ADDRESS: u32 = 0x003f_0000;

pub(crate) type Rs232Uart = Uart<'static, Async>;
pub(crate) type Rs232Rts = Output<'static>;
pub(crate) type Rs232Cts = Input<'static>;

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

/// Pins used outside the RS232 interface.
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

/// Construct the physical RS232 port.
///
/// UART1 is intentionally used so firmware logging/debug transport does not
/// contend with the exposed serial port. RTS remains a GPIO rather than being
/// handed to the UART peripheral: RFC 2217 must be able to explicitly assert
/// and deassert RTS. CTS is also kept as a GPIO input so the server can report
/// MODEMSTATE changes and implement RFC 2217 hardware flow control in software.
macro_rules! rs232 {
    ($peripherals:ident) => {{
        // Use fully-qualified names inside this exported macro. `macro_rules!`
        // identifiers are resolved at the invocation site, so imports in this
        // module are not visible when `board::rs232!` expands in `main.rs`.
        let uart = esp_hal::uart::Uart::new($peripherals.UART1, esp_hal::uart::Config::default())
            .expect("initialize RS232 UART")
            .with_rx($peripherals.GPIO4)
            .with_tx($peripherals.GPIO10)
            .into_async();

        // SP3232 transmitters invert logic. Driving MCU_RTS low produces a
        // positive/asserted RS232 RTS level on DE-9 pin 7.
        let rts = esp_hal::gpio::Output::new(
            $peripherals.GPIO0,
            esp_hal::gpio::Level::Low,
            esp_hal::gpio::OutputConfig::default(),
        );
        let cts =
            esp_hal::gpio::Input::new($peripherals.GPIO1, esp_hal::gpio::InputConfig::default());
        (uart, rts, cts)
    }};
}

pub(crate) use io;
pub(crate) use rs232;
