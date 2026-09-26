//! Board interaction policy that is the same everywhere: reset-button monitoring and identify LED
//! timing.
//!
//! Electrical polarity and LED semantics stay board-local; this module owns the timing and
//! state-machine behavior so the board implementations do not drift apart.

use defmt_or_log::{info, warn};
use embassy_time::{Duration, Instant, Timer};
use embedded_hal::digital::InputPin;
use embedded_storage::nor_flash::NorFlash;

use crate::storage::Storage;

/// Duration announced by the setup shell and used by its long identify pattern.
pub const SETUP_IDENTIFY_SECONDS: u8 = 5;

/// Timings, polarity, and reset behaviour for the configuration-reset button.
#[derive(Clone, Copy)]
pub struct ResetButton {
    /// Whether a low pin level means the button is pressed.
    pub active_low: bool,

    /// How long the button must be held before the configuration record is erased.
    pub hold: Duration,

    /// How often the pin is sampled. Also the debounce granularity.
    pub poll_interval: Duration,

    /// How long the button must read released before a release is believed.
    pub release_settle: Duration,

    /// Wait for a stable release before resetting.
    ///
    /// The ESP32-C3/C6 user button is also the BOOT strap, so resetting while it is still held
    /// drops the chip into the ROM downloader instead of rebooting into setup mode. A
    /// board whose button is not a strap — the Nucleo's B1 — can reset immediately.
    pub reset_on_release: bool,
}

impl ResetButton {
    /// Active-high, three seconds, sampled every 20 ms, with a 50 ms release debounce.
    pub const DEFAULT: Self = Self {
        active_low: false,
        hold: Duration::from_secs(3),
        poll_interval: Duration::from_millis(20),
        release_settle: Duration::from_millis(50),
        reset_on_release: false,
    };
}

fn button_is_pressed<P: InputPin>(button: &mut P, config: ResetButton) -> Result<bool, P::Error> {
    if config.active_low {
        button.is_low()
    } else {
        button.is_high()
    }
}

/// Wait until the button has read released continuously for `release_settle`.
async fn wait_for_release<P: InputPin>(button: &mut P, config: ResetButton) {
    let mut released_since = None;

    loop {
        match button_is_pressed(button, config) {
            Ok(true) => released_since = None,
            Ok(false) => {
                let now = Instant::now();
                let since = *released_since.get_or_insert(now);
                if now >= since + config.release_settle {
                    return;
                }
            }
            Err(_) => {
                // A failed sample cannot prove a stable release.
                released_since = None;
            }
        }

        Timer::after(config.poll_interval).await;
    }
}

/// Erase the configuration record and reset when the user button is held. Never returns.
///
/// The pin uses the standard [`InputPin`] trait; [`ResetButton::active_low`] captures the only
/// board-specific input semantic. `#[embassy_executor::task]` cannot be generic, so each board
/// wraps this in a one-line task.
///
/// After the erase the next boot finds no valid record and comes up in setup mode.
pub async fn monitor_reset<P, B>(
    mut button: P,
    config: ResetButton,
    storage: &Storage<B>,
    reset: fn() -> !,
) -> !
where
    P: InputPin,
    B: NorFlash,
{
    let mut pressed_since = None;

    loop {
        match button_is_pressed(&mut button, config) {
            Ok(false) => {
                pressed_since = None;
                Timer::after(config.poll_interval).await;
                continue;
            }
            Err(_) => {
                warn!("failed to read configuration-reset button");
                pressed_since = None;
                Timer::after(config.poll_interval).await;
                continue;
            }
            Ok(true) => {}
        }

        let now = Instant::now();
        let since = *pressed_since.get_or_insert(now);
        if now < since + config.hold {
            Timer::after(config.poll_interval).await;
            continue;
        }

        info!(
            "user button held for {}s; clearing device configuration",
            config.hold.as_secs()
        );

        match storage.erase_config().await {
            Ok(()) => {
                if config.reset_on_release {
                    info!(
                        "device configuration cleared; release the user button to reboot into setup mode"
                    );
                    wait_for_release(&mut button, config).await;
                    info!("user button released; rebooting into setup mode");
                } else {
                    info!("device configuration cleared; rebooting into setup mode");
                }
                reset();
            }
            Err(error) => {
                warn!(
                    "failed to clear device configuration after user-button hold: {}",
                    error
                );

                // Do not hammer the flash with retries while the same long press is still
                // active. Re-arm only after a stable release.
                wait_for_release(&mut button, config).await;
                pressed_since = None;
            }
        }
    }
}

/// Minimal logical LED capability needed by the shared identify patterns.
///
/// This intentionally remains a domain trait rather than exposing `OutputPin`: a logical LED
/// "on" maps to HIGH on some boards and LOW on others.
pub trait IdentifyLed {
    fn is_on(&self) -> bool;
    fn set_on(&mut self, on: bool);
}

/// Run the long identify pattern used in setup mode.
pub async fn identify_setup_led<L: IdentifyLed>(led: &mut L) {
    blink_led(led, SETUP_IDENTIFY_SECONDS * 2, Duration::from_millis(250)).await;
}

/// Run the short identify pattern used by an operational shell.
pub async fn identify_operational_led<L: IdentifyLed>(led: &mut L) {
    blink_led(led, 3, Duration::from_millis(150)).await;
}

async fn blink_led<L: IdentifyLed>(led: &mut L, pulses: u8, half_period: Duration) {
    let saved_state = led.is_on();
    for _ in 0..pulses {
        led.set_on(true);
        Timer::after(half_period).await;
        led.set_on(false);
        Timer::after(half_period).await;
    }
    led.set_on(saved_state);
}
