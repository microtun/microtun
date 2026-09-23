#![no_std]
#![no_main]

extern crate alloc;

mod firmware;
mod network;
mod shell;
mod storage;

use core::cell::RefCell;

use embassy_executor::Spawner;
use embassy_net::StackResources;
use embassy_sync::blocking_mutex::{Mutex as BlockingMutex, raw::CriticalSectionRawMutex};
use embassy_time::{Duration as EmbassyDuration, Timer};
use esp_alloc as _;
use esp_hal::{
    clock::CpuClock,
    efuse,
    gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull},
    interrupt::software::SoftwareInterruptControl,
    rng::{Trng, TrngSource},
    rtc_cntl::{Rtc, RwdtStage, SocResetReason},
    system::{reset_reason as hal_reset_reason, software_reset},
    timer::timg::TimerGroup,
    tsens::{Config as TemperatureSensorConfig, TemperatureSensor},
};
use esp_radio::wifi::{
    Config as WifiConfig, ControllerConfig, Interface, WifiController, sta::StationConfig,
};
use esp_storage::FlashStorage;
use firmware::{confirm_firmware_ota, prepare_firmware_ota};
use log::{info, warn};
use microtun_embassy::{TunnelDevice, TunnelState};
use microtun_examples_common::{
    board::{IdentifyLed, ResetButton, monitor_reset},
    configuration::{DeviceIdentity, RECORD_SIZE},
    firmware::trial_image_is_healthy,
    tunnel::{self as common_tunnel, INNER_STACK_SOCKETS, TUNNEL_QUEUE_DEPTH},
};
use microtun_net_util::{device_ap_ssid, device_hostname};
use network::{
    inner_net_task, outer_net_task, peers_resolver_task, start_setup_ap, tunnel_task,
    wifi_connection_task,
};
use rand_core::RngCore as _;
use shell::{Shell, WallClock, setup_mode, sync_time_from_ntp, telnet_task};
use static_cell::StaticCell;
use storage::{BoardStorage, CONFIGURATION_BUFFER, Storage};

// The Cargo package version is the canonical firmware SemVer. The same
// x.y.z is compiled into the anti-rollback floor and must be supplied to
// `imgtool sign -v` when creating the signed MCUboot envelope.
const FIRMWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

// Make the native ESP application descriptor the canonical firmware metadata.
esp_bootloader_esp_idf::esp_app_desc!(
    FIRMWARE_VERSION,
    env!("CARGO_PKG_NAME"),
    esp_bootloader_esp_idf::BUILD_TIME,
    esp_bootloader_esp_idf::BUILD_DATE,
    esp_bootloader_esp_idf::ESP_IDF_COMPATIBLE_VERSION,
    esp_bootloader_esp_idf::MMU_PAGE_SIZE,
    0,
    u16::MAX,
    esp_bootloader_esp_idf::SECURE_VERSION
);

const CONFIGURATION_ADDRESS: u32 = 0x003f_0000;
// The `microtun` partition in `partitions.csv` is exactly one 4 KiB flash
// sector, which is also the portable record size, so the whole partition is
// erased and rewritten as a unit.
const DEVICE_MODEL: &str = "ESP32-C6-PLC-V";

// GPIO9 is the BOOT strap. Resetting while it is held low would enter the ROM downloader, so
// keep the shared timings and only override the release policy.
const USER_BUTTON: ResetButton = ResetButton {
    active_low: true,
    reset_on_release: true,
    ..ResetButton::DEFAULT
};

type OuterDevice = Interface;
type InnerDevice = TunnelDevice<'static>;
type HardwareRng = Trng;

/// The one board LED reserved by the example for `identify`.
///
/// Relay outputs and field inputs are deliberately not configured here so application code can
/// claim those peripherals independently. The RUN LED is wired from 3.3 V into GPIO8, so driving
/// the pin low sinks current and turns the LED on.
struct IdentifyLedPin {
    led: Output<'static>,
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

/// Hardware watchdog period. Intentionally fairly relaxed so transient stalls
/// do not cause unnecessary resets while a genuinely wedged image still
/// eventually reboots into rollback.
const WATCHDOG_TIMEOUT: esp_hal::time::Duration = esp_hal::time::Duration::from_secs(30);
const WATCHDOG_PET_INTERVAL: EmbassyDuration = EmbassyDuration::from_secs(5);

static WATCHDOG: BlockingMutex<CriticalSectionRawMutex, RefCell<Option<Rtc<'static>>>> =
    BlockingMutex::new(RefCell::new(None));

/// Feed the watchdog.
///
/// Synchronous flash work runs with interrupts and the cache disabled, so the
/// executor cannot run `watchdog_task` during it; those paths call this
/// directly.
pub(crate) fn pet_watchdog() {
    WATCHDOG.lock(|watchdog| {
        if let Some(rtc) = watchdog.borrow_mut().as_mut() {
            rtc.rwdt.feed();
        }
    });
}

fn start_watchdog(rtc_cntl: esp_hal::peripherals::LPWR<'static>) {
    let mut rtc = Rtc::new(rtc_cntl);
    rtc.rwdt.set_timeout(RwdtStage::Stage0, WATCHDOG_TIMEOUT);
    rtc.rwdt.enable();
    WATCHDOG.lock(|watchdog| *watchdog.borrow_mut() = Some(rtc));
}

#[embassy_executor::task]
async fn watchdog_task() -> ! {
    loop {
        pet_watchdog();
        Timer::after(WATCHDOG_PET_INTERVAL).await;
    }
}

/// Monitor the active-low BOOT/user button while the device is configured.
///
/// Holding it erases the configuration record; the next boot finds none and comes up in
/// setup mode. The debounce and hold logic is shared — all this board contributes is that
/// GPIO9 reads low while held, and that it is a boot strap, which is what
/// [`ResetButton::reset_on_release`] is for.
#[embassy_executor::task]
async fn user_button_reset_task(button: Input<'static>, storage: &'static Storage) -> ! {
    monitor_reset(button, USER_BUTTON, storage, software_reset).await
}

// A panic in a trial image must return control to the rollback-capable
// second-stage bootloader. Halting forever would strand the device in the bad
// image and defeat A/B recovery.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    software_reset()
}

#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    esp_println::logger::init_logger_from_env();

    let hal_config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(hal_config);
    let reset_reason = esp_reset_reason_name(hal_reset_reason());

    // Arm the watchdog before anything else can hang. The petting task is
    // spawned as soon as the executor is running; until then the only work is
    // flash access, which pets directly.
    start_watchdog(peripherals.LPWR);

    // Every flash user shares this one mutex-backed storage handle, in both setup and
    // operational mode. Boot-time reads use the same path before any concurrent tasks exist.
    static STORAGE: StaticCell<Storage> = StaticCell::new();
    let storage = STORAGE.init(Storage::new(BoardStorage::new(FlashStorage::new(
        peripherals.FLASH,
    ))));
    let mut firmware_status = storage
        .with_backend(|backend| prepare_firmware_ota(backend.flash_mut()))
        .await;
    let configuration_scratch = CONFIGURATION_BUFFER.init([0u8; RECORD_SIZE]);
    let stored_config = storage
        .load_config(&mut *configuration_scratch)
        .await
        .expect("read configuration flash");

    // reclaimed bootloader ram
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 64 * 1024);
    // tunnel etc
    esp_alloc::heap_allocator!(size: 72 * 1024);

    // esp-radio's async Wi-Fi driver expects the esp-rtos preemptive scheduler.
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);
    spawner.spawn(watchdog_task().unwrap());

    let temperature_sensor =
        TemperatureSensor::new(peripherals.TSENS, TemperatureSensorConfig::default())
            .expect("initialize ESP32-C6 temperature sensor");
    // Espressif recommends allowing a few hundred microseconds for TSENS to
    // settle after power-up before taking the first reading.
    Timer::after_millis(1).await;

    // microtun's handshake/cookie path requires rand_core 0.6 CryptoRng. On the
    // C6, TrngSource keeps RNG+ADC1 supplying entropy while Trng is the handle
    // that implements RngCore + CryptoRng. Keep the source alive for main's
    // whole (never-ending) scope.
    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let mut rng = Trng::try_new().expect("initialize ESP32-C6 TRNG");
    let outer_seed = rng.next_u64();
    let inner_seed = rng.next_u64();
    let mut websocket_seed = [0u8; 32];
    rng.fill_bytes(&mut websocket_seed);

    let identity = esp32_device_identity();

    // A configured device joins the operator's Wi-Fi network as a station. An
    // unconfigured one cannot: the credentials for that network are part of the
    // configuration it is still waiting to receive. It therefore hosts its own
    // open access point on a per-device SSID and serves setup mode there.
    //
    // Reserve only the RUN LED for `identify`. Relay outputs and field inputs are intentionally
    // left unconfigured so the rest of the application can use them.
    let identify_led = IdentifyLedPin {
        led: Output::new(peripherals.GPIO8, Level::High, OutputConfig::default()),
    };
    // GPIO9/BOOT is reserved only for the configuration-reset gesture: hold it for three seconds
    // on a configured device to erase the stored configuration and return to setup mode.
    let user_button = Input::new(
        peripherals.GPIO9,
        InputConfig::default().with_pull(Pull::Up),
    );

    let (config, identify_led, user_button) = match stored_config {
        Some(config) => (config, identify_led, user_button),
        None => {
            if firmware_status.trial {
                warn!(
                    "trial OTA image could not load device configuration; resetting so the bootloader rolls back"
                );
                software_reset();
            }
            warn!("device is not configured or the flash config is invalid");
            let (stack, mac) =
                start_setup_ap(spawner, peripherals.WIFI, &identity, outer_seed).await;
            let wifi_ssid =
                device_ap_ssid(identity.device_id().as_str()).expect("device ID fits SSID");
            let shell = Shell::setup(
                identity,
                reset_reason,
                stack,
                firmware_status,
                mac,
                wifi_ssid,
                temperature_sensor,
                identify_led,
            );
            setup_mode(storage, shell, configuration_scratch).await
        }
    };

    spawner.spawn(user_button_reset_task(user_button, storage).unwrap());
    info!(
        "loaded device configuration for tunnel {}",
        config.tunnel.tunnel_address
    );

    let wifi = config
        .wifi
        .as_ref()
        .expect("ESP32-C6 device configuration requires a Wi-Fi section");
    let station_config = WifiConfig::Station(
        StationConfig::default()
            .with_ssid(wifi.ssid.as_str())
            .with_password(wifi.password.as_str().into()),
    );
    let wifi_interface = Interface::station();
    let mac = wifi_interface.mac_address();
    let wifi_ssid = wifi.ssid.clone();
    let wifi_controller = WifiController::new(
        peripherals.WIFI,
        ControllerConfig::default().with_initial_config(station_config),
    )
    .expect("create Wi-Fi controller");

    // Operational peak: built-in DHCP + DNS, the tunnel UDP socket, and one transient
    // ICMP socket while the inner Telnet client runs `ping net`.
    static OUTER_RESOURCES: StaticCell<StackResources<4>> = StaticCell::new();
    let (outer_stack, outer_runner) = embassy_net::new(
        wifi_interface,
        {
            let mut dhcp_config = embassy_net::DhcpConfig::default();
            dhcp_config.hostname = Some(
                device_hostname(identity.device_id().as_str()).expect("device ID fits hostname"),
            );
            embassy_net::Config::dhcpv4(dhcp_config)
        },
        OUTER_RESOURCES.init(StackResources::new()),
        outer_seed,
    );

    spawner.spawn(wifi_connection_task(wifi_controller).unwrap());
    spawner.spawn(outer_net_task(outer_runner).unwrap());

    info!("waiting for ESP32-C6 Wi-Fi DHCP");
    outer_stack.wait_config_up().await;
    info!("Wi-Fi DHCP lease acquired");

    let wall_clock = if let Some(ntp) = config.ntp.as_ref() {
        let (unix_secs, unix_nanos) =
            sync_time_from_ntp(outer_stack, ntp.host.as_str(), ntp.port).await;
        Some(WallClock::new(unix_secs, unix_nanos))
    } else {
        warn!("NTP not configured; no wall clock will be supplied to microtun");
        None
    };
    static TUNNEL_STATE: StaticCell<TunnelState<TUNNEL_QUEUE_DEPTH, TUNNEL_QUEUE_DEPTH>> =
        StaticCell::new();
    static INNER_RESOURCES: StaticCell<StackResources<INNER_STACK_SOCKETS>> = StaticCell::new();
    let common_tunnel::Setup {
        runner: tunnel,
        inner_stack,
        inner_runner,
        status: tunnel_status,
        tracker_tunnel_addr,
    } = common_tunnel::setup(
        outer_stack,
        inner_seed,
        &config,
        rng,
        TUNNEL_STATE.init(TunnelState::<TUNNEL_QUEUE_DEPTH, TUNNEL_QUEUE_DEPTH>::new()),
        INNER_RESOURCES.init(StackResources::new()),
        wall_clock.map(|clock| clock.now()),
    )
    .await;
    spawner.spawn(inner_net_task(inner_runner).unwrap());

    let local_public_key = tunnel.public_key();
    info!("microtun tunnel ready; telnet is only on the inner interface");
    spawner.spawn(tunnel_task(tunnel, outer_stack).unwrap());
    spawner.spawn(
        peers_resolver_task(
            inner_stack,
            local_public_key,
            tracker_tunnel_addr,
            websocket_seed,
        )
        .unwrap(),
    );

    if firmware_status.trial {
        info!("OTA image is pending verification; checking tunnel health before confirmation");
        if !trial_image_is_healthy(inner_stack).await {
            warn!("trial OTA image did not reach the inner tunnel link; resetting for rollback");
            software_reset();
        }
        firmware_status = match storage
            .with_backend(|backend| confirm_firmware_ota(backend.flash_mut()))
            .await
        {
            Ok(status) => status,
            Err(error) => {
                warn!(
                    "failed to confirm healthy OTA image: {:?}; resetting to force rollback",
                    error
                );
                software_reset();
            }
        };
    }

    spawner.spawn(
        telnet_task(
            Shell::operational(
                identity,
                reset_reason,
                outer_stack,
                inner_stack,
                tunnel_status,
                firmware_status,
                wall_clock,
                mac,
                wifi_ssid,
                temperature_sensor,
                identify_led,
            ),
            storage,
            configuration_scratch,
        )
        .unwrap(),
    );

    core::future::pending().await
}

fn esp32_device_identity() -> DeviceIdentity {
    // The factory eFuse base MAC is the ESP32-C6's stable per-chip identifier,
    // the counterpart of the STM32's 96-bit UID. The Wi-Fi interfaces derive
    // their own addresses from it, so this identity is consistent with what the
    // radio advertises without the firmware having to set any MAC itself.
    let base_mac = efuse::base_mac_address();

    let mut mac = [0u8; 6];
    mac.copy_from_slice(base_mac.as_bytes());
    DeviceIdentity::from_mac(mac)
}

fn esp_reset_reason_name(reason: Option<SocResetReason>) -> &'static str {
    match reason {
        Some(SocResetReason::ChipPowerOn) => "power-on",
        Some(SocResetReason::SysBrownOut) => "brownout",
        Some(
            SocResetReason::CoreMwdt0
            | SocResetReason::CoreMwdt1
            | SocResetReason::CoreRtcWdt
            | SocResetReason::Cpu0Mwdt0
            | SocResetReason::Cpu0Mwdt1
            | SocResetReason::Cpu0RtcWdt
            | SocResetReason::SysRtcWdt
            | SocResetReason::SysSuperWdt,
        ) => "watchdog",
        Some(SocResetReason::CoreSw | SocResetReason::Cpu0Sw) => "software",
        Some(SocResetReason::CoreDeepSleep) => "deep-sleep",
        Some(
            SocResetReason::CoreSDIO
            | SocResetReason::CoreUsbUart
            | SocResetReason::CoreUsbJtag
            | SocResetReason::Cpu0JtagCpu,
        ) => "external",
        Some(SocResetReason::CoreEfuseCrc) => "hardware",
        None => "unknown",
    }
}
