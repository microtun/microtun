#![no_std]
#![no_main]

mod board;
mod firmware;
mod network;
mod shell;
mod storage;
mod temp_sensor;

use core::cell::RefCell;

use defmt::{info, warn};
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_net::{ConfigV4, StackResources};
use embassy_stm32::{
    Config, Peri, bind_interrupts, eth,
    flash::Flash,
    pac,
    peripherals::{self, RNG},
    rng::{self, Rng},
    rtc::{Rtc, RtcConfig},
    wdg::IndependentWatchdog,
};
use embassy_sync::blocking_mutex::{Mutex as BlockingMutex, raw::CriticalSectionRawMutex};
use embassy_time::{Duration as EmbassyDuration, Timer, with_timeout};
use firmware::{confirm_firmware_boot, log_firmware_update_error, prepare_firmware_boot};
use microtun_embassy::{TunnelDevice, TunnelState};
use microtun_firmware_common::{
    configuration::{DeviceIdentity, RECORD_SIZE},
    firmware::trial_image_is_healthy,
    net::fallback_static_ipv4_config,
    tunnel::{self as common_tunnel, INNER_STACK_SOCKETS, TUNNEL_QUEUE_DEPTH},
};
use microtun_net_util::{
    FALLBACK_DHCP_RANGE_END, FALLBACK_DHCP_RANGE_START, FALLBACK_IPV4_PREFIX_LEN,
    MICROTUN_MDNS_SERVICE, device_hostname,
};
use network::{
    inner_net_task, outer_net_task, peers_resolver_task, setup_dhcp_task, setup_mdns_task,
    tunnel_task,
};
use shell::{Shell, rtc_unix_time, setup_mode, sync_rtc_from_ntp, telnet_task};
use static_cell::StaticCell;
use storage::{BoardStorage, CONFIGURATION_BUFFER, Storage};
use temp_sensor::TemperatureSensor;

// The Cargo package version is the canonical firmware SemVer. The same
// x.y.z is compiled into the anti-rollback floor and must be supplied to
// `imgtool sign -v` when creating the signed MCUboot envelope.
const FIRMWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

bind_interrupts!(struct Irqs {
    ETH => eth::InterruptHandler;
    HASH_RNG => rng::InterruptHandler<peripherals::RNG>;
});

type OuterDevice = board::OuterDevice;
type InnerDevice = TunnelDevice<'static>;
type HardwareRng = Rng<'static, RNG>;

/// Reset the SoC. Never returns.
///
/// Named rather than spelled out at each of its call sites so that it can also be handed to the
/// shared button monitor as a `fn() -> !`.
fn reset() -> ! {
    cortex_m::peripheral::SCB::sys_reset()
}

fn stm32_reset_reason_name() -> &'static str {
    // Capture the sticky RCC reset flags before HAL clock initialization, then
    // clear them so the next boot reports only the reset that actually caused
    // that boot. POR has priority because the documented power-on reset value
    // sets several subordinate reset flags at once.
    let flags = pac::RCC.c1_rsr().read();
    let reason = if flags.porrstf() {
        "power-on"
    } else if flags.borrstf() {
        "brownout"
    } else if flags.iwdg1rstf() || flags.wwdg1rstf() {
        "watchdog"
    } else if flags.sftrstf() {
        "software"
    } else if flags.pinrstf() {
        "external"
    } else if flags.lpwrrstf() {
        "low-power"
    } else {
        "unknown"
    };

    pac::RCC.c1_rsr().modify(|w| w.set_rmvf(true));
    reason
}

const SETUP_DHCP_PROBE_SECONDS: u64 = 30;
const SETUP_DHCP_PROBE_TIMEOUT: EmbassyDuration =
    EmbassyDuration::from_secs(SETUP_DHCP_PROBE_SECONDS);
/// IWDG period. The LSI-driven 12-bit counter tops out near 32 s, so 30 s
/// is deliberately relaxed while retaining a little hardware headroom.
const WATCHDOG_TIMEOUT_US: u32 = 30_000_000;
const WATCHDOG_PET_INTERVAL: EmbassyDuration = EmbassyDuration::from_secs(5);

static WATCHDOG: BlockingMutex<CriticalSectionRawMutex, RefCell<Option<Watchdog>>> =
    BlockingMutex::new(RefCell::new(None));

type Watchdog = IndependentWatchdog<'static, peripherals::IWDG1>;

/// Pet the watchdog.
///
/// A 128 KiB H7 sector erase blocks the executor for on the order of a second
/// and cannot yield, so the flash paths call this directly instead of relying
/// on `watchdog_task` getting scheduled.
pub(crate) fn pet_watchdog() {
    WATCHDOG.lock(|watchdog| {
        if let Some(watchdog) = watchdog.borrow_mut().as_mut() {
            watchdog.pet();
        }
    });
}

fn start_watchdog(iwdg: Peri<'static, peripherals::IWDG1>) {
    let mut watchdog = IndependentWatchdog::new(iwdg, WATCHDOG_TIMEOUT_US);
    watchdog.unleash();
    WATCHDOG.lock(|slot| *slot.borrow_mut() = Some(watchdog));
}

#[embassy_executor::task]
async fn watchdog_task() -> ! {
    loop {
        pet_watchdog();
        Timer::after(WATCHDOG_PET_INTERVAL).await;
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    reset()
}

#[cortex_m_rt::exception]
unsafe fn HardFault(_: &cortex_m_rt::ExceptionFrame) -> ! {
    reset()
}

#[embassy_executor::main]
async fn main(spawner: Spawner) -> ! {
    let reset_reason = stm32_reset_reason_name();
    let mut chip = Config::default();
    {
        use embassy_stm32::rcc::*;

        chip.rcc.hsi = Some(HSIPrescaler::DIV1);
        chip.rcc.csi = true;
        chip.rcc.hsi48 = Some(Default::default()); // RNG clock
        chip.rcc.pll1 = Some(Pll {
            source: PllSource::HSI,
            prediv: PllPreDiv::DIV4,
            mul: PllMul::MUL50,
            divp: Some(PllDiv::DIV2),
            divq: None,
            divr: None,
        });
        chip.rcc.pll2 = Some(Pll {
            source: PllSource::HSI,
            prediv: PllPreDiv::DIV4,
            mul: PllMul::MUL50,
            divp: Some(PllDiv::DIV8), // 100 MHz; ADC driver prescales to <=50 MHz.
            divq: None,
            divr: None,
        });
        chip.rcc.mux.adcsel = mux::Adcsel::from_bits(0); // PLL2_P
        chip.rcc.sys = Sysclk::PLL1_P; // 400 MHz
        chip.rcc.ahb_pre = AHBPrescaler::DIV2; // 200 MHz
        chip.rcc.apb1_pre = APBPrescaler::DIV2; // 100 MHz
        chip.rcc.apb2_pre = APBPrescaler::DIV2;
        chip.rcc.apb3_pre = APBPrescaler::DIV2;
        chip.rcc.apb4_pre = APBPrescaler::DIV2;
        chip.rcc.voltage_scale = VoltageScale::Scale1;
        chip.rcc.ls = LsConfig::default_lsi();
    }

    let p = embassy_stm32::init(chip);

    // Arm the watchdog before any flash work. `watchdog_task` takes over the
    // petting once the executor is running; the flash paths pet directly.
    start_watchdog(p.IWDG1);

    let temperature_sensor = TemperatureSensor::new(p.ADC3);
    static STORAGE: StaticCell<Storage> = StaticCell::new();
    let storage = STORAGE.init(Storage::new(BoardStorage::new(Flash::new_blocking(
        p.FLASH,
    ))));
    let mut firmware_status = match storage
        .with_backend(|backend| prepare_firmware_boot(backend.flash_mut()))
        .await
    {
        Ok(status) => status,
        Err(error) => {
            log_firmware_update_error(&error);
            reset();
        }
    };
    if firmware_status.trial {
        info!("Embassy Boot trial image is pending verification");
    } else if firmware_status.state == "recovered" {
        warn!("Embassy Boot restored the previously confirmed firmware image");
    }
    let configuration_scratch = CONFIGURATION_BUFFER.init([0u8; RECORD_SIZE]);
    let stored_config = storage
        .load_config(&mut *configuration_scratch)
        .await
        .expect("read configuration flash");

    let identity = stm32_device_identity();
    let mut rng = Rng::new(p.RNG, Irqs);

    let outer_seed = rng.next_u64();
    let inner_seed = rng.next_u64();
    let mut websocket_seed = [0u8; 32];
    rng.fill_bytes(&mut websocket_seed);
    let mac = identity.mac();

    let ethernet = board::ethernet!(p, mac);

    // Start Ethernet as a DHCP client in both modes. A configured board simply
    // keeps its operational lease. An unconfigured board uses this first lease
    // attempt only as a conservative probe for an already-managed LAN; if no
    // server answers within the setup-mode timeout, it switches to the
    // fixed setup subnet and starts its own tiny DHCP server.
    let mut dhcp_config = embassy_net::DhcpConfig::default();
    dhcp_config.hostname =
        Some(device_hostname(identity.device_id().as_str()).expect("device ID fits hostname"));
    let outer_config = embassy_net::Config::dhcpv4(dhcp_config);

    // Peak socket use is setup mode: built-in DHCP + DNS, mDNS UDP, Telnet TCP,
    // and one transient ICMP socket while the Telnet client runs `ping net`. Operational
    // mode peaks at four (DHCP + DNS + tunnel UDP + CLI ping).
    static OUTER_RESOURCES: StaticCell<StackResources<5>> = StaticCell::new();
    let (outer_stack, outer_runner) = embassy_net::new(
        ethernet,
        outer_config,
        OUTER_RESOURCES.init(StackResources::new()),
        outer_seed,
    );
    spawner.spawn(outer_net_task(outer_runner).unwrap());
    spawner.spawn(watchdog_task().unwrap());

    // The concrete board GPIO assignments and polarities live in board.rs.
    let (identify_led, user_button) = board::io!(p);

    let (config, identify_led, user_button) = match stored_config {
        Some(config) => (config, identify_led, user_button),
        None => {
            if firmware_status.trial {
                warn!(
                    "trial OTA image could not load device configuration; resetting for rollback"
                );
                reset();
            }
            warn!("device is not configured or the flash config is invalid");
            outer_stack.wait_link_up().await;

            info!("setup mode: probing for an existing DHCP server");
            if with_timeout(SETUP_DHCP_PROBE_TIMEOUT, outer_stack.wait_config_up())
                .await
                .is_ok()
            {
                if let Some(config) = outer_stack.config_v4() {
                    info!(
                        "setup mode: existing DHCP server detected; lease is {}",
                        config.address
                    );
                }
                info!("setup mode: the main Telnet CLI can discover this DHCP lease via mDNS");
            } else {
                info!(
                    "setup mode: no DHCP lease after {}s; using isolated fallback subnet",
                    SETUP_DHCP_PROBE_SECONDS
                );
                outer_stack.set_config_v4(ConfigV4::Static(fallback_static_ipv4_config()));
                spawner.spawn(setup_dhcp_task(outer_stack).unwrap());
                info!(
                    "setup mode: DHCP server will assign {}.{}.{}.{}-{}.{}.{}.{}/{}",
                    FALLBACK_DHCP_RANGE_START[0],
                    FALLBACK_DHCP_RANGE_START[1],
                    FALLBACK_DHCP_RANGE_START[2],
                    FALLBACK_DHCP_RANGE_START[3],
                    FALLBACK_DHCP_RANGE_END[0],
                    FALLBACK_DHCP_RANGE_END[1],
                    FALLBACK_DHCP_RANGE_END[2],
                    FALLBACK_DHCP_RANGE_END[3],
                    FALLBACK_IPV4_PREFIX_LEN
                );
            }

            spawner.spawn(setup_mdns_task(outer_stack, identity).unwrap());
            info!(
                "setup mode: advertising {} over mDNS/DNS-SD",
                MICROTUN_MDNS_SERVICE
            );
            let shell = Shell::setup(
                identity,
                reset_reason,
                outer_stack,
                firmware_status,
                mac,
                temperature_sensor,
                identify_led,
            );
            setup_mode(storage, shell, configuration_scratch).await
        }
    };
    spawner.spawn(board::user_button_reset_task(user_button, storage).unwrap());

    info!("waiting for wired Ethernet DHCP");
    outer_stack.wait_config_up().await;
    info!("wired Ethernet DHCP lease acquired");

    info!(
        "loaded device configuration for tunnel {}",
        config.tunnel.tunnel_address.as_str()
    );
    let (mut rtc, rtc_time) = Rtc::new(p.RTC, RtcConfig::default());

    let wall_clock = if let Some(ntp) = config.ntp.as_ref() {
        Some(
            sync_rtc_from_ntp(
                outer_stack,
                &mut rtc,
                &rtc_time,
                ntp.host.as_str(),
                ntp.port,
            )
            .await,
        )
    } else {
        info!("NTP not configured; using the current STM32 RTC value");
        rtc_unix_time(&rtc_time)
    };

    if wall_clock.is_none() {
        warn!("no usable wall clock is available to microtun");
    }

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
        wall_clock,
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
        info!("trial OTA core services are up; checking tunnel health before confirmation");
        if !trial_image_is_healthy(inner_stack).await {
            warn!("trial OTA image did not reach the inner tunnel link; resetting for rollback");
            reset();
        }
        firmware_status = match storage
            .with_backend(|backend| confirm_firmware_boot(backend.flash_mut()))
            .await
        {
            Ok(status) => {
                info!("trial OTA image confirmed; automatic rollback disabled");
                status
            }
            Err(error) => {
                log_firmware_update_error(&error);
                reset();
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
                rtc_time,
                mac,
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

fn stm32_device_identity() -> DeviceIdentity {
    let uid = embassy_stm32::uid::uid();
    DeviceIdentity::from_unique_bytes(&uid).expect("STM32 UID fits device identity")
}
