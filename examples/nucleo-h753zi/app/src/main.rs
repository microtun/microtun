#![no_std]
#![no_main]

mod firmware;
mod stm32_phy;
mod temperature_sensor;

use core::{cell::RefCell, fmt::Write as _, net::IpAddr};

use chrono::Datelike;
use defmt::{info, warn};
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_net::{
    ConfigV4, Ipv4Address, Ipv4Cidr, Stack, StackResources, StaticConfigV4, tcp::TcpSocket,
    udp::PacketMetadata,
};
use embassy_stm32::{
    Config, Peri, bind_interrupts, eth,
    eth::{Ethernet, PacketQueue, Sma},
    flash::{Blocking, Flash},
    gpio::{Input, Level, Output, Pull, Speed},
    pac,
    peripherals::{self, ETH, ETH_SMA, RNG},
    rng::{self, Rng},
    rtc::{DateTime as RtcDateTime, Rtc, RtcConfig, RtcTimeProvider},
    wdg::IndependentWatchdog,
};
use embassy_sync::{
    blocking_mutex::{Mutex as BlockingMutex, raw::CriticalSectionRawMutex},
    mutex::Mutex,
};
use embassy_time::{Duration as EmbassyDuration, Instant as EmbassyInstant, Timer, with_timeout};
use embedded_io_async::Write as AsyncWrite;
use firmware::{
    FirmwareStatus, confirm_firmware_boot, firmware_update_error_text, log_firmware_update_error,
    prepare_firmware_boot, receive_firmware_update, receive_ymodem_buffer, telnet_write_data,
};
use microtun_embassy::{
    TunnelDevice, TunnelRunner, TunnelState, TunnelStatus, core::key::encode_key,
};
use microtun_examples_common::{
    cli::{
        DEFAULT_PING_COUNT, IoAction, PingIface, SYS_TABLE, SysField, TELNET_PORT,
        TELNET_TCP_BUFFER, TunnelAction, field as cli_field, line as cli_line, ping as cli_ping,
        println as cli_println, time as cli_time, time_field as cli_time_field,
        write_ip_status as cli_write_ip_status, write_link_status as cli_write_link_status,
        write_mac_status as cli_write_mac_status, write_net_base as cli_write_net_base,
        write_tunnel_status,
    },
    firmware::transfer_error_text,
    net::{TCP_IDLE_TIMEOUT, TCP_KEEP_ALIVE, ntp_unix_time, query_ntp_time},
    table::Table,
    tunnel::{self as common_tunnel, OUTER_UDP_PACKETS, TUNNEL_QUEUE_DEPTH},
};
use microtun_provisioning::{
    ConfigStore, ConfigStoreError, DeviceIdentity, IDENTIFY_SECONDS, MAX_INI_LEN,
    PROVISION_DEVICE_IPV4, PROVISION_DHCP_RANGE_END, PROVISION_DHCP_RANGE_START,
    PROVISION_IPV4_PREFIX_LEN, PROVISION_PORT, PROVISION_STORED, PROVISION_YMODEM_READY,
    ProvisionRecord, RECORD_SIZE, TELNET_PROMPT, decode_record, device_hostname, encode_record,
};
use microtun_telnet_cli::{
    Config as CliConfig, Dispatch, Error as CliError, IoError, Parser, ParserFamily, Session,
    ValueEnum,
};
use static_cell::StaticCell;
use stm32_phy::{Lan8742Phy, phy_link_snapshot};
use temperature_sensor::TemperatureSensor;

// The Cargo package version is the canonical firmware SemVer. The same
// x.y.z is compiled into the anti-rollback floor and must be supplied to
// `imgtool sign -v` when creating the signed MCUboot envelope.
const FIRMWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

bind_interrupts!(struct Irqs {
    ETH => eth::InterruptHandler;
    HASH_RNG => rng::InterruptHandler<peripherals::RNG>;
});

type OuterPhy = Lan8742Phy<Sma<'static, ETH_SMA>>;
type OuterDevice = Ethernet<'static, ETH, OuterPhy>;
type InnerDevice = TunnelDevice<'static>;
type HardwareRng = Rng<'static, RNG>;
type SharedFlash = Mutex<CriticalSectionRawMutex, Flash<'static, Blocking>>;

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

// Provisioning occupies bank 2 sector 7. Embassy Boot's swap partitions
// exclude that sector, so this physical flash offset remains stable.
const PROVISION_OFFSET: u32 = 0x001e_0000;
const PROVISION_SECTOR_SIZE: u32 = 0x0002_0000;

fn provision_offset() -> u32 {
    PROVISION_OFFSET
}

const PROVISION_DHCP_PROBE_SECONDS: u64 = 30;
const PROVISION_DHCP_PROBE_TIMEOUT: EmbassyDuration =
    EmbassyDuration::from_secs(PROVISION_DHCP_PROBE_SECONDS);
const DEVICE_MODEL: &str = "NUCLEO-H753ZI";
const OTA_TRIAL_HEALTH_WINDOW: EmbassyDuration = EmbassyDuration::from_secs(30);
/// How long the trial image may wait for the inner tunnel link before the
/// attempt is abandoned.
///
/// Without a bound here a trial image that comes up but never reaches the
/// tunnel simply waits forever: it is never confirmed, but nothing resets it
/// either, so the rollback Embassy Boot is holding ready is never taken.
const OTA_TRIAL_LINK_TIMEOUT: EmbassyDuration = EmbassyDuration::from_secs(120);

/// IWDG period. The LSI-driven 12-bit counter tops out near 32 s, so 20 s
/// leaves headroom while still rebooting a wedged image quickly.
const WATCHDOG_TIMEOUT_US: u32 = 20_000_000;
const WATCHDOG_PET_INTERVAL: EmbassyDuration = EmbassyDuration::from_secs(4);

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
async fn watchdog_task() {
    loop {
        pet_watchdog();
        Timer::after(WATCHDOG_PET_INTERVAL).await;
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    cortex_m::peripheral::SCB::sys_reset()
}

#[cortex_m_rt::exception]
unsafe fn HardFault(_: &cortex_m_rt::ExceptionFrame) -> ! {
    cortex_m::peripheral::SCB::sys_reset()
}

/// Board-level I/O owned by the main Telnet shell.
///
/// UM2407 documents LD1/LD2/LD3 as active-high GPIO outputs on PB0, PE1,
/// and PB14 respectively. The same I/O surface remains available while the
/// device is waiting to be provisioned.
struct NucleoBoardIo {
    leds: [Output<'static>; 3],
}

impl NucleoBoardIo {
    fn set_led(&mut self, index: usize, on: bool) -> bool {
        let Some(led) = self.leds.get_mut(index) else {
            return false;
        };
        if on {
            led.set_high();
        } else {
            led.set_low();
        }
        true
    }

    fn toggle_led(&mut self, index: usize) -> bool {
        let Some(led) = self.leds.get_mut(index) else {
            return false;
        };
        led.toggle();
        true
    }

    fn led_states(&self) -> [bool; 3] {
        [
            self.leds[0].is_set_high(),
            self.leds[1].is_set_high(),
            self.leds[2].is_set_high(),
        ]
    }

    fn restore_led_states(&mut self, states: [bool; 3]) {
        for (index, on) in states.into_iter().enumerate() {
            let _ = self.set_led(index, on);
        }
    }

    fn set_all_leds(&mut self, on: bool) {
        for index in 0..self.leds.len() {
            let _ = self.set_led(index, on);
        }
    }

    fn toggle_all_leds(&mut self) {
        for index in 0..self.leds.len() {
            let _ = self.toggle_led(index);
        }
    }
}

#[embassy_executor::task]
async fn outer_net_task(mut runner: embassy_net::Runner<'static, OuterDevice>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn inner_net_task(mut runner: embassy_net::Runner<'static, InnerDevice>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn provision_dhcp_task(stack: Stack<'static>) {
    if microtun_provisioning::dhcp::run(stack).await.is_err() {
        warn!("provisioning-mode DHCP server stopped unexpectedly");
    }
}

#[embassy_executor::task]
async fn provision_mdns_task(stack: Stack<'static>, identity: DeviceIdentity) {
    if microtun_net_util::mdns::run(stack, identity, DEVICE_MODEL)
        .await
        .is_err()
    {
        warn!("provisioning-mode mDNS responder stopped unexpectedly");
    }
}

#[embassy_executor::task]
async fn tunnel_task(runner: TunnelRunner<'static, HardwareRng>, outer_stack: Stack<'static>) -> ! {
    // Held in statics rather than on this task's stack. At OUTER_SIZE (1500)
    // times OUTER_UDP_PACKETS this is roughly 12 KiB, which is large enough
    // that burying it in a task stack makes the executor's stack requirement
    // invisible at the call site and turns any future increase into a stack
    // overflow rather than a link error. In a static it shows up in the map
    // alongside the rest of the budget.
    static RX_META: StaticCell<[PacketMetadata; OUTER_UDP_PACKETS]> = StaticCell::new();
    static TX_META: StaticCell<[PacketMetadata; OUTER_UDP_PACKETS]> = StaticCell::new();
    static RX: StaticCell<[u8; microtun_embassy::OUTER_SIZE * OUTER_UDP_PACKETS]> =
        StaticCell::new();
    static TX: StaticCell<[u8; microtun_embassy::OUTER_SIZE * OUTER_UDP_PACKETS]> =
        StaticCell::new();

    let rx_meta = RX_META.init([PacketMetadata::EMPTY; OUTER_UDP_PACKETS]);
    let tx_meta = TX_META.init([PacketMetadata::EMPTY; OUTER_UDP_PACKETS]);
    let rx = RX.init([0u8; microtun_embassy::OUTER_SIZE * OUTER_UDP_PACKETS]);
    let tx = TX.init([0u8; microtun_embassy::OUTER_SIZE * OUTER_UDP_PACKETS]);

    common_tunnel::run(runner, outer_stack, rx_meta, rx, tx_meta, tx).await
}

#[embassy_executor::task]
async fn peers_resolver_task(
    inner_stack: Stack<'static>,
    local_public_key: [u8; 32],
    tracker_tunnel_addr: IpAddr,
    websocket_seed: [u8; 32],
) -> ! {
    common_tunnel::run_peer_resolver(
        inner_stack,
        local_public_key,
        tracker_tunnel_addr,
        websocket_seed,
    )
    .await
}

enum TelnetSessionExit {
    Close,
    Provision,
    ProvisionClear,
    FirmwareUpdate,
}

const TELNET_BANNER: &str = "microtun NUCLEO-H753ZI\r\ntype 'help' for commands";
const PROVISIONING_TELNET_BANNER: &str =
    "microtun NUCLEO-H753ZI provisioning mode\r\ntype 'help' for commands";

trait TelnetShell {
    fn reset_telnet_requests(&mut self);
    fn take_telnet_request(&mut self) -> Option<TelnetSessionExit>;
}

async fn telnet_session<S>(
    socket: &mut TcpSocket<'_>,
    shell: &mut S,
    banner: &'static str,
) -> Result<TelnetSessionExit, CliError>
where
    S: TelnetShell,
    for<'a> <CommandParser as ParserFamily>::Parsed<'a>: Dispatch<S>,
{
    shell.reset_telnet_requests();
    let result =
        Session::<_, 160, 4, 256>::new(socket, CliConfig::new(TELNET_PROMPT).banner(banner))
            .serve::<CommandParser, _>(shell)
            .await;

    if let Some(request) = shell.take_telnet_request() {
        return Ok(request);
    }

    match result {
        Ok(()) | Err(CliError::Disconnected) => Ok(TelnetSessionExit::Close),
        Err(error) => Err(error),
    }
}

#[embassy_executor::task]
async fn telnet_task(mut shell: Shell, flash: &'static SharedFlash) -> ! {
    let mut rx = [0u8; TELNET_TCP_BUFFER];
    let mut tx = [0u8; TELNET_TCP_BUFFER];
    let record = PROVISION_WRITE_BUFFER.init([0u8; RECORD_SIZE]);
    let config = PROVISION_CONFIG_BUFFER.init([0u8; MAX_INI_LEN]);

    loop {
        let mut socket = TcpSocket::new(shell.inner_stack, &mut rx, &mut tx);
        // The shell may sit idle indefinitely, so use TCP-level liveness rather
        // than an application idle timeout: a healthy quiet client stays
        // connected while a vanished/reset client is eventually reclaimed.
        socket.set_keep_alive(Some(TCP_KEEP_ALIVE));
        socket.set_timeout(Some(TCP_IDLE_TIMEOUT));
        info!("telnet shell listening on inner port {}", TELNET_PORT);

        if let Err(error) = socket.accept(TELNET_PORT).await {
            warn!("telnet accept failed: {:?}", error);
            continue;
        }

        info!("telnet client connected through microtun");
        loop {
            match telnet_session(&mut socket, &mut shell, TELNET_BANNER).await {
                Ok(TelnetSessionExit::Close) => break,
                Ok(TelnetSessionExit::Provision) => {
                    match receive_ymodem_buffer(&mut socket, &mut config[..]).await {
                        Ok(config_len) => {
                            let result = {
                                let mut flash = flash.lock().await;
                                let mut store = NucleoConfigStore {
                                    flash: &mut flash,
                                    record: &mut *record,
                                };
                                store.store(&config[..config_len])
                            };

                            match result {
                                Ok(()) => {
                                    let mut message = heapless::String::<96>::new();
                                    let _ = write!(message, "\r\n{PROVISION_STORED}\r\n");
                                    let _ =
                                        telnet_write_data(&mut socket, message.as_bytes()).await;
                                    info!("replacement provisioning committed; rebooting");
                                    Timer::after_millis(100).await;
                                    cortex_m::peripheral::SCB::sys_reset();
                                }
                                Err(error) => {
                                    let mut message = heapless::String::<160>::new();
                                    let _ = write!(
                                        message,
                                        "\r\nprovisioning failed: {}\r\nreturning to shell\r\n",
                                        provisioning_store_error_text(error)
                                    );
                                    if telnet_write_data(&mut socket, message.as_bytes())
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                    warn!("replacement provisioning store failed: {:?}", error);
                                }
                            }
                        }
                        Err(error) => {
                            let mut message = heapless::String::<160>::new();
                            let _ = write!(
                                message,
                                "\r\nprovisioning transfer failed: {}\r\nreturning to shell\r\n",
                                transfer_error_text(error)
                            );
                            if telnet_write_data(&mut socket, message.as_bytes())
                                .await
                                .is_err()
                            {
                                break;
                            }
                            warn!(
                                "replacement provisioning YMODEM transfer failed: {:?}",
                                error
                            );
                        }
                    }
                }
                Ok(TelnetSessionExit::ProvisionClear) => {
                    let result = {
                        let mut flash = flash.lock().await;
                        let mut store = NucleoConfigStore {
                            flash: &mut flash,
                            record: &mut *record,
                        };
                        store.erase()
                    };

                    match result {
                        Ok(()) => {
                            let _ = telnet_write_data(
                                &mut socket,
                                b"\r\nconfiguration cleared; rebooting\r\n",
                            )
                            .await;
                            info!("provisioning configuration cleared; rebooting");
                            Timer::after_millis(100).await;
                            cortex_m::peripheral::SCB::sys_reset();
                        }
                        Err(error) => {
                            let mut message = heapless::String::<160>::new();
                            let _ = write!(
                                message,
                                "\r\nfailed to clear configuration: {}\r\nreturning to shell\r\n",
                                provisioning_store_error_text(error)
                            );
                            if telnet_write_data(&mut socket, message.as_bytes())
                                .await
                                .is_err()
                            {
                                break;
                            }
                            warn!("provisioning erase failed: {:?}", error);
                        }
                    }
                }
                Ok(TelnetSessionExit::FirmwareUpdate) => {
                    let update = {
                        let mut flash = flash.lock().await;
                        receive_firmware_update(&mut socket, &mut flash).await
                    };

                    match update {
                        Ok((verified, slot)) => {
                            let version = verified.header.version;
                            let mut message = heapless::String::<224>::new();
                            let _ = write!(
                                message,
                                "\r\nfirmware accepted\r\nversion: {}.{}.{}+{}\r\nslot: {}\r\nrebooting\r\n",
                                version.major, version.minor, version.revision, version.build, slot,
                            );
                            let _ = telnet_write_data(&mut socket, message.as_bytes()).await;
                            info!(
                                "firmware update verified and activated: {}.{}.{}+{} -> {}",
                                version.major, version.minor, version.revision, version.build, slot
                            );
                            Timer::after_millis(100).await;
                            cortex_m::peripheral::SCB::sys_reset();
                        }
                        Err(error) => {
                            log_firmware_update_error(&error);
                            let mut message = heapless::String::<160>::new();
                            let _ = write!(
                                message,
                                "\r\nfirmware update failed: {}\r\nreturning to shell\r\n",
                                firmware_update_error_text(&error)
                            );
                            if telnet_write_data(&mut socket, message.as_bytes())
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
                Err(_error) => {
                    warn!("telnet session ended with an error");
                    break;
                }
            }
        }

        socket.close();

        if let Err(error) = socket.flush().await {
            warn!("telnet socket close failed: {:?}", error);
        }
    }
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
    let mut flash = Flash::new_blocking(p.FLASH);
    let mut firmware_status = match prepare_firmware_boot(&mut flash) {
        Ok(status) => status,
        Err(error) => {
            log_firmware_update_error(&error);
            cortex_m::peripheral::SCB::sys_reset();
        }
    };
    if firmware_status.trial {
        info!("Embassy Boot trial image is pending verification");
    } else if firmware_status.state == "recovered" {
        warn!("Embassy Boot restored the previously confirmed firmware image");
    }
    let provision = load_provisioning(&mut flash);

    let identity = stm32_device_identity();
    let mut rng = Rng::new(p.RNG, Irqs);

    let outer_seed = rng.next_u64();
    let inner_seed = rng.next_u64();
    let mut websocket_seed = [0u8; 32];
    rng.fill_bytes(&mut websocket_seed);
    let mac = identity.mac();

    static ETH_PACKETS: StaticCell<PacketQueue<4, 4>> = StaticCell::new();
    let sma = Sma::new(
        p.ETH_SMA, p.PA2, // RMII MDIO
        p.PC1, // RMII MDC
    );
    let ethernet = Ethernet::new_with_phy(
        ETH_PACKETS.init(PacketQueue::new()),
        p.ETH,
        Irqs,
        p.PA1,  // RMII REF_CLK (50 MHz from LAN8742A)
        p.PA7,  // RMII CRS_DV
        p.PC4,  // RMII RXD0
        p.PC5,  // RMII RXD1
        p.PG13, // RMII TXD0
        p.PB13, // RMII TXD1
        p.PG11, // RMII TX_EN
        mac,
        Lan8742Phy::new(sma),
    );

    // Start Ethernet as a DHCP client in both modes. A configured board simply
    // keeps its operational lease. An unprovisioned board uses this first lease
    // attempt only as a conservative probe for an already-managed LAN; if no
    // server answers within the provisioning-mode timeout, it switches to the
    // fixed provisioning subnet and starts its own tiny DHCP server.
    let mut dhcp_config = embassy_net::DhcpConfig::default();
    dhcp_config.hostname = Some(device_hostname(&identity));
    let outer_config = embassy_net::Config::dhcpv4(dhcp_config);

    static OUTER_RESOURCES: StaticCell<StackResources<7>> = StaticCell::new();
    let (outer_stack, outer_runner) = embassy_net::new(
        ethernet,
        outer_config,
        OUTER_RESOURCES.init(StackResources::new()),
        outer_seed,
    );
    spawner.spawn(outer_net_task(outer_runner).unwrap());
    spawner.spawn(watchdog_task().unwrap());

    // The main Telnet shell is used in both operational and provisioning mode,
    // so keep the same board I/O surface available before the tunnel exists.
    let board_io = NucleoBoardIo {
        leds: [
            Output::new(p.PB0, Level::Low, Speed::Low),
            Output::new(p.PE1, Level::Low, Speed::Low),
            Output::new(p.PB14, Level::Low, Speed::Low),
        ],
    };
    let user_button = Input::new(p.PC13, Pull::Down);

    let (provision, board_io, user_button) = match provision {
        Ok(provision) => (provision, board_io, user_button),
        Err(_) => {
            if firmware_status.trial {
                warn!("trial OTA image could not load provisioning; resetting for rollback");
                cortex_m::peripheral::SCB::sys_reset();
            }
            warn!("device is not provisioned or the flash config is invalid");
            outer_stack.wait_link_up().await;

            info!("provisioning mode: probing for an existing DHCP server");
            if with_timeout(PROVISION_DHCP_PROBE_TIMEOUT, outer_stack.wait_config_up())
                .await
                .is_ok()
            {
                if let Some(config) = outer_stack.config_v4() {
                    info!(
                        "provisioning mode: existing DHCP server detected; lease is {}",
                        config.address
                    );
                }
                info!(
                    "provisioning mode: the main Telnet CLI can discover this DHCP lease via mDNS"
                );
            } else {
                info!(
                    "provisioning mode: no DHCP lease after {}s; using isolated fallback subnet",
                    PROVISION_DHCP_PROBE_SECONDS
                );
                outer_stack.set_config_v4(ConfigV4::Static(provision_static_config()));
                spawner.spawn(provision_dhcp_task(outer_stack).unwrap());
                info!(
                    "provisioning mode: DHCP server will assign {}.{}.{}.{}-{}.{}.{}.{}/{}",
                    PROVISION_DHCP_RANGE_START[0],
                    PROVISION_DHCP_RANGE_START[1],
                    PROVISION_DHCP_RANGE_START[2],
                    PROVISION_DHCP_RANGE_START[3],
                    PROVISION_DHCP_RANGE_END[0],
                    PROVISION_DHCP_RANGE_END[1],
                    PROVISION_DHCP_RANGE_END[2],
                    PROVISION_DHCP_RANGE_END[3],
                    PROVISION_IPV4_PREFIX_LEN
                );
            }

            spawner.spawn(provision_mdns_task(outer_stack, identity).unwrap());
            info!(
                "provisioning mode: advertising {} over mDNS/DNS-SD",
                microtun_provisioning::PROVISION_MDNS_SERVICE
            );
            provisioning_mode(
                outer_stack,
                &mut flash,
                identity,
                mac,
                reset_reason,
                temperature_sensor,
                board_io,
                user_button,
                firmware_status,
            )
            .await
        }
    };
    static SHARED_FLASH: StaticCell<SharedFlash> = StaticCell::new();
    let flash = SHARED_FLASH.init(Mutex::new(flash));

    info!("waiting for wired Ethernet DHCP");
    outer_stack.wait_config_up().await;
    info!("wired Ethernet DHCP lease acquired");

    info!(
        "loaded provisioning for tunnel {}",
        provision.config.tunnel.tunnel_address.as_str()
    );
    let config = provision.config;
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
    static INNER_RESOURCES: StaticCell<StackResources<5>> = StaticCell::new();
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
        info!(
            "trial OTA core services are up; waiting for the inner tunnel link and then 30s before confirmation"
        );
        // tunnel.run() raises the virtual interface link only after the long-running
        // tunnel task is actually running. Until mark_booted() below, every reset
        // causes Embassy Boot to restore the previously confirmed ACTIVE image.
        if with_timeout(OTA_TRIAL_LINK_TIMEOUT, inner_stack.wait_link_up())
            .await
            .is_err()
        {
            warn!(
                "trial OTA image did not reach the inner tunnel link within {}s; resetting for rollback",
                OTA_TRIAL_LINK_TIMEOUT.as_secs()
            );
            cortex_m::peripheral::SCB::sys_reset();
        }
        Timer::after(OTA_TRIAL_HEALTH_WINDOW).await;
        let mut flash_guard = flash.lock().await;
        firmware_status = match confirm_firmware_boot(&mut flash_guard) {
            Ok(status) => {
                info!("trial OTA image confirmed; automatic rollback disabled");
                status
            }
            Err(error) => {
                log_firmware_update_error(&error);
                drop(flash_guard);
                cortex_m::peripheral::SCB::sys_reset();
            }
        };
    }

    spawner.spawn(
        telnet_task(
            Shell {
                tunnel_status,
                rtc_time,
                outer_stack,
                inner_stack,
                mac,
                identity,
                reset_reason,
                temperature_sensor,
                board_io,
                button: user_button,
                firmware_status,
                provision_requested: false,
                provision_clear_requested: false,
                firmware_update_requested: false,
            },
            flash,
        )
        .unwrap(),
    );

    core::future::pending().await
}

static PROVISION_RECORD_BUFFER: StaticCell<[u8; RECORD_SIZE]> = StaticCell::new();
static PROVISION_WRITE_BUFFER: StaticCell<[u8; RECORD_SIZE]> = StaticCell::new();
static PROVISION_CONFIG_BUFFER: StaticCell<[u8; MAX_INI_LEN]> = StaticCell::new();

fn load_provisioning(
    flash: &mut Flash<'_, Blocking>,
) -> Result<ProvisionRecord, microtun_provisioning::RecordError> {
    let record = PROVISION_RECORD_BUFFER.init([0u8; RECORD_SIZE]);
    if let Err(error) = flash.blocking_read(provision_offset(), record) {
        panic!("failed to read provisioning record: {:?}", error);
    }

    decode_record(record)
}

fn stm32_device_identity() -> DeviceIdentity {
    let uid = embassy_stm32::uid::uid();
    DeviceIdentity::from_unique_bytes(&uid).expect("STM32 UID fits provisioning identity")
}

struct NucleoConfigStore<'a, 'd> {
    flash: &'a mut Flash<'d, Blocking>,
    record: &'a mut [u8; RECORD_SIZE],
}

impl ConfigStore for NucleoConfigStore<'_, '_> {
    fn erase(&mut self) -> Result<(), ConfigStoreError> {
        let start = provision_offset();
        self.flash
            .blocking_erase(start, start + PROVISION_SECTOR_SIZE)
            .map_err(|_| ConfigStoreError::Storage)
    }

    fn store(&mut self, config: &[u8]) -> Result<(), ConfigStoreError> {
        // Encode and validate before erasing the single global provisioning sector.
        encode_record(config, self.record).map_err(|_| ConfigStoreError::InvalidConfig)?;

        self.erase()?;
        let offset = provision_offset();
        self.flash
            .blocking_write(offset, self.record)
            .map_err(|_| ConfigStoreError::Storage)?;

        // Verify bytes from flash, including record header/CRC, INI parsing,
        // and semantic config validation.
        self.record.fill(0);
        self.flash
            .blocking_read(offset, self.record)
            .map_err(|_| ConfigStoreError::Storage)?;
        decode_record(self.record).map_err(|_| ConfigStoreError::Verify)?;
        Ok(())
    }
}

fn provision_static_config() -> StaticConfigV4 {
    StaticConfigV4 {
        address: Ipv4Cidr::new(
            Ipv4Address::new(
                PROVISION_DEVICE_IPV4[0],
                PROVISION_DEVICE_IPV4[1],
                PROVISION_DEVICE_IPV4[2],
                PROVISION_DEVICE_IPV4[3],
            ),
            PROVISION_IPV4_PREFIX_LEN,
        ),
        gateway: None,
        dns_servers: Default::default(),
    }
}

struct ProvisioningShell {
    stack: Stack<'static>,
    mac: [u8; 6],
    identity: DeviceIdentity,
    reset_reason: &'static str,
    temperature_sensor: TemperatureSensor,
    board_io: NucleoBoardIo,
    button: Input<'static>,
    firmware_status: FirmwareStatus,
    provision_requested: bool,
    provision_clear_requested: bool,
    firmware_update_requested: bool,
}

impl TelnetShell for ProvisioningShell {
    fn reset_telnet_requests(&mut self) {
        self.provision_requested = false;
        self.provision_clear_requested = false;
        self.firmware_update_requested = false;
    }

    fn take_telnet_request(&mut self) -> Option<TelnetSessionExit> {
        if self.provision_requested {
            self.provision_requested = false;
            Some(TelnetSessionExit::Provision)
        } else if self.provision_clear_requested {
            self.provision_clear_requested = false;
            Some(TelnetSessionExit::ProvisionClear)
        } else if self.firmware_update_requested {
            self.firmware_update_requested = false;
            Some(TelnetSessionExit::FirmwareUpdate)
        } else {
            None
        }
    }
}

impl Dispatch<ProvisioningShell> for Command {
    async fn dispatch<W: AsyncWrite<Error = IoError> + ?Sized>(
        self,
        shell: &mut ProvisioningShell,
        out: &mut W,
    ) -> Result<(), CliError> {
        match self {
            Command::Sys { field: None } => {
                SYS_TABLE.field(out, "mode", "provisioning").await?;
                SYS_TABLE.field(out, "provisioned", "false").await?;
                SYS_TABLE.field(out, "board", DEVICE_MODEL).await?;
                let device_id = shell.identity.device_id();
                SYS_TABLE.field(out, "id", device_id.as_str()).await?;
                SYS_TABLE.field(out, "version", FIRMWARE_VERSION).await?;
                SYS_TABLE
                    .field(out, "reset-reason", shell.reset_reason)
                    .await?;
                write_temperature(out, &mut shell.temperature_sensor, Some(SYS_TABLE)).await?;
                SYS_TABLE
                    .field_fmt(
                        out,
                        "uptime",
                        format_args!("{}ms", EmbassyInstant::now().as_millis()),
                    )
                    .await?;
                cli_time_field(out, SYS_TABLE, "time", None).await?;
                write_memory(out, Some(SYS_TABLE)).await?;
            }
            Command::Sys {
                field: Some(SysField::Mode),
            } => cli_println(out, "provisioning").await?,
            Command::Sys {
                field: Some(SysField::Provisioned),
            } => cli_println(out, "false").await?,
            Command::Sys {
                field: Some(SysField::Board),
            } => cli_println(out, DEVICE_MODEL).await?,
            Command::Sys {
                field: Some(SysField::Version),
            } => write_version(out).await?,
            Command::Sys {
                field: Some(SysField::Id),
            } => {
                let device_id = shell.identity.device_id();
                cli_println(out, device_id.as_str()).await?;
            }
            Command::Sys {
                field: Some(SysField::ResetReason),
            } => cli_println(out, shell.reset_reason).await?,
            Command::Sys {
                field: Some(SysField::Temp),
            } => {
                write_temperature(out, &mut shell.temperature_sensor, None).await?;
            }
            Command::Sys {
                field: Some(SysField::Uptime),
            } => {
                cli_line(out, format_args!("{}ms", EmbassyInstant::now().as_millis())).await?;
            }
            Command::Sys {
                field: Some(SysField::Time),
            } => cli_time(out, None, None).await?,
            Command::Sys {
                field: Some(SysField::Memory),
            } => write_memory(out, None).await?,

            Command::Net { field: None } => {
                cli_write_net_base(out, NET_TABLE, shell.stack, shell.mac).await?;
                let phy = phy_link_snapshot();
                match (phy.speed_name(), phy.duplex_name()) {
                    (Some(speed), Some(duplex)) => {
                        NET_TABLE
                            .field_fmt(
                                out,
                                "phy",
                                format_args!("{} {} autoneg={}", speed, duplex, phy.autoneg_name()),
                            )
                            .await?;
                    }
                    _ => {
                        NET_TABLE
                            .field_fmt(
                                out,
                                "phy",
                                format_args!("n/a autoneg={}", phy.autoneg_name()),
                            )
                            .await?;
                    }
                }
            }
            Command::Net {
                field: Some(NetField::Link),
            } => cli_write_link_status(out, shell.stack).await?,
            Command::Net {
                field: Some(NetField::Ip),
            } => cli_write_ip_status(out, shell.stack).await?,
            Command::Net {
                field: Some(NetField::Mac),
            } => cli_write_mac_status(out, shell.mac).await?,
            Command::Net {
                field: Some(NetField::Phy),
            } => {
                let status = phy_link_snapshot();
                match status.speed_name() {
                    Some(speed) => PHY_TABLE.field(out, "speed", speed).await?,
                    None => PHY_TABLE.field(out, "speed", "n/a").await?,
                }
                match status.duplex_name() {
                    Some(duplex) => PHY_TABLE.field(out, "duplex", duplex).await?,
                    None => PHY_TABLE.field(out, "duplex", "n/a").await?,
                }
                PHY_TABLE
                    .field(out, "autoneg", status.autoneg_name())
                    .await?;
            }

            Command::Ping {
                iface: PingIface::Net,
                addr,
                count,
            } => {
                cli_ping(out, PingIface::Net.name(), shell.stack, addr, count).await?;
            }
            Command::Ping {
                iface: PingIface::Tunnel,
                ..
            }
            | Command::Tunnel { .. } => {
                cli_println(
                    out,
                    "unavailable: tunnel is not configured in provisioning mode",
                )
                .await?;
            }

            Command::Provision { action: None } => {
                cli_println(out, PROVISION_YMODEM_READY).await?;
                cli_println(
                    out,
                    "send one INI file with YMODEM-1K/CRC now; Ctrl-X cancels",
                )
                .await?;
                out.flush().await?;
                shell.provision_requested = true;
                return Err(CliError::Disconnected);
            }
            Command::Provision {
                action: Some(ProvisionAction::Clear),
            } => {
                cli_println(out, "clearing provisioning configuration").await?;
                out.flush().await?;
                shell.provision_clear_requested = true;
                return Err(CliError::Disconnected);
            }

            Command::Io {
                kind: None,
                target: None,
                action: None,
            } => {
                IO_TABLE.field(out, "led", &3usize).await?;
                IO_TABLE.field(out, "button", &1usize).await?;
            }
            Command::Io {
                kind: Some(BoardIoKind::Led),
                target: None | Some(BoardIoTarget::All),
                action: None,
            } => {
                for (index, state) in shell.board_io.led_states().into_iter().enumerate() {
                    IO_INDEX_TABLE
                        .field(
                            out,
                            IO_INDEX_LABELS[index],
                            if state { "on" } else { "off" },
                        )
                        .await?;
                }
            }
            Command::Io {
                kind: Some(BoardIoKind::Led),
                target:
                    Some(target @ (BoardIoTarget::One | BoardIoTarget::Two | BoardIoTarget::Three)),
                action: None,
            } => {
                let index = match target {
                    BoardIoTarget::One => 0,
                    BoardIoTarget::Two => 1,
                    BoardIoTarget::Three => 2,
                    BoardIoTarget::All => unreachable!(),
                };
                cli_println(
                    out,
                    if shell.board_io.led_states()[index] {
                        "on"
                    } else {
                        "off"
                    },
                )
                .await?;
            }
            Command::Io {
                kind: Some(BoardIoKind::Led),
                target: Some(target),
                action: Some(action),
            } => set_led_action(out, &mut shell.board_io, target, action).await?,
            Command::Io {
                kind: Some(BoardIoKind::Button),
                target: None,
                action: None,
            } => {
                cli_println(
                    out,
                    if shell.button.is_high() {
                        "pressed"
                    } else {
                        "released"
                    },
                )
                .await?;
            }
            Command::Io { .. } => {
                cli_println(
                    out,
                    "error: expected io [led [1|2|3|all] [on|off|toggle] | button]",
                )
                .await?;
            }

            Command::Fw {
                action: None | Some(FirmwareAction::Show),
            } => {
                FW_TABLE.field(out, "version", FIRMWARE_VERSION).await?;
                FW_TABLE
                    .field(out, "slot", shell.firmware_status.slot)
                    .await?;
                FW_TABLE
                    .field(out, "state", shell.firmware_status.state)
                    .await?;
            }
            Command::Fw {
                action: Some(FirmwareAction::Update),
            } => {
                cli_println(out, "MICROTUN-YMODEM-1K READY").await?;
                cli_println(out, "send signed MCUboot image now; Ctrl-X cancels").await?;
                out.flush().await?;
                shell.firmware_update_requested = true;
                return Err(CliError::Disconnected);
            }
            Command::Identify => {
                cli_line(out, format_args!("identifying: {IDENTIFY_SECONDS} seconds")).await?;
                out.flush().await?;
                identify_provisioning_board(&mut shell.board_io).await;
            }
            Command::Reboot => {
                cli_println(out, "rebooting").await?;
                out.flush().await?;
                Timer::after_millis(100).await;
                cortex_m::peripheral::SCB::sys_reset();
            }
            Command::Quit => {
                cli_println(out, "bye").await?;
                out.flush().await?;
                return Err(CliError::Disconnected);
            }
        }
        Ok(())
    }
}

fn provisioning_store_error_text(error: ConfigStoreError) -> &'static str {
    match error {
        ConfigStoreError::InvalidConfig => "invalid config",
        ConfigStoreError::Storage => "flash operation failed",
        ConfigStoreError::Verify => "flash verification failed",
    }
}

#[allow(clippy::too_many_arguments)]
async fn provisioning_mode(
    stack: Stack<'static>,
    flash: &mut Flash<'_, Blocking>,
    identity: DeviceIdentity,
    mac: [u8; 6],
    reset_reason: &'static str,
    temperature_sensor: TemperatureSensor,
    board_io: NucleoBoardIo,
    button: Input<'static>,
    firmware_status: FirmwareStatus,
) -> ! {
    let mut rx = [0u8; TELNET_TCP_BUFFER];
    let mut tx = [0u8; TELNET_TCP_BUFFER];
    let record = PROVISION_WRITE_BUFFER.init([0u8; RECORD_SIZE]);
    let config = PROVISION_CONFIG_BUFFER.init([0u8; MAX_INI_LEN]);
    let device_id = identity.device_id();
    let mut shell = ProvisioningShell {
        stack,
        mac,
        identity,
        reset_reason,
        temperature_sensor,
        board_io,
        button,
        firmware_status,
        provision_requested: false,
        provision_clear_requested: false,
        firmware_update_requested: false,
    };

    if let Some(config_v4) = stack.config_v4() {
        info!(
            "provisioning mode: device={} main Telnet CLI listening on {} port {}",
            device_id.as_str(),
            config_v4.address,
            PROVISION_PORT
        );
    }

    loop {
        let mut socket = TcpSocket::new(stack, &mut rx, &mut tx);
        socket.set_keep_alive(Some(TCP_KEEP_ALIVE));
        socket.set_timeout(Some(TCP_IDLE_TIMEOUT));

        if socket.accept(PROVISION_PORT).await.is_err() {
            warn!("provisioning Telnet accept failed");
            continue;
        }
        info!("provisioning-mode Telnet client connected");
        loop {
            let request =
                match telnet_session(&mut socket, &mut shell, PROVISIONING_TELNET_BANNER).await {
                    Ok(request) => request,
                    Err(_error) => {
                        warn!("provisioning Telnet session ended with an error");
                        break;
                    }
                };

            match request {
                TelnetSessionExit::Provision => {
                    match receive_ymodem_buffer(&mut socket, &mut config[..]).await {
                        Ok(config_len) => {
                            let result = {
                                let mut store = NucleoConfigStore {
                                    flash: &mut *flash,
                                    record: &mut *record,
                                };
                                store.store(&config[..config_len])
                            };

                            match result {
                                Ok(()) => {
                                    let mut message = heapless::String::<96>::new();
                                    let _ = write!(message, "\r\n{PROVISION_STORED}\r\n");
                                    let _ =
                                        telnet_write_data(&mut socket, message.as_bytes()).await;
                                    info!("provisioning committed; rebooting into normal mode");
                                    Timer::after_millis(100).await;
                                    cortex_m::peripheral::SCB::sys_reset();
                                }
                                Err(error) => {
                                    let mut message = heapless::String::<128>::new();
                                    let _ = write!(
                                        message,
                                        "\r\nprovisioning failed: {}\r\nreturning to shell\r\n",
                                        provisioning_store_error_text(error)
                                    );
                                    let _ =
                                        telnet_write_data(&mut socket, message.as_bytes()).await;
                                    warn!("provisioning config store failed: {:?}", error);
                                }
                            }
                        }
                        Err(error) => {
                            let mut message = heapless::String::<128>::new();
                            let _ = write!(
                                message,
                                "\r\nprovisioning transfer failed: {}\r\nreturning to shell\r\n",
                                transfer_error_text(error)
                            );
                            let _ = telnet_write_data(&mut socket, message.as_bytes()).await;
                            warn!("provisioning YMODEM transfer failed");
                        }
                    }
                }
                TelnetSessionExit::ProvisionClear => {
                    let result = {
                        let mut store = NucleoConfigStore {
                            flash: &mut *flash,
                            record: &mut *record,
                        };
                        store.erase()
                    };

                    match result {
                        Ok(()) => {
                            let _ = telnet_write_data(
                                &mut socket,
                                b"\r\nconfiguration cleared; rebooting\r\n",
                            )
                            .await;
                            info!("provisioning configuration cleared; rebooting");
                            Timer::after_millis(100).await;
                            cortex_m::peripheral::SCB::sys_reset();
                        }
                        Err(error) => {
                            let mut message = heapless::String::<128>::new();
                            let _ = write!(
                                message,
                                "\r\nfailed to clear configuration: {}\r\nreturning to shell\r\n",
                                provisioning_store_error_text(error)
                            );
                            let _ = telnet_write_data(&mut socket, message.as_bytes()).await;
                            warn!("provisioning erase failed: {:?}", error);
                        }
                    }
                }
                TelnetSessionExit::FirmwareUpdate => {
                    match receive_firmware_update(&mut socket, flash).await {
                        Ok((verified, slot)) => {
                            let version = verified.header.version;
                            let mut message = heapless::String::<224>::new();
                            let _ = write!(
                                message,
                                "\r\nfirmware accepted\r\nversion: {}.{}.{}+{}\r\nslot: {}\r\nrebooting\r\n",
                                version.major, version.minor, version.revision, version.build, slot,
                            );
                            let _ = telnet_write_data(&mut socket, message.as_bytes()).await;
                            Timer::after_millis(100).await;
                            cortex_m::peripheral::SCB::sys_reset();
                        }
                        Err(error) => {
                            log_firmware_update_error(&error);
                            let mut message = heapless::String::<160>::new();
                            let _ = write!(
                                message,
                                "\r\nfirmware update failed: {}\r\nreturning to shell\r\n",
                                firmware_update_error_text(&error)
                            );
                            let _ = telnet_write_data(&mut socket, message.as_bytes()).await;
                        }
                    }
                }
                TelnetSessionExit::Close => break,
            }
        }

        socket.close();
        if socket.flush().await.is_err() {
            warn!("provisioning Telnet socket close failed");
        }
    }
}

async fn sync_rtc_from_ntp(
    stack: Stack<'static>,
    rtc: &mut Rtc,
    rtc_time: &RtcTimeProvider,
    host: &str,
    port: u16,
) -> (u64, u32) {
    loop {
        let result = query_ntp_time(stack, host, port).await;
        let (unix_secs, unix_nanos) = ntp_unix_time(&result);
        let Some(datetime) = unix_to_rtc_datetime(unix_secs, unix_nanos) else {
            warn!("SNTP timestamp is outside the STM32 RTC year range");
            Timer::after_secs(2).await;
            continue;
        };

        if let Err(error) = rtc.set_datetime(datetime) {
            warn!("failed to set STM32 RTC from SNTP: {:?}", error);
            Timer::after_secs(2).await;
            continue;
        }

        let (rtc_secs, rtc_nanos) = rtc_unix_time(rtc_time).expect("RTC readable after SNTP sync");
        info!(
            "RTC synchronized from {}: unix={} stratum={} rtt={}us",
            host,
            rtc_secs,
            result.stratum(),
            result.roundtrip()
        );
        return (rtc_secs, rtc_nanos);
    }
}

fn rtc_unix_time(rtc_time: &RtcTimeProvider) -> Option<(u64, u32)> {
    let datetime: chrono::NaiveDateTime = rtc_time.now().ok()?.into();
    let datetime = datetime.and_utc();

    Some((
        u64::try_from(datetime.timestamp()).ok()?,
        datetime.timestamp_subsec_nanos(),
    ))
}

fn unix_to_rtc_datetime(unix_secs: u64, unix_nanos: u32) -> Option<RtcDateTime> {
    let datetime = chrono::DateTime::from_timestamp(i64::try_from(unix_secs).ok()?, unix_nanos)?;

    // STM32's calendar RTC stores a two-digit year relative to 2000.
    if !(2000..=2099).contains(&datetime.year()) {
        return None;
    }

    Some(datetime.naive_utc().into())
}

#[derive(Clone, Copy)]
struct MemoryUsage {
    total: usize,
    static_used: usize,
    stack_used: usize,
    free_now: usize,
}

fn memory_usage() -> MemoryUsage {
    // Report the linker RAM arena selected by embassy-stm32's generated memory.x.
    unsafe extern "C" {
        static _ram_start: u8;
        static _ram_end: u8;
        static _stack_start: u8;
    }

    let ram_start = core::ptr::addr_of!(_ram_start) as usize;
    let ram_end = core::ptr::addr_of!(_ram_end) as usize;
    let stack_start = core::ptr::addr_of!(_stack_start) as usize;
    let static_end = cortex_m_rt::heap_start() as usize;
    let stack_pointer = cortex_m::register::msp::read() as usize;

    MemoryUsage {
        total: ram_end.saturating_sub(ram_start),
        static_used: static_end.saturating_sub(ram_start),
        stack_used: stack_start.saturating_sub(stack_pointer),
        free_now: stack_pointer.saturating_sub(static_end),
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum NetField {
    /// Show whether the Ethernet link is up.
    Link,
    /// Show the configured IP address and gateway.
    Ip,
    /// Show the Ethernet MAC address.
    Mac,
    /// Show Ethernet PHY status.
    Phy,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum BoardIoKind {
    /// Inspect or control the user LEDs.
    Led,
    /// Read the user button state.
    Button,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum BoardIoTarget {
    /// Select LED 1.
    #[value(name = "1")]
    One,
    /// Select LED 2.
    #[value(name = "2")]
    Two,
    /// Select LED 3.
    #[value(name = "3")]
    Three,
    /// Select all user LEDs.
    All,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ProvisionAction {
    /// Erase the persisted provisioning configuration and reboot.
    Clear,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum FirmwareAction {
    /// Show firmware update status.
    Show,
    /// Receive and install a signed MCUboot image using YMODEM-1K/CRC.
    Update,
}

#[derive(Debug, Parser)]
#[command(name = "microtun", about = "microtun NUCLEO-H753ZI console")]
enum Command {
    /// Show system information.
    Sys {
        #[arg(value_enum, value_name = "FIELD")]
        field: Option<SysField>,
    },

    /// Show network status.
    Net {
        #[arg(value_enum, value_name = "FIELD")]
        field: Option<NetField>,
    },

    /// Ping an address.
    Ping {
        /// Interface to use.
        #[arg(value_enum, value_name = "IFACE")]
        iface: PingIface,
        /// IPv4 or IPv6 address to ping.
        #[arg(value_name = "ADDR")]
        addr: IpAddr,
        /// Number of echo requests to send (1-16).
        #[arg(value_name = "COUNT", default_value_t = DEFAULT_PING_COUNT)]
        count: u8,
    },

    /// Show tunnel status.
    Tunnel {
        #[arg(value_enum, value_name = "ACTION")]
        action: Option<TunnelAction>,
    },

    /// Manage the device configuration.
    Provision {
        #[arg(value_enum, value_name = "ACTION")]
        action: Option<ProvisionAction>,
    },

    /// Show firmware status or install an update.
    Fw {
        #[arg(value_enum, value_name = "ACTION")]
        action: Option<FirmwareAction>,
    },

    /// Inspect or control hardware I/O.
    Io {
        /// I/O function.
        #[arg(value_enum, value_name = "KIND")]
        kind: Option<BoardIoKind>,
        /// LED target.
        #[arg(value_enum, value_name = "TARGET")]
        target: Option<BoardIoTarget>,
        /// LED action.
        #[arg(value_enum, value_name = "ACTION")]
        action: Option<IoAction>,
    },

    /// Identify this device by blinking its LED(s).
    Identify,

    /// Reboot the device.
    Reboot,

    /// Close this session.
    Quit,
}

const NET_TABLE: Table = Table::new(&["link", "ip", "mac", "phy"]);
const PHY_TABLE: Table = Table::new(&["speed", "duplex", "autoneg"]);
const IO_TABLE: Table = Table::new(&["led", "button"]);
const IO_INDEX_LABELS: [&str; 3] = ["1", "2", "3"];
const IO_INDEX_TABLE: Table = Table::new(&IO_INDEX_LABELS);
const FW_TABLE: Table = Table::new(&["version", "slot"]);

struct Shell {
    tunnel_status: TunnelStatus<'static>,
    rtc_time: RtcTimeProvider,
    outer_stack: Stack<'static>,
    inner_stack: Stack<'static>,
    mac: [u8; 6],
    identity: DeviceIdentity,
    reset_reason: &'static str,
    temperature_sensor: TemperatureSensor,
    board_io: NucleoBoardIo,
    button: Input<'static>,
    firmware_status: FirmwareStatus,
    provision_requested: bool,
    provision_clear_requested: bool,
    firmware_update_requested: bool,
}

impl TelnetShell for Shell {
    fn reset_telnet_requests(&mut self) {
        self.provision_requested = false;
        self.provision_clear_requested = false;
        self.firmware_update_requested = false;
    }

    fn take_telnet_request(&mut self) -> Option<TelnetSessionExit> {
        if self.provision_requested {
            self.provision_requested = false;
            Some(TelnetSessionExit::Provision)
        } else if self.provision_clear_requested {
            self.provision_clear_requested = false;
            Some(TelnetSessionExit::ProvisionClear)
        } else if self.firmware_update_requested {
            self.firmware_update_requested = false;
            Some(TelnetSessionExit::FirmwareUpdate)
        } else {
            None
        }
    }
}

async fn write_version<W>(out: &mut W) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    cli_field(out, "version", FIRMWARE_VERSION).await
}

async fn write_temperature<W>(
    out: &mut W,
    sensor: &mut TemperatureSensor,
    table: Option<Table>,
) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    let Some(millicelsius) = sensor.read_millicelsius().map(i64::from) else {
        return match table {
            Some(table) => table.field(out, "temp", "unavailable").await,
            None => cli_println(out, "unavailable").await,
        };
    };
    let sign = if millicelsius < 0 { "-" } else { "" };
    let magnitude = millicelsius.abs();
    let whole = magnitude / 1000;
    let tenths = (magnitude % 1000) / 100;
    match table {
        Some(table) => {
            table
                .field_fmt(out, "temp", format_args!("{sign}{whole}.{tenths} C"))
                .await
        }
        None => cli_line(out, format_args!("{sign}{whole}.{tenths} C")).await,
    }
}

async fn write_memory<W>(out: &mut W, table: Option<Table>) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    let memory = memory_usage();
    let used = memory.static_used.saturating_add(memory.stack_used);
    let percent = used
        .saturating_mul(100)
        .checked_div(memory.total)
        .unwrap_or(0);
    match table {
        Some(table) => {
            table
                .field_fmt(
                    out,
                    "memory",
                    format_args!(
                        "{used}B/{}B ({percent}%) free={}B",
                        memory.total, memory.free_now
                    ),
                )
                .await
        }
        None => {
            cli_line(
                out,
                format_args!(
                    "{used}B/{}B ({percent}%) static={}B stack={}B free={}B",
                    memory.total, memory.static_used, memory.stack_used, memory.free_now
                ),
            )
            .await
        }
    }
}

async fn identify_provisioning_board(board_io: &mut NucleoBoardIo) {
    let saved = board_io.led_states();
    for _ in 0..IDENTIFY_SECONDS * 2 {
        board_io.set_all_leds(true);
        Timer::after_millis(250).await;
        board_io.set_all_leds(false);
        Timer::after_millis(250).await;
    }
    board_io.restore_led_states(saved);
}

async fn identify_board(board_io: &mut NucleoBoardIo) {
    let saved = board_io.led_states();
    for _ in 0..3 {
        board_io.set_all_leds(true);
        Timer::after_millis(150).await;
        board_io.set_all_leds(false);
        Timer::after_millis(150).await;
    }
    board_io.restore_led_states(saved);
}

async fn set_led_action<W>(
    out: &mut W,
    board_io: &mut NucleoBoardIo,
    target: BoardIoTarget,
    action: IoAction,
) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    if matches!(target, BoardIoTarget::All) {
        match action {
            IoAction::On => board_io.set_all_leds(true),
            IoAction::Off => board_io.set_all_leds(false),
            IoAction::Toggle => board_io.toggle_all_leds(),
        }
    } else {
        let index = match target {
            BoardIoTarget::One => 0,
            BoardIoTarget::Two => 1,
            BoardIoTarget::Three => 2,
            BoardIoTarget::All => unreachable!(),
        };
        match action {
            IoAction::On => {
                let _ = board_io.set_led(index, true);
            }
            IoAction::Off => {
                let _ = board_io.set_led(index, false);
            }
            IoAction::Toggle => {
                let _ = board_io.toggle_led(index);
            }
        }
    }
    cli_println(out, "ok").await
}

async fn handle_command<W>(shell: &mut Shell, command: Command, out: &mut W) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    match command {
        Command::Sys { field: None } => {
            SYS_TABLE.field(out, "mode", "operational").await?;
            SYS_TABLE.field(out, "provisioned", "true").await?;
            SYS_TABLE.field(out, "board", DEVICE_MODEL).await?;
            let device_id = shell.identity.device_id();
            SYS_TABLE.field(out, "id", device_id.as_str()).await?;
            SYS_TABLE.field(out, "version", FIRMWARE_VERSION).await?;
            SYS_TABLE
                .field(out, "reset-reason", shell.reset_reason)
                .await?;
            write_temperature(out, &mut shell.temperature_sensor, Some(SYS_TABLE)).await?;
            SYS_TABLE
                .field_fmt(
                    out,
                    "uptime",
                    format_args!("{}ms", EmbassyInstant::now().as_millis()),
                )
                .await?;
            cli_time_field(out, SYS_TABLE, "time", rtc_unix_time(&shell.rtc_time)).await?;
            write_memory(out, Some(SYS_TABLE)).await?;
        }
        Command::Sys {
            field: Some(SysField::Mode),
        } => cli_println(out, "operational").await?,
        Command::Sys {
            field: Some(SysField::Provisioned),
        } => cli_println(out, "true").await?,
        Command::Sys {
            field: Some(SysField::Board),
        } => cli_println(out, DEVICE_MODEL).await?,
        Command::Sys {
            field: Some(SysField::Version),
        } => write_version(out).await?,
        Command::Sys {
            field: Some(SysField::Id),
        } => {
            let device_id = shell.identity.device_id();
            cli_println(out, device_id.as_str()).await?;
        }
        Command::Sys {
            field: Some(SysField::ResetReason),
        } => cli_println(out, shell.reset_reason).await?,
        Command::Sys {
            field: Some(SysField::Temp),
        } => write_temperature(out, &mut shell.temperature_sensor, None).await?,
        Command::Sys {
            field: Some(SysField::Uptime),
        } => {
            cli_line(out, format_args!("{}ms", EmbassyInstant::now().as_millis())).await?;
        }
        Command::Sys {
            field: Some(SysField::Time),
        } => {
            cli_time(out, None, rtc_unix_time(&shell.rtc_time)).await?;
        }
        Command::Sys {
            field: Some(SysField::Memory),
        } => write_memory(out, None).await?,
        Command::Net { field: None } => {
            cli_write_net_base(out, NET_TABLE, shell.outer_stack, shell.mac).await?;

            let phy = phy_link_snapshot();
            match (phy.speed_name(), phy.duplex_name()) {
                (Some(speed), Some(duplex)) => {
                    NET_TABLE
                        .field_fmt(
                            out,
                            "phy",
                            format_args!("{} {} autoneg={}", speed, duplex, phy.autoneg_name()),
                        )
                        .await?;
                }
                _ => {
                    NET_TABLE
                        .field_fmt(
                            out,
                            "phy",
                            format_args!("n/a autoneg={}", phy.autoneg_name()),
                        )
                        .await?;
                }
            }
        }
        Command::Net {
            field: Some(NetField::Link),
        } => cli_write_link_status(out, shell.outer_stack).await?,
        Command::Net {
            field: Some(NetField::Ip),
        } => cli_write_ip_status(out, shell.outer_stack).await?,
        Command::Net {
            field: Some(NetField::Mac),
        } => cli_write_mac_status(out, shell.mac).await?,

        Command::Net {
            field: Some(NetField::Phy),
        } => {
            let status = phy_link_snapshot();
            match status.speed_name() {
                Some(speed) => PHY_TABLE.field(out, "speed", speed).await?,
                None => PHY_TABLE.field(out, "speed", "n/a").await?,
            }
            match status.duplex_name() {
                Some(duplex) => PHY_TABLE.field(out, "duplex", duplex).await?,
                None => PHY_TABLE.field(out, "duplex", "n/a").await?,
            }
            PHY_TABLE
                .field(out, "autoneg", status.autoneg_name())
                .await?;
        }

        Command::Ping { iface, addr, count } => {
            let selected_iface = match iface {
                PingIface::Net => shell.outer_stack,
                PingIface::Tunnel => shell.inner_stack,
            };
            cli_ping(out, iface.name(), selected_iface, addr, count).await?;
        }

        Command::Tunnel {
            action: None | Some(TunnelAction::Show),
        } => write_tunnel_status(out, shell.tunnel_status, &shell.inner_stack).await?,
        Command::Tunnel {
            action: Some(TunnelAction::Key),
        } => {
            let snapshot = shell.tunnel_status.snapshot();
            let encoded = encode_key(&snapshot.public_key);
            cli_println(out, encoded.as_str()).await?;
        }

        Command::Provision { action: None } => {
            cli_println(out, PROVISION_YMODEM_READY).await?;
            cli_println(
                out,
                "send one INI file with YMODEM-1K/CRC now; Ctrl-X cancels",
            )
            .await?;
            out.flush().await?;
            shell.provision_requested = true;
            return Err(CliError::Disconnected);
        }
        Command::Provision {
            action: Some(ProvisionAction::Clear),
        } => {
            cli_println(out, "clearing provisioning configuration").await?;
            out.flush().await?;
            shell.provision_clear_requested = true;
            return Err(CliError::Disconnected);
        }

        Command::Io {
            kind: None,
            target: None,
            action: None,
        } => {
            IO_TABLE.field(out, "led", &3usize).await?;
            IO_TABLE.field(out, "button", &1usize).await?;
        }
        Command::Io {
            kind: Some(BoardIoKind::Led),
            target: None | Some(BoardIoTarget::All),
            action: None,
        } => {
            for (index, state) in shell.board_io.led_states().into_iter().enumerate() {
                IO_INDEX_TABLE
                    .field(
                        out,
                        IO_INDEX_LABELS[index],
                        if state { "on" } else { "off" },
                    )
                    .await?;
            }
        }
        Command::Io {
            kind: Some(BoardIoKind::Led),
            target: Some(target @ (BoardIoTarget::One | BoardIoTarget::Two | BoardIoTarget::Three)),
            action: None,
        } => {
            let index = match target {
                BoardIoTarget::One => 0,
                BoardIoTarget::Two => 1,
                BoardIoTarget::Three => 2,
                BoardIoTarget::All => unreachable!(),
            };
            cli_println(
                out,
                if shell.board_io.led_states()[index] {
                    "on"
                } else {
                    "off"
                },
            )
            .await?;
        }
        Command::Io {
            kind: Some(BoardIoKind::Led),
            target: Some(target),
            action: Some(action),
        } => set_led_action(out, &mut shell.board_io, target, action).await?,
        Command::Io {
            kind: Some(BoardIoKind::Button),
            target: None,
            action: None,
        } => {
            cli_println(
                out,
                if shell.button.is_high() {
                    "pressed"
                } else {
                    "released"
                },
            )
            .await?;
        }
        Command::Fw {
            action: None | Some(FirmwareAction::Show),
        } => {
            FW_TABLE.field(out, "version", FIRMWARE_VERSION).await?;
            FW_TABLE
                .field(out, "slot", shell.firmware_status.slot)
                .await?;
            FW_TABLE
                .field(out, "state", shell.firmware_status.state)
                .await?;
        }
        Command::Fw {
            action: Some(FirmwareAction::Update),
        } => {
            cli_println(out, "MICROTUN-YMODEM-1K READY").await?;
            cli_println(out, "send signed MCUboot image now; Ctrl-X cancels").await?;
            out.flush().await?;
            shell.firmware_update_requested = true;
            return Err(CliError::Disconnected);
        }
        Command::Identify => {
            identify_board(&mut shell.board_io).await;
            cli_println(out, "ok").await?;
        }
        Command::Io { .. } => {
            cli_println(
                out,
                "error: expected io [led [1|2|3|all] [on|off|toggle] | button]",
            )
            .await?;
        }

        Command::Reboot => {
            cli_println(out, "rebooting").await?;
            out.flush().await?;
            Timer::after_millis(100).await;
            cortex_m::peripheral::SCB::sys_reset();
        }
        Command::Quit => {
            cli_println(out, "bye").await?;
            out.flush().await?;
            return Err(CliError::Disconnected);
        }
    }

    Ok(())
}

impl Dispatch<Shell> for Command {
    async fn dispatch<W: AsyncWrite<Error = IoError> + ?Sized>(
        self,
        shell: &mut Shell,
        out: &mut W,
    ) -> Result<(), CliError> {
        handle_command(shell, self, out).await
    }
}
