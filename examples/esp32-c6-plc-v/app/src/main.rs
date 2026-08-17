#![no_std]
#![no_main]

extern crate alloc;

mod firmware;

use core::{cell::RefCell, net::IpAddr};

use embassy_executor::Spawner;
use embassy_net::{
    Ipv4Address, Ipv4Cidr, Stack, StackResources, StaticConfigV4, tcp::TcpSocket,
    udp::PacketMetadata,
};
use embassy_sync::{
    blocking_mutex::{Mutex as BlockingMutex, raw::CriticalSectionRawMutex},
    mutex::Mutex as AsyncMutex,
};
use embassy_time::{Duration as EmbassyDuration, Instant as EmbassyInstant, Timer, with_timeout};
use embedded_io_async::Write as AsyncWrite;
use embedded_storage::nor_flash::{NorFlash as _, ReadNorFlash as _};
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
    Config as WifiConfig, ControllerConfig, Interface, WifiController, ap::AccessPointConfig,
    sta::StationConfig,
};
use esp_storage::FlashStorage;
use firmware::{
    FirmwareStatus, confirm_firmware_ota, firmware_update_error_text, log_firmware_update_error,
    ota_slot_name, prepare_firmware_ota, receive_firmware_update, receive_ymodem_buffer,
    telnet_write_data,
};
use log::{info, warn};
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
    PROVISION_DEVICE_IPV4, PROVISION_IPV4_PREFIX_LEN, PROVISION_PORT, PROVISION_STORED,
    PROVISION_YMODEM_READY, ProvisionRecord, RECORD_SIZE, TELNET_PROMPT, decode_record,
    device_hostname, encode_record, provision_ap_ssid,
};
use microtun_telnet_cli::{
    Config as CliConfig, Dispatch, Error as CliError, IoError, Parser, ParserFamily, Session,
    ValueEnum,
};
use rand_core::RngCore as _;
use static_cell::StaticCell;

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

const PROVISION_ADDRESS: u32 = 0x003f_0000;
// The `microtun` partition in `partitions.csv` is exactly one 4 KiB flash
// sector, which is also the portable record size, so the whole partition is
// erased and rewritten as a unit.
const PROVISION_ERASE_END: u32 = PROVISION_ADDRESS + RECORD_SIZE as u32;
const DEVICE_MODEL: &str = "ESP32-C6-PLC-V";

type SharedFlash = AsyncMutex<CriticalSectionRawMutex, FlashStorage<'static>>;

type OuterDevice = Interface;
type InnerDevice = TunnelDevice<'static>;
type HardwareRng = Trng;

/// GPIO adapter for the ICBBUY ESP32-C6-PLC-V evaluation board.
///
/// The board drives relay transistors high and exposes opto-isolated inputs
/// which are pulled high on the MCU side, so an asserted field input reads low.
struct PlcBoardIo {
    led: Output<'static>,
    relays: [Output<'static>; 4],
    inputs: [Input<'static>; 4],
}

impl PlcBoardIo {
    fn led_is_on(&self) -> bool {
        // The RUN LED is wired from 3.3 V into GPIO8, so driving the pin low
        // sinks current and turns the LED on.
        !self.led.is_set_high()
    }

    fn set_led(&mut self, on: bool) {
        if on {
            self.led.set_low();
        } else {
            self.led.set_high();
        }
    }

    fn toggle_led(&mut self) {
        let on = self.led_is_on();
        self.set_led(!on);
    }

    fn relay_is_on(&self, index: usize) -> Option<bool> {
        self.relays.get(index).map(|relay| relay.is_set_high())
    }

    fn set_relay(&mut self, index: usize, on: bool) -> bool {
        let Some(relay) = self.relays.get_mut(index) else {
            return false;
        };
        if on {
            relay.set_high();
        } else {
            relay.set_low();
        }
        true
    }

    fn input_is_active(&self, index: usize) -> Option<bool> {
        self.inputs.get(index).map(|input| input.is_low())
    }
}

#[derive(Clone, Copy)]
struct WifiLinkSnapshot {
    associated: bool,
    bssid: [u8; 6],
    channel: u8,
    rssi_dbm: Option<i32>,
    reconnects: u32,
}

impl WifiLinkSnapshot {
    const fn empty() -> Self {
        Self {
            associated: false,
            bssid: [0; 6],
            channel: 0,
            rssi_dbm: None,
            reconnects: 0,
        }
    }
}

static WIFI_LINK: BlockingMutex<CriticalSectionRawMutex, RefCell<WifiLinkSnapshot>> =
    BlockingMutex::new(RefCell::new(WifiLinkSnapshot::empty()));

fn wifi_link_snapshot() -> WifiLinkSnapshot {
    WIFI_LINK.lock(|status| *status.borrow())
}

fn publish_wifi_link(snapshot: WifiLinkSnapshot) {
    WIFI_LINK.lock(|status| *status.borrow_mut() = snapshot);
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
async fn wifi_connection_task(mut controller: WifiController<'static>) -> ! {
    info!("Wi-Fi connection task started");
    let mut ever_connected = false;
    let mut reconnects = 0u32;

    loop {
        info!("connecting to provisioned Wi-Fi network");
        match controller.connect_async().await {
            Ok(connected) => {
                info!("Wi-Fi station connected: {:?}", connected);
                if ever_connected {
                    reconnects = reconnects.saturating_add(1);
                } else {
                    ever_connected = true;
                }

                let bssid = connected.bssid;
                let channel = connected.channel;
                loop {
                    publish_wifi_link(WifiLinkSnapshot {
                        associated: true,
                        bssid,
                        channel,
                        rssi_dbm: controller.rssi().ok(),
                        reconnects,
                    });

                    // Refresh RSSI every two seconds while still using the
                    // stable disconnect waiter exposed by esp-radio. This keeps
                    // signal strength useful for diagnosing intermittent links.
                    match with_timeout(
                        EmbassyDuration::from_secs(2),
                        controller.wait_for_disconnect_async(),
                    )
                    .await
                    {
                        Ok(Ok(disconnected)) => {
                            warn!("Wi-Fi disconnected: {:?}", disconnected);
                            break;
                        }
                        Ok(Err(error)) => {
                            warn!("Wi-Fi disconnect wait failed: {:?}", error);
                            break;
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(error) => warn!("Wi-Fi connect failed: {:?}", error),
        }

        publish_wifi_link(WifiLinkSnapshot {
            reconnects,
            ..WifiLinkSnapshot::empty()
        });
        Timer::after_secs(2).await;
    }
}

#[embassy_executor::task]
async fn tunnel_task(runner: TunnelRunner<'static, HardwareRng>, outer_stack: Stack<'static>) -> ! {
    let mut rx_meta = alloc::vec![PacketMetadata::EMPTY; OUTER_UDP_PACKETS].into_boxed_slice();
    let mut tx_meta = alloc::vec![PacketMetadata::EMPTY; OUTER_UDP_PACKETS].into_boxed_slice();
    let mut rx =
        alloc::vec![0u8; microtun_embassy::OUTER_SIZE * OUTER_UDP_PACKETS].into_boxed_slice();
    let mut tx =
        alloc::vec![0u8; microtun_embassy::OUTER_SIZE * OUTER_UDP_PACKETS].into_boxed_slice();

    common_tunnel::run(
        runner,
        outer_stack,
        rx_meta.as_mut(),
        rx.as_mut(),
        tx_meta.as_mut(),
        tx.as_mut(),
    )
    .await
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

const TELNET_BANNER: &str = "microtun ESP32-C6-PLC-V\r\ntype 'help' for commands";
const PROVISIONING_TELNET_BANNER: &str =
    "microtun ESP32-C6-PLC-V provisioning mode\r\ntype 'help' for commands";

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
                                let mut store = Esp32ConfigStore {
                                    flash: &mut flash,
                                    record: &mut *record,
                                };
                                store.store(&config[..config_len])
                            };

                            match result {
                                Ok(()) => {
                                    let message = alloc::format!("\r\n{PROVISION_STORED}\r\n");
                                    let _ =
                                        telnet_write_data(&mut socket, message.as_bytes()).await;
                                    info!("replacement provisioning committed; rebooting");
                                    Timer::after_millis(100).await;
                                    software_reset();
                                }
                                Err(error) => {
                                    let message = alloc::format!(
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
                            let message = alloc::format!(
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
                        let mut store = Esp32ConfigStore {
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
                            software_reset();
                        }
                        Err(error) => {
                            let message = alloc::format!(
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
                        Ok((metadata, slot)) => {
                            let version = metadata.version().unwrap_or("invalid");
                            let project = metadata.project_name().unwrap_or("invalid");
                            let message = alloc::format!(
                                "\r\nfirmware accepted\r\nversion: {}\r\nproject: {}\r\nsecure-version: {}\r\nslot: {}\r\nrebooting\r\n",
                                version,
                                project,
                                metadata.secure_version(),
                                ota_slot_name(slot),
                            );
                            let _ = telnet_write_data(&mut socket, message.as_bytes()).await;
                            info!(
                                "firmware update verified and activated: {} ({}, secure-version={}) -> {}",
                                version,
                                project,
                                metadata.secure_version(),
                                ota_slot_name(slot)
                            );
                            Timer::after_millis(100).await;
                            software_reset();
                        }
                        Err(error) => {
                            log_firmware_update_error(&error);
                            let message = alloc::format!(
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
                Err(error) => {
                    warn!("telnet session ended with error: {:?}", error);
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

const OTA_TRIAL_HEALTH_WINDOW: EmbassyDuration = EmbassyDuration::from_secs(30);
/// How long the trial image may wait for the inner tunnel link before the
/// attempt is abandoned.
///
/// Without a bound here a trial image that comes up but never reaches the
/// tunnel simply waits forever: it is never confirmed, but nothing resets it
/// either, so the rollback the bootloader is holding ready is never taken.
const OTA_TRIAL_LINK_TIMEOUT: EmbassyDuration = EmbassyDuration::from_secs(120);

/// Hardware watchdog period. Long enough to cover a stalled flash erase or a
/// slow Wi-Fi association, short enough that a wedged image is rebooted into
/// rollback promptly.
const WATCHDOG_TIMEOUT: esp_hal::time::Duration = esp_hal::time::Duration::from_secs(20);
const WATCHDOG_PET_INTERVAL: EmbassyDuration = EmbassyDuration::from_secs(4);

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
async fn watchdog_task() {
    loop {
        pet_watchdog();
        Timer::after(WATCHDOG_PET_INTERVAL).await;
    }
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

    // Kept alive for the whole of main. Provisioning mode owns it directly;
    // operational mode moves it into a shared async mutex used by BOOT recovery
    // and the explicit shell firmware-update mode.
    let mut flash = FlashStorage::new(peripherals.FLASH);
    let mut firmware_status = prepare_firmware_ota(&mut flash);
    let provision = load_provisioning(&mut flash);

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

    // A provisioned device joins the operator's Wi-Fi network as a station. An
    // unprovisioned one cannot: the credentials for that network are part of the
    // configuration it is still waiting to receive. It therefore hosts its own
    // open access point on a per-device SSID and serves provisioning mode there.
    //
    // The main Telnet shell is used in both operational and provisioning mode,
    // so initialize the same board-I/O surface before deciding whether a tunnel
    // configuration exists.
    let board_io = PlcBoardIo {
        led: Output::new(peripherals.GPIO8, Level::High, OutputConfig::default()),
        relays: [
            Output::new(peripherals.GPIO22, Level::Low, OutputConfig::default()),
            Output::new(peripherals.GPIO11, Level::Low, OutputConfig::default()),
            Output::new(peripherals.GPIO10, Level::Low, OutputConfig::default()),
            Output::new(peripherals.GPIO23, Level::Low, OutputConfig::default()),
        ],
        inputs: [
            Input::new(peripherals.GPIO1, InputConfig::default()),
            Input::new(peripherals.GPIO2, InputConfig::default()),
            Input::new(peripherals.GPIO3, InputConfig::default()),
            Input::new(peripherals.GPIO15, InputConfig::default()),
        ],
    };
    let user_button = Input::new(
        peripherals.GPIO9,
        InputConfig::default().with_pull(Pull::Up),
    );

    let (provision, board_io, user_button) = match provision {
        Ok(provision) => (provision, board_io, user_button),
        Err(_) => {
            if firmware_status.trial {
                warn!(
                    "trial OTA image could not load provisioning; resetting so the bootloader rolls back"
                );
                software_reset();
            }
            warn!("device is not provisioned or the flash config is invalid");
            let (stack, mac) =
                start_provisioning_ap(spawner, peripherals.WIFI, &identity, outer_seed).await;
            provisioning_mode(
                stack,
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
    let flash = SHARED_FLASH.init(AsyncMutex::new(flash));
    info!(
        "loaded provisioning for tunnel {}",
        provision.config.tunnel.tunnel_address
    );
    let config = provision.config;

    let wifi = config
        .wifi
        .as_ref()
        .expect("ESP32-C6 provisioning requires a wifi object");
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

    static OUTER_RESOURCES: StaticCell<StackResources<9>> = StaticCell::new();
    let (outer_stack, outer_runner) = embassy_net::new(
        wifi_interface,
        {
            let mut dhcp_config = embassy_net::DhcpConfig::default();
            dhcp_config.hostname = Some(device_hostname(&identity));
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
        info!(
            "OTA image is pending verification; waiting for the inner tunnel link and then observing {}s of stable service before confirmation",
            OTA_TRIAL_HEALTH_WINDOW.as_secs()
        );
        // tunnel.run() raises the virtual interface link only after the long-running
        // tunnel task has actually started. Reaching this point plus the stability
        // window is a substantially stronger health checkpoint than merely entering
        // main(). A panic/reset before mark-valid is interpreted by the ESP-IDF
        // bootloader as a failed trial and rolls back automatically.
        if with_timeout(OTA_TRIAL_LINK_TIMEOUT, inner_stack.wait_link_up())
            .await
            .is_err()
        {
            warn!(
                "trial OTA image did not reach the inner tunnel link within {}s; resetting so the bootloader rolls back",
                OTA_TRIAL_LINK_TIMEOUT.as_secs()
            );
            software_reset();
        }
        Timer::after(OTA_TRIAL_HEALTH_WINDOW).await;
        let mut flash_guard = flash.lock().await;
        firmware_status = match confirm_firmware_ota(&mut flash_guard) {
            Ok(status) => status,
            Err(error) => {
                warn!(
                    "failed to confirm healthy OTA image: {:?}; resetting to force rollback",
                    error
                );
                drop(flash_guard);
                software_reset();
            }
        };
    }

    spawner.spawn(
        telnet_task(
            Shell {
                tunnel_status,
                wall_clock,
                outer_stack,
                inner_stack,
                mac,
                wifi_ssid,
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
    flash: &mut FlashStorage<'_>,
) -> Result<ProvisionRecord, microtun_provisioning::RecordError> {
    let record = PROVISION_RECORD_BUFFER.init([0u8; RECORD_SIZE]);
    // A flash read that fails outright is a hardware fault rather than a
    // missing configuration, so it is not something provisioning mode can fix.
    if let Err(error) = flash.read(PROVISION_ADDRESS, record) {
        panic!("failed to read provisioning record: {:?}", error);
    }

    decode_record(record)
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

/// Bring up the SoftAP an unprovisioned device serves provisioning mode on.
async fn start_provisioning_ap(
    spawner: Spawner,
    wifi: esp_hal::peripherals::WIFI<'static>,
    identity: &DeviceIdentity,
    seed: u64,
) -> (Stack<'static>, [u8; 6]) {
    let ssid = provision_ap_ssid(identity);
    let access_point_config =
        WifiConfig::AccessPoint(AccessPointConfig::default().with_ssid(ssid.as_str()));
    let wifi_interface = Interface::access_point();
    let mac = wifi_interface.mac_address();

    // Creating the controller applies the initial config and starts the radio,
    // so the AP needs no connection task the way the station path does. It must
    // outlive this function, or dropping it would stop the AP.
    static WIFI_CONTROLLER: StaticCell<WifiController<'static>> = StaticCell::new();
    let _controller = WIFI_CONTROLLER.init(
        WifiController::new(
            wifi,
            ControllerConfig::default().with_initial_config(access_point_config),
        )
        .expect("create provisioning Wi-Fi access point"),
    );

    // The device keeps a predictable fixed address, while a tiny DHCP server
    // configures the provisioning host automatically after it joins this AP.
    // embassy-net reserves one SocketSet slot for its built-in DNS socket
    // whenever the `dns` feature is enabled. Provisioning mode concurrently
    // needs three application sockets: DHCP server UDP, mDNS UDP, and the
    // Provisioning Telnet listener. Keep four slots so task scheduling order cannot
    // make the fourth socket panic while being added.
    static PROVISION_RESOURCES: StaticCell<StackResources<4>> = StaticCell::new();
    let (stack, runner) = embassy_net::new(
        wifi_interface,
        embassy_net::Config::ipv4_static(provision_static_config()),
        PROVISION_RESOURCES.init(StackResources::new()),
        seed,
    );
    spawner.spawn(outer_net_task(runner).unwrap());

    info!(
        "provisioning mode: advertising open Wi-Fi network {}",
        ssid.as_str()
    );
    stack.wait_link_up().await;
    spawner.spawn(provision_dhcp_task(stack).unwrap());
    spawner.spawn(provision_mdns_task(stack, *identity).unwrap());
    info!(
        "provisioning mode: advertising {} over mDNS/DNS-SD",
        microtun_provisioning::PROVISION_MDNS_SERVICE
    );
    info!(
        "provisioning mode: join {}; DHCP will configure the host on {}.{}.{}.0/{}",
        ssid.as_str(),
        PROVISION_DEVICE_IPV4[0],
        PROVISION_DEVICE_IPV4[1],
        PROVISION_DEVICE_IPV4[2],
        PROVISION_IPV4_PREFIX_LEN
    );

    (stack, mac)
}

struct Esp32ConfigStore<'a, 'd> {
    flash: &'a mut FlashStorage<'d>,
    record: &'a mut [u8; RECORD_SIZE],
}

impl ConfigStore for Esp32ConfigStore<'_, '_> {
    fn erase(&mut self) -> Result<(), ConfigStoreError> {
        self.flash
            .erase(PROVISION_ADDRESS, PROVISION_ERASE_END)
            .map_err(|_| ConfigStoreError::Storage)
    }

    fn store(&mut self, config: &[u8]) -> Result<(), ConfigStoreError> {
        // Encode and validate before erasing anything.
        encode_record(config, self.record).map_err(|_| ConfigStoreError::InvalidConfig)?;

        self.erase()?;
        self.flash
            .write(PROVISION_ADDRESS, self.record)
            .map_err(|_| ConfigStoreError::Storage)?;

        // Verify from flash: record header, CRC, INI parsing, and semantic
        // config validation, exactly as the next boot will do.
        self.record.fill(0);
        self.flash
            .read(PROVISION_ADDRESS, self.record)
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
    wifi_ssid: heapless::String<32>,
    identity: DeviceIdentity,
    reset_reason: &'static str,
    temperature_sensor: TemperatureSensor<'static>,
    board_io: PlcBoardIo,
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
                SYS_TABLE
                    .field(out, "version", ESP_APP_DESC.version())
                    .await?;
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
                NET_TABLE
                    .field_fmt(
                        out,
                        "wifi",
                        format_args!("access-point ssid={}", shell.wifi_ssid.as_str()),
                    )
                    .await?;
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
                field: Some(NetField::Wifi),
            } => {
                WIFI_TABLE
                    .field(out, "ssid", shell.wifi_ssid.as_str())
                    .await?;
                WIFI_TABLE.field(out, "mode", "access-point").await?;
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
                IO_TABLE.field(out, "input", &4usize).await?;
                IO_TABLE.field(out, "relay", &4usize).await?;
                IO_TABLE.field(out, "led", &1usize).await?;
                IO_TABLE.field(out, "button", &1usize).await?;
            }
            Command::Io {
                kind: Some(PlcIoKind::Input),
                target: None,
                action: None,
            } => {
                for (index, label) in IO_INDEX_LABELS.iter().enumerate() {
                    let active = shell.board_io.input_is_active(index).unwrap_or(false);
                    IO_INDEX_TABLE
                        .field(out, label, if active { "active" } else { "inactive" })
                        .await?;
                }
            }
            Command::Io {
                kind: Some(PlcIoKind::Input),
                target: Some(target),
                action: None,
            } => {
                let index = match target {
                    PlcIoTarget::One => 0,
                    PlcIoTarget::Two => 1,
                    PlcIoTarget::Three => 2,
                    PlcIoTarget::Four => 3,
                };
                cli_println(
                    out,
                    if shell.board_io.input_is_active(index).unwrap_or(false) {
                        "active"
                    } else {
                        "inactive"
                    },
                )
                .await?;
            }
            Command::Io {
                kind: Some(PlcIoKind::Relay),
                target: None,
                action: None,
            } => {
                for (index, label) in IO_INDEX_LABELS.iter().enumerate() {
                    let on = shell.board_io.relay_is_on(index).unwrap_or(false);
                    IO_INDEX_TABLE
                        .field(out, label, if on { "on" } else { "off" })
                        .await?;
                }
            }
            Command::Io {
                kind: Some(PlcIoKind::Relay),
                target: Some(target),
                action: None,
            } => {
                let index = match target {
                    PlcIoTarget::One => 0,
                    PlcIoTarget::Two => 1,
                    PlcIoTarget::Three => 2,
                    PlcIoTarget::Four => 3,
                };
                cli_println(
                    out,
                    if shell.board_io.relay_is_on(index).unwrap_or(false) {
                        "on"
                    } else {
                        "off"
                    },
                )
                .await?;
            }
            Command::Io {
                kind: Some(PlcIoKind::Relay),
                target: Some(target),
                action: Some(action),
            } => set_relay_action(out, &mut shell.board_io, target, action).await?,
            Command::Io {
                kind: Some(PlcIoKind::Led),
                target: None,
                action: None,
            } => {
                cli_println(
                    out,
                    if shell.board_io.led_is_on() {
                        "on"
                    } else {
                        "off"
                    },
                )
                .await?
            }
            Command::Io {
                kind: Some(PlcIoKind::Led),
                target: None,
                action: Some(action),
            } => set_led_action(out, &mut shell.board_io, action).await?,
            Command::Io {
                kind: Some(PlcIoKind::Button),
                target: None,
                action: None,
            } => {
                cli_println(
                    out,
                    if shell.button.is_low() {
                        "pressed"
                    } else {
                        "released"
                    },
                )
                .await?
            }
            Command::Io { .. } => {
                cli_println(out, "error: expected io [input [1|2|3|4] | relay [1|2|3|4] [on|off|toggle] | led [on|off|toggle] | button]").await?;
            }

            Command::Fw {
                action: None | Some(FirmwareAction::Show),
            } => {
                FW_TABLE
                    .field(out, "version", ESP_APP_DESC.version())
                    .await?;
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
                cli_println(out, "send signed application image now; Ctrl-X cancels").await?;
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
                software_reset();
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
    flash: &mut FlashStorage<'static>,
    identity: DeviceIdentity,
    mac: [u8; 6],
    reset_reason: &'static str,
    temperature_sensor: TemperatureSensor<'static>,
    board_io: PlcBoardIo,
    button: Input<'static>,
    firmware_status: FirmwareStatus,
) -> ! {
    let mut rx = [0u8; TELNET_TCP_BUFFER];
    let mut tx = [0u8; TELNET_TCP_BUFFER];
    let record = PROVISION_WRITE_BUFFER.init([0u8; RECORD_SIZE]);
    let config = PROVISION_CONFIG_BUFFER.init([0u8; MAX_INI_LEN]);
    let device_id = identity.device_id();
    let wifi_ssid = provision_ap_ssid(&identity);
    let mut shell = ProvisioningShell {
        stack,
        mac,
        wifi_ssid,
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

    info!(
        "provisioning mode: device={} main Telnet CLI listening on {}.{}.{}.{}:{}",
        device_id.as_str(),
        PROVISION_DEVICE_IPV4[0],
        PROVISION_DEVICE_IPV4[1],
        PROVISION_DEVICE_IPV4[2],
        PROVISION_DEVICE_IPV4[3],
        PROVISION_PORT
    );

    loop {
        let mut socket = TcpSocket::new(stack, &mut rx, &mut tx);
        socket.set_keep_alive(Some(TCP_KEEP_ALIVE));
        socket.set_timeout(Some(TCP_IDLE_TIMEOUT));

        if let Err(error) = socket.accept(PROVISION_PORT).await {
            warn!("provisioning Telnet accept failed: {:?}", error);
            continue;
        }
        info!("provisioning-mode Telnet client connected");
        loop {
            let request =
                match telnet_session(&mut socket, &mut shell, PROVISIONING_TELNET_BANNER).await {
                    Ok(request) => request,
                    Err(error) => {
                        warn!("provisioning Telnet session ended with error: {:?}", error);
                        break;
                    }
                };

            match request {
                TelnetSessionExit::Provision => {
                    match receive_ymodem_buffer(&mut socket, &mut config[..]).await {
                        Ok(config_len) => {
                            let result = {
                                let mut store = Esp32ConfigStore {
                                    flash: &mut *flash,
                                    record: &mut *record,
                                };
                                store.store(&config[..config_len])
                            };

                            match result {
                                Ok(()) => {
                                    let message = alloc::format!("\r\n{PROVISION_STORED}\r\n");
                                    let _ =
                                        telnet_write_data(&mut socket, message.as_bytes()).await;
                                    info!("provisioning committed; rebooting into normal mode");
                                    Timer::after_millis(100).await;
                                    software_reset();
                                }
                                Err(error) => {
                                    let message = alloc::format!(
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
                            let message = alloc::format!(
                                "\r\nprovisioning transfer failed: {}\r\nreturning to shell\r\n",
                                transfer_error_text(error)
                            );
                            let _ = telnet_write_data(&mut socket, message.as_bytes()).await;
                            warn!("provisioning YMODEM transfer failed: {:?}", error);
                        }
                    }
                }
                TelnetSessionExit::ProvisionClear => {
                    let result = {
                        let mut store = Esp32ConfigStore {
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
                            software_reset();
                        }
                        Err(error) => {
                            let message = alloc::format!(
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
                        Ok((metadata, slot)) => {
                            let version = metadata.version().unwrap_or("invalid");
                            let project = metadata.project_name().unwrap_or("invalid");
                            let message = alloc::format!(
                                "\r\nfirmware accepted\r\nversion: {}\r\nproject: {}\r\nsecure-version: {}\r\nslot: {}\r\nrebooting\r\n",
                                version,
                                project,
                                metadata.secure_version(),
                                ota_slot_name(slot),
                            );
                            let _ = telnet_write_data(&mut socket, message.as_bytes()).await;
                            Timer::after_millis(100).await;
                            software_reset();
                        }
                        Err(error) => {
                            log_firmware_update_error(&error);
                            let message = alloc::format!(
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
        if let Err(error) = socket.flush().await {
            warn!("provisioning Telnet socket close failed: {:?}", error);
        }
    }
}

#[derive(Clone, Copy)]
struct WallClock {
    unix_secs: u64,
    unix_nanos: u32,
    sample: EmbassyInstant,
}

impl WallClock {
    fn new(unix_secs: u64, unix_nanos: u32) -> Self {
        Self {
            unix_secs,
            unix_nanos,
            sample: EmbassyInstant::now(),
        }
    }

    fn now(self) -> (u64, u32) {
        let elapsed_us = EmbassyInstant::now()
            .as_micros()
            .saturating_sub(self.sample.as_micros());
        let base_us = u64::from(self.unix_nanos / 1_000);
        let total_us = base_us.saturating_add(elapsed_us);
        (
            self.unix_secs.saturating_add(total_us / 1_000_000),
            ((total_us % 1_000_000) * 1_000) as u32,
        )
    }
}

async fn sync_time_from_ntp(stack: Stack<'static>, host: &str, port: u16) -> (u64, u32) {
    let result = query_ntp_time(stack, host, port).await;
    let (unix_secs, unix_nanos) = ntp_unix_time(&result);
    info!(
        "time synchronized from {}: unix={} stratum={} rtt={}us",
        host,
        unix_secs,
        result.stratum(),
        result.roundtrip()
    );
    (unix_secs, unix_nanos)
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum NetField {
    /// Show whether the network link is up.
    Link,
    /// Show the configured IP address and gateway.
    Ip,
    /// Show the network MAC address.
    Mac,
    /// Show Wi-Fi association and signal details.
    Wifi,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PlcIoKind {
    /// Read a digital input.
    Input,
    /// Inspect or control a relay output.
    Relay,
    /// Inspect or control the user LED.
    Led,
    /// Read the user button state.
    Button,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PlcIoTarget {
    /// Select channel 1.
    #[value(name = "1")]
    One,
    /// Select channel 2.
    #[value(name = "2")]
    Two,
    /// Select channel 3.
    #[value(name = "3")]
    Three,
    /// Select channel 4.
    #[value(name = "4")]
    Four,
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
#[command(name = "microtun", about = "microtun ESP32-C6-PLC-V console")]
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

    /// Inspect or control hardware I/O.
    Io {
        /// I/O function.
        #[arg(value_enum, value_name = "KIND")]
        kind: Option<PlcIoKind>,
        /// Input, relay, or LED number.
        #[arg(value_enum, value_name = "TARGET")]
        target: Option<PlcIoTarget>,
        /// Relay or LED action.
        #[arg(value_enum, value_name = "ACTION")]
        action: Option<IoAction>,
    },

    /// Show firmware status or install an update.
    Fw {
        #[arg(value_enum, value_name = "ACTION")]
        action: Option<FirmwareAction>,
    },

    /// Identify this device by blinking its LED(s).
    Identify,

    /// Reboot the device.
    Reboot,

    /// Close this session.
    Quit,
}

const NET_TABLE: Table = Table::new(&["link", "ip", "mac", "wifi"]);
const WIFI_TABLE: Table = Table::new(&["ssid", "bssid", "channel", "rssi", "reconnects"]);
const IO_TABLE: Table = Table::new(&["input", "relay", "led", "button"]);
const IO_INDEX_LABELS: [&str; 4] = ["1", "2", "3", "4"];
const IO_INDEX_TABLE: Table = Table::new(&IO_INDEX_LABELS);
const FW_TABLE: Table = Table::new(&["version", "slot"]);

struct Shell {
    tunnel_status: TunnelStatus<'static>,
    wall_clock: Option<WallClock>,
    outer_stack: Stack<'static>,
    inner_stack: Stack<'static>,
    mac: [u8; 6],
    wifi_ssid: heapless::String<32>,
    identity: DeviceIdentity,
    reset_reason: &'static str,
    temperature_sensor: TemperatureSensor<'static>,
    board_io: PlcBoardIo,
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
    cli_field(out, "version", ESP_APP_DESC.version()).await
}

async fn write_temperature<W>(
    out: &mut W,
    sensor: &mut TemperatureSensor<'static>,
    table: Option<Table>,
) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    let celsius = sensor.get_temperature().to_celsius();
    match table {
        Some(table) => {
            table
                .field_fmt(out, "temp", format_args!("{celsius:.1} C"))
                .await
        }
        None => cli_line(out, format_args!("{celsius:.1} C")).await,
    }
}

async fn write_memory<W>(out: &mut W, table: Option<Table>) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    let memory = esp_alloc::HEAP.stats();
    let free = memory.size.saturating_sub(memory.current_usage);
    let percent = memory
        .current_usage
        .saturating_mul(100)
        .checked_div(memory.size)
        .unwrap_or(0);
    match table {
        Some(table) => {
            table
                .field_fmt(
                    out,
                    "memory",
                    format_args!(
                        "{}B/{}B ({percent}%) free={free}B",
                        memory.current_usage, memory.size
                    ),
                )
                .await
        }
        None => {
            cli_line(
                out,
                format_args!(
                    "{}B/{}B ({percent}%) free={free}B",
                    memory.current_usage, memory.size
                ),
            )
            .await
        }
    }
}

async fn set_relay_action<W>(
    out: &mut W,
    board_io: &mut PlcBoardIo,
    target: PlcIoTarget,
    action: IoAction,
) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    let index = match target {
        PlcIoTarget::One => 0,
        PlcIoTarget::Two => 1,
        PlcIoTarget::Three => 2,
        PlcIoTarget::Four => 3,
    };
    let current = board_io.relay_is_on(index).unwrap_or(false);
    let requested = match action {
        IoAction::On => true,
        IoAction::Off => false,
        IoAction::Toggle => !current,
    };
    let _ = board_io.set_relay(index, requested);
    cli_println(out, "ok").await
}

async fn identify_provisioning_board(board_io: &mut PlcBoardIo) {
    let saved = board_io.led_is_on();
    for _ in 0..IDENTIFY_SECONDS * 2 {
        board_io.set_led(true);
        Timer::after_millis(250).await;
        board_io.set_led(false);
        Timer::after_millis(250).await;
    }
    board_io.set_led(saved);
}

async fn identify_board(board_io: &mut PlcBoardIo) {
    let saved = board_io.led_is_on();
    for _ in 0..3 {
        board_io.set_led(true);
        Timer::after_millis(150).await;
        board_io.set_led(false);
        Timer::after_millis(150).await;
    }
    board_io.set_led(saved);
}

async fn set_led_action<W>(
    out: &mut W,
    board_io: &mut PlcBoardIo,
    action: IoAction,
) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    match action {
        IoAction::On => board_io.set_led(true),
        IoAction::Off => board_io.set_led(false),
        IoAction::Toggle => board_io.toggle_led(),
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
            SYS_TABLE
                .field(out, "version", ESP_APP_DESC.version())
                .await?;
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
            cli_time_field(out, SYS_TABLE, "time", shell.wall_clock.map(WallClock::now)).await?;
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
            cli_time(out, None, shell.wall_clock.map(WallClock::now)).await?;
        }
        Command::Sys {
            field: Some(SysField::Memory),
        } => write_memory(out, None).await?,
        Command::Net { field: None } => {
            cli_write_net_base(out, NET_TABLE, shell.outer_stack, shell.mac).await?;

            let wifi = wifi_link_snapshot();
            if wifi.associated {
                match wifi.rssi_dbm {
                    Some(rssi_dbm) => {
                        NET_TABLE
                            .field_fmt(
                                out,
                                "wifi",
                                format_args!(
                                    "{} ch={} rssi={} dBm reconnects={}",
                                    shell.wifi_ssid, wifi.channel, rssi_dbm, wifi.reconnects
                                ),
                            )
                            .await?;
                    }
                    None => {
                        NET_TABLE
                            .field_fmt(
                                out,
                                "wifi",
                                format_args!(
                                    "{} ch={} rssi=n/a reconnects={}",
                                    shell.wifi_ssid, wifi.channel, wifi.reconnects
                                ),
                            )
                            .await?;
                    }
                }
            } else {
                NET_TABLE
                    .field_fmt(
                        out,
                        "wifi",
                        format_args!(
                            "{} disconnected reconnects={}",
                            shell.wifi_ssid, wifi.reconnects
                        ),
                    )
                    .await?;
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
            field: Some(NetField::Wifi),
        } => {
            let status = wifi_link_snapshot();
            WIFI_TABLE
                .field(out, "ssid", shell.wifi_ssid.as_str())
                .await?;
            if status.associated {
                WIFI_TABLE
                    .field_fmt(
                        out,
                        "bssid",
                        format_args!(
                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            status.bssid[0],
                            status.bssid[1],
                            status.bssid[2],
                            status.bssid[3],
                            status.bssid[4],
                            status.bssid[5]
                        ),
                    )
                    .await?;
                WIFI_TABLE.field(out, "channel", &status.channel).await?;
                match status.rssi_dbm {
                    Some(rssi_dbm) => {
                        WIFI_TABLE
                            .field_fmt(out, "rssi", format_args!("{rssi_dbm} dBm"))
                            .await?;
                    }
                    None => WIFI_TABLE.field(out, "rssi", "n/a").await?,
                }
            } else {
                WIFI_TABLE.field(out, "bssid", "n/a").await?;
                WIFI_TABLE.field(out, "channel", "n/a").await?;
                WIFI_TABLE.field(out, "rssi", "n/a").await?;
            }
            WIFI_TABLE
                .field(out, "reconnects", &status.reconnects)
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
            IO_TABLE.field(out, "input", &4usize).await?;
            IO_TABLE.field(out, "relay", &4usize).await?;
            IO_TABLE.field(out, "led", &1usize).await?;
            IO_TABLE.field(out, "button", &1usize).await?;
        }
        Command::Io {
            kind: Some(PlcIoKind::Input),
            target: None,
            action: None,
        } => {
            for (index, label) in IO_INDEX_LABELS.iter().enumerate() {
                let active = shell.board_io.input_is_active(index).unwrap_or(false);
                IO_INDEX_TABLE
                    .field(out, label, if active { "active" } else { "inactive" })
                    .await?;
            }
        }
        Command::Io {
            kind: Some(PlcIoKind::Input),
            target: Some(target),
            action: None,
        } => {
            let index = match target {
                PlcIoTarget::One => 0,
                PlcIoTarget::Two => 1,
                PlcIoTarget::Three => 2,
                PlcIoTarget::Four => 3,
            };
            cli_println(
                out,
                if shell.board_io.input_is_active(index).unwrap_or(false) {
                    "active"
                } else {
                    "inactive"
                },
            )
            .await?;
        }
        Command::Io {
            kind: Some(PlcIoKind::Relay),
            target: None,
            action: None,
        } => {
            for (index, label) in IO_INDEX_LABELS.iter().enumerate() {
                let on = shell.board_io.relay_is_on(index).unwrap_or(false);
                IO_INDEX_TABLE
                    .field(out, label, if on { "on" } else { "off" })
                    .await?;
            }
        }
        Command::Io {
            kind: Some(PlcIoKind::Relay),
            target: Some(target),
            action: None,
        } => {
            let index = match target {
                PlcIoTarget::One => 0,
                PlcIoTarget::Two => 1,
                PlcIoTarget::Three => 2,
                PlcIoTarget::Four => 3,
            };
            cli_println(
                out,
                if shell.board_io.relay_is_on(index).unwrap_or(false) {
                    "on"
                } else {
                    "off"
                },
            )
            .await?;
        }
        Command::Io {
            kind: Some(PlcIoKind::Relay),
            target: Some(target),
            action: Some(action),
        } => set_relay_action(out, &mut shell.board_io, target, action).await?,
        Command::Io {
            kind: Some(PlcIoKind::Led),
            target: None,
            action: None,
        } => {
            IO_INDEX_TABLE
                .field(
                    out,
                    IO_INDEX_LABELS[0],
                    if shell.board_io.led_is_on() {
                        "on"
                    } else {
                        "off"
                    },
                )
                .await?;
        }
        Command::Io {
            kind: Some(PlcIoKind::Led),
            target: Some(PlcIoTarget::One),
            action: None,
        } => {
            cli_println(
                out,
                if shell.board_io.led_is_on() {
                    "on"
                } else {
                    "off"
                },
            )
            .await?;
        }
        Command::Io {
            kind: Some(PlcIoKind::Led),
            target: Some(PlcIoTarget::One),
            action: Some(action),
        } => set_led_action(out, &mut shell.board_io, action).await?,
        Command::Io {
            kind: Some(PlcIoKind::Button),
            target: None,
            action: None,
        } => {
            cli_println(
                out,
                if shell.button.is_low() {
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
            FW_TABLE
                .field(out, "version", ESP_APP_DESC.version())
                .await?;
            FW_TABLE
                .field_fmt(
                    out,
                    "slot",
                    format_args!(
                        "{} ({})",
                        shell.firmware_status.slot, shell.firmware_status.state
                    ),
                )
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
                "error: expected io [input [1|2|3|4] | relay [1|2|3|4] [on|off|toggle] | led [1] [on|off|toggle] | button]",
            )
            .await?;
        }

        Command::Reboot => {
            cli_println(out, "rebooting").await?;
            out.flush().await?;
            Timer::after_millis(100).await;
            software_reset();
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
