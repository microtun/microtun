#![no_std]
#![no_main]

use core::{
    fmt::Write as _,
    net::{IpAddr, SocketAddr},
};

use embassy_executor::Spawner;
use embassy_net::{
    IpAddress, IpEndpoint, Ipv4Address, Ipv4Cidr, Stack, StackResources, StaticConfigV4,
    dns::DnsQueryType,
    tcp::{self, TcpSocket},
    udp::{PacketMetadata, UdpSocket},
};
use embassy_net_driver_channel::Device as TunnelDevice;
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, channel::Channel};
use embassy_time::{Duration as EmbassyDuration, Instant as EmbassyInstant, Timer, with_timeout};
use embedded_io_async::Write as _;
use esp_alloc as _;
use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    interrupt::software::SoftwareInterruptControl,
    rng::{Trng, TrngSource},
    timer::timg::TimerGroup,
};
use esp_radio::wifi::{
    Config as WifiConfig, ControllerConfig, Interface, WifiController, sta::StationConfig,
};
use heapless::String;
use log::{info, warn};
use microtun_embassy::{
    ResolverBuffers, ResolverChannels, ResolverConfig, TunnelRunner, TunnelState,
    core::{
        Config as TunnelConfig, Duration, InboundPolicy, Instant, IpNet, PinnedPeer,
        ResolverCommand, ResolverEvent, decode_key, decode_key_into, encode_key, parse_ip_net,
    },
    new_tunnel, resolver_task,
};
use rand_core::RngCore as _;
use sntpc::{NtpContext, NtpTimestampGenerator, get_time};
use sntpc_net_embassy::UdpSocketWrapper;
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

mod config {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

const SSID: &str = env!("SSID");
const PASSWORD: &str = env!("PASSWORD");

type OuterDevice = Interface;
type InnerDevice = TunnelDevice<'static, { microtun_embassy::MTU }>;
type HardwareRng = Trng;

const RESOLVER_CHANNEL_DEPTH: usize = 16;
const TUNNEL_QUEUE_DEPTH: usize = 4;
const OUTER_UDP_PACKETS: usize = 4;
const RESOLVER_TCP_BUFFER: usize = 2048;
const TELNET_TCP_BUFFER: usize = 1024;
const TCP_KEEP_ALIVE: EmbassyDuration = EmbassyDuration::from_secs(15);
const TCP_IDLE_TIMEOUT: EmbassyDuration = EmbassyDuration::from_secs(45);
const NTP_PACKET_BUFFER: usize = 128;

static RESOLVER_COMMANDS: Channel<
    CriticalSectionRawMutex,
    ResolverCommand,
    RESOLVER_CHANNEL_DEPTH,
> = Channel::new();
static RESOLVER_EVENTS: Channel<CriticalSectionRawMutex, ResolverEvent, RESOLVER_CHANNEL_DEPTH> =
    Channel::new();

#[embassy_executor::task]
async fn outer_net_task(mut runner: embassy_net::Runner<'static, OuterDevice>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn inner_net_task(mut runner: embassy_net::Runner<'static, InnerDevice>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn wifi_connection_task(mut controller: WifiController<'static>) -> ! {
    info!("Wi-Fi connection task started");

    loop {
        info!("connecting to Wi-Fi SSID {}", SSID);
        match controller.connect_async().await {
            Ok(connected) => {
                info!("Wi-Fi station connected: {:?}", connected);

                // The 1.0.0-beta.0 public API exposes this dedicated stable
                // disconnect waiter. No private WifiEvent/WifiState access is
                // needed, and ControllerConfig's initial station config has
                // already started the station side for us.
                match controller.wait_for_disconnect_async().await {
                    Ok(disconnected) => warn!("Wi-Fi disconnected: {:?}", disconnected),
                    Err(error) => warn!("Wi-Fi disconnect wait failed: {:?}", error),
                }
            }
            Err(error) => warn!("Wi-Fi connect failed: {:?}", error),
        }

        Timer::after_secs(2).await;
    }
}

#[embassy_executor::task]
async fn tunnel_task(runner: TunnelRunner<'static, HardwareRng>, outer_stack: Stack<'static>) -> ! {
    let mut rx_meta = [PacketMetadata::EMPTY; OUTER_UDP_PACKETS];
    let mut tx_meta = [PacketMetadata::EMPTY; OUTER_UDP_PACKETS];
    let mut rx = [0u8; microtun_embassy::OUTER_SIZE * OUTER_UDP_PACKETS];
    let mut tx = [0u8; microtun_embassy::OUTER_SIZE * OUTER_UDP_PACKETS];

    runner
        .run(
            outer_stack,
            RESOLVER_COMMANDS.sender(),
            RESOLVER_EVENTS.receiver(),
            &mut rx_meta,
            &mut rx,
            &mut tx_meta,
            &mut tx,
        )
        .await
}

#[embassy_executor::task]
async fn peers_resolver_task(inner_stack: Stack<'static>, local_public_key: [u8; 32]) -> ! {
    let mut rx = [0u8; RESOLVER_TCP_BUFFER];
    let mut tx = [0u8; RESOLVER_TCP_BUFFER];

    let cfg = ResolverConfig {
        server: IpEndpoint::new(
            Ipv4Address::new(
                config::API_SERVER_TUNNEL_ADDR[0],
                config::API_SERVER_TUNNEL_ADDR[1],
                config::API_SERVER_TUNNEL_ADDR[2],
                config::API_SERVER_TUNNEL_ADDR[3],
            )
            .into(),
            config::PEERS_API_PORT,
        ),
        jitter_seed: microtun_embassy::peers_api::Jitter::seed_from_key(&local_public_key),
    };

    resolver_task(
        inner_stack,
        cfg,
        ResolverChannels {
            commands: RESOLVER_COMMANDS.receiver(),
            events: RESOLVER_EVENTS.sender(),
        },
        ResolverBuffers {
            socket_rx: &mut rx,
            socket_tx: &mut tx,
        },
    )
    .await
}

#[embassy_executor::task]
async fn telnet_task(
    inner_stack: Stack<'static>,
    local_public_key: [u8; 32],
    wall_clock: WallClock,
) -> ! {
    let mut rx = [0u8; TELNET_TCP_BUFFER];
    let mut tx = [0u8; TELNET_TCP_BUFFER];

    loop {
        let mut socket = TcpSocket::new(inner_stack, &mut rx, &mut tx);
        socket.set_keep_alive(Some(TCP_KEEP_ALIVE));
        socket.set_timeout(Some(TCP_IDLE_TIMEOUT));
        info!(
            "telnet shell listening on inner port {}",
            config::TELNET_PORT
        );

        if let Err(error) = socket.accept(config::TELNET_PORT).await {
            warn!("telnet accept failed: {:?}", error);
            continue;
        }

        info!("telnet client connected through microtun");
        if let Err(error) = telnet_session(&mut socket, &local_public_key, wall_clock).await {
            warn!("telnet session ended with error: {:?}", error);
        }
        socket.close();
    }
}

#[esp_rtos::main]
async fn main(spawner: Spawner) -> ! {
    esp_println::logger::init_logger_from_env();

    let hal_config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(hal_config);

    // reclaimed bootloader ram
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 64 * 1024);
    // wireguard etc
    esp_alloc::heap_allocator!(size: 72 * 1024);

    // esp-radio's async Wi-Fi driver expects the esp-rtos preemptive scheduler.
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    // microtun's handshake/cookie path requires rand_core 0.6 CryptoRng. On the
    // C3, TrngSource keeps RNG+ADC1 supplying entropy while Trng is the handle
    // that implements RngCore + CryptoRng. Keep the source alive for main's
    // whole (never-ending) scope.
    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let mut rng = Trng::try_new().expect("initialize ESP32-C3 TRNG");
    let outer_seed = rng.next_u64();
    let inner_seed = rng.next_u64();

    let station_config = WifiConfig::Station(
        StationConfig::default()
            .with_ssid(SSID)
            .with_password(PASSWORD.into()),
    );
    let wifi_interface = Interface::station();
    let wifi_controller = WifiController::new(
        peripherals.WIFI,
        ControllerConfig::default().with_initial_config(station_config),
    )
    .expect("create Wi-Fi controller");

    static OUTER_RESOURCES: StaticCell<StackResources<8>> = StaticCell::new();
    let (outer_stack, outer_runner) = embassy_net::new(
        wifi_interface,
        embassy_net::Config::dhcpv4(Default::default()),
        OUTER_RESOURCES.init(StackResources::new()),
        outer_seed,
    );

    spawner.spawn(wifi_connection_task(wifi_controller).unwrap());
    spawner.spawn(outer_net_task(outer_runner).unwrap());

    info!("waiting for ESP32-C3 Wi-Fi DHCP");
    outer_stack.wait_config_up().await;
    info!("Wi-Fi DHCP lease acquired");

    let (unix_secs, unix_nanos) = sync_time_from_ntp(outer_stack).await;
    let wall_clock = WallClock::new(unix_secs, unix_nanos);
    let api_server_outer_ip = resolve_api_server_host(outer_stack).await;

    static TUNNEL_STATE: StaticCell<TunnelState<TUNNEL_QUEUE_DEPTH, TUNNEL_QUEUE_DEPTH>> =
        StaticCell::new();
    let (channel_runner, tunnel_device) =
        new_tunnel(TUNNEL_STATE.init(TunnelState::<TUNNEL_QUEUE_DEPTH, TUNNEL_QUEUE_DEPTH>::new()));

    let inner_cfg = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(
            Ipv4Address::new(
                config::LOCAL_TUNNEL_IPV4[0],
                config::LOCAL_TUNNEL_IPV4[1],
                config::LOCAL_TUNNEL_IPV4[2],
                config::LOCAL_TUNNEL_IPV4[3],
            ),
            config::LOCAL_TUNNEL_PREFIX_LEN,
        ),
        gateway: None,
        dns_servers: Default::default(),
    });

    static INNER_RESOURCES: StaticCell<StackResources<4>> = StaticCell::new();
    let (inner_stack, inner_runner) = embassy_net::new(
        tunnel_device,
        inner_cfg,
        INNER_RESOURCES.init(StackResources::new()),
        inner_seed,
    );
    spawner.spawn(inner_net_task(inner_runner).unwrap());

    let api_inner: IpNet =
        parse_ip_net(config::API_SERVER_TUNNEL_CIDR).expect("valid API server tunnel host CIDR");
    let api_server_public_key =
        decode_key(config::API_SERVER_PUBLIC_KEY).expect("valid API server public key");
    let api_routes = [api_inner];
    let pinned = [PinnedPeer {
        public_key: api_server_public_key,
        endpoint: Some(SocketAddr::from((
            api_server_outer_ip.octets(),
            config::API_SERVER_PORT,
        ))),
        relay: None,
        addresses: &api_routes,
        inbound_policy: InboundPolicy::EstablishedOnly,
        persistent_keepalive: Some(Duration::from_secs(25)),
    }];

    let mut private_key = [0u8; 32];
    decode_key_into(config::PRIVATE_KEY, &mut private_key).expect("valid device private key");

    let now = Instant::from_millis(EmbassyInstant::now().as_millis());
    let mut tunnel = TunnelRunner::new(
        TunnelConfig::new(private_key, &pinned),
        rng,
        channel_runner,
        config::LISTEN_PORT,
        now,
    )
    .expect("create microtun runner");

    tunnel.set_unix_time(unix_secs, unix_nanos, now);
    let local_public_key = tunnel.public_key();
    info!("microtun tunnel ready; telnet is only on the inner stack");

    spawner.spawn(tunnel_task(tunnel, outer_stack).unwrap());
    spawner.spawn(peers_resolver_task(inner_stack, local_public_key).unwrap());
    spawner.spawn(telnet_task(inner_stack, local_public_key, wall_clock).unwrap());

    core::future::pending().await
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

#[derive(Clone, Copy)]
struct BootTimestampGenerator {
    sample: EmbassyInstant,
}

// sntpc only needs an approximate Unix time to select the correct 2^32-second
// NTP era. 2050 remains a safe pivot for contemporary deployments; uptime
// supplies the changing portion used for request/response timing.
const NTP_ERA_PIVOT_UNIX_SECS: u64 = 2_524_608_000; // 2050-01-01 UTC

impl BootTimestampGenerator {
    fn new() -> Self {
        Self {
            sample: EmbassyInstant::from_secs(0),
        }
    }
}

impl NtpTimestampGenerator for BootTimestampGenerator {
    fn init(&mut self) {
        self.sample = EmbassyInstant::now();
    }

    fn timestamp_sec(&self) -> u64 {
        NTP_ERA_PIVOT_UNIX_SECS.saturating_add(self.sample.as_secs())
    }

    fn timestamp_subsec_micros(&self) -> u32 {
        (self.sample.as_micros() % 1_000_000) as u32
    }
}

async fn resolve_api_server_host(stack: Stack<'static>) -> Ipv4Address {
    if let Ok(address) = config::API_SERVER_HOST.parse::<core::net::Ipv4Addr>() {
        let octets = address.octets();
        return Ipv4Address::new(octets[0], octets[1], octets[2], octets[3]);
    }

    loop {
        info!("resolving API server host {}", config::API_SERVER_HOST);
        let addresses = match with_timeout(
            EmbassyDuration::from_secs(5),
            stack.dns_query(config::API_SERVER_HOST, DnsQueryType::A),
        )
        .await
        {
            Ok(Ok(addresses)) => addresses,
            Ok(Err(error)) => {
                warn!("API server DNS lookup failed: {:?}", error);
                Timer::after_secs(2).await;
                continue;
            }
            Err(_) => {
                warn!("API server DNS lookup timed out");
                Timer::after_secs(2).await;
                continue;
            }
        };

        if let Some(address) = addresses.into_iter().find_map(|address| match address {
            IpAddress::Ipv4(ip) => Some(ip),
            _ => None,
        }) {
            info!(
                "API server {} resolved to {}",
                config::API_SERVER_HOST,
                address
            );
            return address;
        }

        warn!("API server DNS lookup returned no IPv4 address");
        Timer::after_secs(2).await;
    }
}

async fn sync_time_from_ntp(stack: Stack<'static>) -> (u64, u32) {
    loop {
        info!("resolving NTP server {}", config::NTP_SERVER);
        let addresses = match with_timeout(
            EmbassyDuration::from_secs(5),
            stack.dns_query(config::NTP_SERVER, DnsQueryType::A),
        )
        .await
        {
            Ok(Ok(addresses)) => addresses,
            Ok(Err(error)) => {
                warn!("NTP DNS lookup failed: {:?}", error);
                Timer::after_secs(2).await;
                continue;
            }
            Err(_) => {
                warn!("NTP DNS lookup timed out");
                Timer::after_secs(2).await;
                continue;
            }
        };

        let Some(server_ip) = addresses.into_iter().find_map(|address| match address {
            IpAddress::Ipv4(ip) => Some(ip),
            _ => None,
        }) else {
            warn!("NTP DNS lookup returned no IPv4 address");
            Timer::after_secs(2).await;
            continue;
        };

        let mut rx_meta = [PacketMetadata::EMPTY; 1];
        let mut tx_meta = [PacketMetadata::EMPTY; 1];
        let mut rx = [0u8; NTP_PACKET_BUFFER];
        let mut tx = [0u8; NTP_PACKET_BUFFER];
        let mut socket = UdpSocket::new(stack, &mut rx_meta, &mut rx, &mut tx_meta, &mut tx);
        if let Err(error) = socket.bind(config::NTP_LOCAL_PORT) {
            warn!("NTP UDP bind failed: {:?}", error);
            Timer::after_secs(2).await;
            continue;
        }

        let server = SocketAddr::new(IpAddr::V4(server_ip), config::NTP_PORT);
        let wrapper = UdpSocketWrapper::new(socket);
        let context = NtpContext::new(BootTimestampGenerator::new());
        let result = match with_timeout(
            EmbassyDuration::from_secs(5),
            get_time(server, &wrapper, context),
        )
        .await
        {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                warn!("SNTP request failed");
                Timer::after_secs(2).await;
                continue;
            }
            Err(_) => {
                warn!("SNTP request timed out");
                Timer::after_secs(2).await;
                continue;
            }
        };

        let unix_secs = result.sec();
        let unix_nanos = ((u64::from(result.sec_fraction()) * 1_000_000_000) >> 32) as u32;
        info!(
            "time synchronized from {}: unix={} stratum={} rtt={}us",
            config::NTP_SERVER,
            unix_secs,
            result.stratum(),
            result.roundtrip()
        );
        return (unix_secs, unix_nanos);
    }
}

#[derive(Clone, Copy)]
enum TelnetState {
    Data,
    Iac,
    Option(u8),
}

async fn telnet_session(
    socket: &mut TcpSocket<'_>,
    local_public_key: &[u8; 32],
    wall_clock: WallClock,
) -> Result<(), tcp::Error> {
    const IAC: u8 = 255;
    const WILL: u8 = 251;
    const WONT: u8 = 252;
    const DO: u8 = 253;
    const DONT: u8 = 254;

    socket
        .write_all(
            b"\r\nmicrotun ESP32-C3 shell\r\n\
              Type 'help'.\r\n\r\n> ",
        )
        .await?;

    let mut line = [0u8; 160];
    let mut line_len = 0usize;
    let mut input = [0u8; 64];
    let mut telnet_state = TelnetState::Data;

    loop {
        let n = socket.read(&mut input).await?;
        if n == 0 {
            return Ok(());
        }

        for &byte in &input[..n] {
            match telnet_state {
                TelnetState::Data if byte == IAC => {
                    telnet_state = TelnetState::Iac;
                    continue;
                }
                TelnetState::Iac => {
                    telnet_state = match byte {
                        WILL | WONT => TelnetState::Option(DONT),
                        DO | DONT => TelnetState::Option(WONT),
                        _ => TelnetState::Data,
                    };
                    continue;
                }
                TelnetState::Option(reply_command) => {
                    socket.write_all(&[IAC, reply_command, byte]).await?;
                    telnet_state = TelnetState::Data;
                    continue;
                }
                TelnetState::Data => {}
            }

            match byte {
                b'\r' => {
                    socket.write_all(b"\r\n").await?;
                    let command = core::str::from_utf8(&line[..line_len]).unwrap_or("");
                    let keep_open =
                        run_command(socket, command.trim(), local_public_key, wall_clock).await?;
                    line_len = 0;
                    if !keep_open {
                        socket.write_all(b"bye\r\n").await?;
                        return Ok(());
                    }
                    socket.write_all(b"> ").await?;
                }
                b'\n' if line_len == 0 => {}
                b'\n' => {
                    let command = core::str::from_utf8(&line[..line_len]).unwrap_or("");
                    let keep_open =
                        run_command(socket, command.trim(), local_public_key, wall_clock).await?;
                    line_len = 0;
                    if !keep_open {
                        socket.write_all(b"bye\r\n").await?;
                        return Ok(());
                    }
                    socket.write_all(b"\r\n> ").await?;
                }
                0x08 | 0x7f if line_len != 0 => {
                    line_len -= 1;
                }
                0x20..=0x7e if line_len < line.len() => {
                    line[line_len] = byte;
                    line_len += 1;
                }
                _ => {}
            }
        }
    }
}

async fn run_command(
    socket: &mut TcpSocket<'_>,
    command: &str,
    local_public_key: &[u8; 32],
    wall_clock: WallClock,
) -> Result<bool, tcp::Error> {
    match command {
        "" => {}
        "help" | "?" => {
            socket
                .write_all(
                    b"help          show this command list\r\n\
                      status        show tunnel identity/address/uptime/time/heap\r\n\
                      key           show this node's WireGuard public key\r\n\
                      echo TEXT     echo text back\r\n\
                      quit          close the session\r\n",
                )
                .await?;
        }
        "key" => {
            let encoded = encode_key(local_public_key);
            socket.write_all(encoded.as_str().as_bytes()).await?;
            socket.write_all(b"\r\n").await?;
        }
        "status" => {
            let encoded = encode_key(local_public_key);
            let (wall_secs, _) = wall_clock.now();
            let memory = esp_alloc::HEAP.stats();
            let free_now = memory.size.saturating_sub(memory.current_usage);
            let used_percent = memory
                .current_usage
                .saturating_mul(100)
                .checked_div(memory.size)
                .unwrap_or_default();
            let mut text = String::<384>::new();
            let _ = write!(
                text,
                "chip=esp32-c3 arch=riscv32imc\r\n\
                 uptime={}ms unix={}\r\n\
                 heap={}B/{}B ({}%) free-now={}B\r\n\
                 key={}\r\n",
                EmbassyInstant::now().as_millis(),
                wall_secs,
                memory.current_usage,
                memory.size,
                used_percent,
                free_now,
                encoded.as_str(),
            );
            socket.write_all(text.as_bytes()).await?;
        }
        "quit" | "exit" => return Ok(false),
        _ if command.starts_with("echo ") => {
            socket.write_all(&command.as_bytes()[5..]).await?;
            socket.write_all(b"\r\n").await?;
        }
        _ => {
            socket.write_all(b"unknown command; try 'help'\r\n").await?;
        }
    }

    Ok(true)
}
