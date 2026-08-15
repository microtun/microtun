#![no_std]
#![no_main]

use core::{
    fmt::Write as _,
    net::{IpAddr, SocketAddr},
};

use chrono::Datelike;
use defmt::{info, warn};
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_net::{
    IpAddress, IpEndpoint, Ipv4Address, Ipv4Cidr, Ipv6Cidr, Stack, StackResources, StaticConfigV4,
    StaticConfigV6,
    dns::DnsQueryType,
    tcp::{self, TcpSocket},
    udp::{PacketMetadata, UdpSocket},
};
use embassy_stm32::{
    Config, bind_interrupts, eth,
    flash::{Blocking, Flash},
    eth::{Ethernet, GenericPhy, PacketQueue, Sma},
    peripherals::{self, ETH, ETH_SMA, RNG},
    rng::{self, Rng},
    rtc::{DateTime as RtcDateTime, Rtc, RtcConfig, RtcTimeProvider},
};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, channel::Channel};
use embassy_time::{Duration as EmbassyDuration, Instant as EmbassyInstant, Timer, with_timeout};
use embedded_io_async::Write as _;
use heapless::String;
use microtun_embassy::{
    ResolverBuffers, ResolverChannels, ResolverConfig, TunnelDevice, TunnelRunner, TunnelState,
    core::{
        Config as TunnelConfig, Duration, Instant, IpInet, PinnedPeer, ResolverCommand,
        ResolverEvent,
        firewall::InboundPolicy,
        ip::{host_cidr, parse_ip_inet},
        key::{decode_key, decode_key_into, encode_key},
    },
    new_tunnel_with_mtu, resolver_task,
    RESOLVER_CHANNEL_DEPTH,
};
use microtun_device_config::{ProvisionRecord, RECORD_SIZE, decode_record};
use panic_probe as _;
use sntpc::{NtpContext, NtpTimestampGenerator, get_time};
use sntpc_net_embassy::UdpSocketWrapper;
use static_cell::StaticCell;


bind_interrupts!(struct Irqs {
    ETH => eth::InterruptHandler;
    HASH_RNG => rng::InterruptHandler<peripherals::RNG>;
});

type OuterDevice = Ethernet<'static, ETH, GenericPhy<Sma<'static, ETH_SMA>>>;
type InnerDevice = TunnelDevice<'static>;
type HardwareRng = Rng<'static, RNG>;

const TUNNEL_QUEUE_DEPTH: usize = 4;
const OUTER_UDP_PACKETS: usize = 4;
const RESOLVER_TCP_BUFFER: usize = 1024;
const TELNET_TCP_BUFFER: usize = 1024;
const TCP_KEEP_ALIVE: EmbassyDuration = EmbassyDuration::from_secs(15);
const TCP_IDLE_TIMEOUT: EmbassyDuration = EmbassyDuration::from_secs(45);
const NTP_PACKET_BUFFER: usize = 128;
const LISTEN_PORT: u16 = 51820;
const PEERS_API_PORT: u16 = 80;
const TELNET_PORT: u16 = 23;
const NTP_LOCAL_PORT: u16 = 49152;
const PROVISION_OFFSET: u32 = 0x001e_0000;

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

    runner
        .run(
            outer_stack,
            RESOLVER_COMMANDS.sender(),
            RESOLVER_EVENTS.receiver(),
            rx_meta,
            rx,
            tx_meta,
            tx,
        )
        .await
}

#[embassy_executor::task]
async fn peers_resolver_task(
    inner_stack: Stack<'static>,
    local_public_key: [u8; 32],
    api_server_tunnel_addr: IpAddr,
) -> ! {
    let mut rx = [0u8; RESOLVER_TCP_BUFFER];
    let mut tx = [0u8; RESOLVER_TCP_BUFFER];

    let cfg = ResolverConfig {
        server: IpEndpoint::new(api_server_tunnel_addr.into(), PEERS_API_PORT),
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
    rtc_time: RtcTimeProvider,
) -> ! {
    let mut rx = [0u8; TELNET_TCP_BUFFER];
    let mut tx = [0u8; TELNET_TCP_BUFFER];

    loop {
        let mut socket = TcpSocket::new(inner_stack, &mut rx, &mut tx);
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
        if let Err(error) = telnet_session(&mut socket, &local_public_key, &rtc_time).await {
            warn!("telnet session ended with error: {:?}", error);
        }
        socket.close();
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) -> ! {
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
    let provision = {
        let mut flash = Flash::new_blocking(p.FLASH);
        load_provisioning(&mut flash)
    };
    info!(
        "loaded provisioning for tunnel {}",
        provision.config.tunnel.tunnel_address.as_str()
    );
    let config = provision.config;

    let (mut rtc, rtc_time) = Rtc::new(p.RTC, RtcConfig::default());
    let mut rng = Rng::new(p.RNG, Irqs);

    let outer_seed = rng.next_u64();
    let inner_seed = rng.next_u64();
    let mut mac = [0u8; 6];
    rng.fill_bytes(&mut mac);
    // Locally administered + unicast. Generate this per boot for a demo; use a
    // stable unique MAC in a product so DHCP leases remain stable.
    mac[0] = (mac[0] | 0x02) & !0x01;

    static ETH_PACKETS: StaticCell<PacketQueue<4, 4>> = StaticCell::new();
    let ethernet = Ethernet::new(
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
        p.ETH_SMA,
        p.PA2, // RMII MDIO
        p.PC1, // RMII MDC
    );

    static OUTER_RESOURCES: StaticCell<StackResources<6>> = StaticCell::new();
    let (outer_stack, outer_runner) = embassy_net::new(
        ethernet,
        embassy_net::Config::dhcpv4(Default::default()),
        OUTER_RESOURCES.init(StackResources::new()),
        outer_seed,
    );
    spawner.spawn(outer_net_task(outer_runner).unwrap());

    info!("waiting for wired Ethernet DHCP");
    outer_stack.wait_config_up().await;
    info!("wired Ethernet DHCP lease acquired");

    let wall_clock = if let Some(ntp) = config.ntp.as_ref() {
        Some(
            sync_rtc_from_ntp(outer_stack, &mut rtc, &rtc_time, ntp.host.as_str(), ntp.port).await,
        )
    } else {
        info!("NTP not configured; using the current STM32 RTC value");
        rtc_unix_time(&rtc_time)
    };

    let api_server_outer_ip =
        resolve_api_server_host(outer_stack, config.api_server.host.as_str()).await;

    let tunnel_mtu = config
        .tunnel
        .mtu
        .map_or(microtun_embassy::MTU, usize::from);
    static TUNNEL_STATE: StaticCell<TunnelState<TUNNEL_QUEUE_DEPTH, TUNNEL_QUEUE_DEPTH>> =
        StaticCell::new();
    let (channel_runner, tunnel_device) = new_tunnel_with_mtu(
        TUNNEL_STATE.init(TunnelState::<TUNNEL_QUEUE_DEPTH, TUNNEL_QUEUE_DEPTH>::new()),
        tunnel_mtu,
    );
    info!("inner tunnel MTU: {}", tunnel_mtu);

    let local_tunnel_address = parse_ip_inet(config.tunnel.tunnel_address.as_str())
        .expect("validated local tunnel address");
    let inner_cfg = match local_tunnel_address {
        IpInet::V4(address) => embassy_net::Config::ipv4_static(StaticConfigV4 {
            address: Ipv4Cidr::new(address.address(), address.network_length()),
            gateway: None,
            dns_servers: Default::default(),
        }),
        IpInet::V6(address) => embassy_net::Config::ipv6_static(StaticConfigV6 {
            address: Ipv6Cidr::new(address.address(), address.network_length()),
            gateway: None,
            dns_servers: Default::default(),
        }),
    };

    static INNER_RESOURCES: StaticCell<StackResources<4>> = StaticCell::new();
    let (inner_stack, inner_runner) = embassy_net::new(
        tunnel_device,
        inner_cfg,
        INNER_RESOURCES.init(StackResources::new()),
        inner_seed,
    );
    spawner.spawn(inner_net_task(inner_runner).unwrap());

    let api_server_tunnel = parse_ip_inet(config.api_server.tunnel_address.as_str())
        .expect("validated API server tunnel address");
    let api_server_tunnel_addr = api_server_tunnel.address();
    let api_inner = host_cidr(api_server_tunnel_addr);
    let api_server_public_key = decode_key(config.api_server.public_key.as_str())
        .expect("validated API server public key");
    let pinned = [PinnedPeer {
        public_key: api_server_public_key,
        endpoint: Some(SocketAddr::from((
            api_server_outer_ip.octets(),
            config.api_server.port,
        ))),
        relay: None,
        address: api_inner,
        // The Peers API server is a client destination, not an unsolicited
        // service source for this board.
        inbound_policy: InboundPolicy::EstablishedOnly,
        persistent_keepalive: Some(Duration::from_secs(25)),
    }];

    let mut private_key = [0u8; 32];
    decode_key_into(config.tunnel.private_key.as_str(), &mut private_key)
        .expect("validated device private key");

    let now = Instant::from_millis(EmbassyInstant::now().as_millis());
    let mut tunnel = TunnelRunner::new(
        TunnelConfig::new(private_key, &pinned),
        rng,
        channel_runner,
        LISTEN_PORT,
        config.tunnel.enable_forwarding,
        now,
    )
    .expect("create microtun runner");

    if let Some((rtc_unix_secs, rtc_unix_nanos)) = wall_clock {
        tunnel.set_unix_time(rtc_unix_secs, rtc_unix_nanos, now);
    } else {
        warn!("no usable wall clock is available to microtun");
    }
    let local_public_key = tunnel.public_key();
    info!("microtun tunnel ready; telnet is only on the inner stack");

    spawner.spawn(tunnel_task(tunnel, outer_stack).unwrap());
    spawner
        .spawn(
            peers_resolver_task(
                inner_stack,
                local_public_key,
                api_server_tunnel_addr,
            )
            .unwrap(),
        );
    spawner.spawn(telnet_task(inner_stack, local_public_key, rtc_time).unwrap());

    core::future::pending().await
}


static PROVISION_RECORD_BUFFER: StaticCell<[u8; RECORD_SIZE]> = StaticCell::new();

fn load_provisioning(flash: &mut Flash<'_, Blocking>) -> ProvisionRecord {
    let record = PROVISION_RECORD_BUFFER.init([0u8; RECORD_SIZE]);
    if let Err(error) = flash.blocking_read(PROVISION_OFFSET, record) {
        panic!("failed to read provisioning record: {:?}", error);
    }

    decode_record(record).unwrap_or_else(|error| {
        panic!(
            "device is not provisioned or record is invalid ({:?})",
            error
        )
    })
}

#[derive(Clone, Copy)]
struct BootTimestampGenerator {
    sample: EmbassyInstant,
}

// sntpc only needs an approximate Unix time to select the correct 2^32-second
// NTP era. 2050 is within ~50 years of every year the STM32 RTC can represent
// (2000..=2099), so no configurable era pivot is needed. Uptime supplies the
// changing part used for request/response timing.
const NTP_ERA_PIVOT_UNIX_SECS: u64 = 2_524_608_000; // 2050-01-01 00:00:00 UTC

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

async fn resolve_api_server_host(stack: Stack<'static>, host: &str) -> Ipv4Address {
    if let Ok(address) = host.parse::<core::net::Ipv4Addr>() {
        let octets = address.octets();
        return Ipv4Address::new(octets[0], octets[1], octets[2], octets[3]);
    }

    loop {
        info!("resolving API server host {}", host);
        let addresses = match with_timeout(
            EmbassyDuration::from_secs(5),
            stack.dns_query(host, DnsQueryType::A),
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
                host,
                address
            );
            return address;
        }

        warn!("API server DNS lookup returned no IPv4 address");
        Timer::after_secs(2).await;
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
        info!("resolving NTP server {}", host);
        let addresses = match with_timeout(
            EmbassyDuration::from_secs(5),
            stack.dns_query(host, DnsQueryType::A),
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
        if let Err(error) = socket.bind(NTP_LOCAL_PORT) {
            warn!("NTP UDP bind failed: {:?}", error);
            Timer::after_secs(2).await;
            continue;
        }

        let server = SocketAddr::new(IpAddr::V4(server_ip), port);
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
enum TelnetState {
    Data,
    Iac,
    Option(u8),
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

async fn telnet_session(
    socket: &mut TcpSocket<'_>,
    local_public_key: &[u8; 32],
    rtc_time: &RtcTimeProvider,
) -> Result<(), tcp::Error> {
    const IAC: u8 = 255;
    const WILL: u8 = 251;
    const WONT: u8 = 252;
    const DO: u8 = 253;
    const DONT: u8 = 254;

    socket
        .write_all(
            b"\r\nmicrotun NUCLEO-H753ZI shell\r\n\
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
                        run_command(socket, command.trim(), local_public_key, rtc_time).await?;
                    line_len = 0;
                    if !keep_open {
                        socket.write_all(b"bye\r\n").await?;
                        return Ok(());
                    }
                    socket.write_all(b"> ").await?;
                }
                b'\n' if line_len == 0 => {
                    // Consume the LF half of a normal TELNET CRLF pair.
                }
                b'\n' => {
                    let command = core::str::from_utf8(&line[..line_len]).unwrap_or("");
                    let keep_open =
                        run_command(socket, command.trim(), local_public_key, rtc_time).await?;
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
    rtc_time: &RtcTimeProvider,
) -> Result<bool, tcp::Error> {
    match command {
        "" => {}
        "help" | "?" => {
            socket
                .write_all(
                    b"help          show this command list\r\n\
                      status        show tunnel identity/address/uptime/RAM\r\n\
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
            let rtc_unix = rtc_unix_time(rtc_time).map(|(secs, _)| secs).unwrap_or(0);
            let memory = memory_usage();
            let used = memory.static_used.saturating_add(memory.stack_used);
            let used_percent = used
                .saturating_mul(100)
                .checked_div(memory.total)
                .unwrap_or(0);
            let mut text = String::<384>::new();
            let _ = write!(
                text,
                "chip=stm32h753zi arch=thumbv7em\r\n\
                 uptime={}ms rtc-unix={}\r\n\
                 ram={}B/{}B ({}%) static={}B stack-now={}B free-now={}B\r\n\
                 key={}\r\n",
                EmbassyInstant::now().as_millis(),
                rtc_unix,
                used,
                memory.total,
                used_percent,
                memory.static_used,
                memory.stack_used,
                memory.free_now,
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
