//! Shared secure-tunnel setup, runner, and dynamic peer resolver plumbing.

use core::net::{IpAddr, SocketAddr};

use defmt_or_log::info;
use embassy_net::{
    IpEndpoint, Ipv4Cidr, Ipv6Cidr, Runner, Stack, StackResources, StaticConfigV4, StaticConfigV6,
    udp::PacketMetadata,
};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, channel::Channel};
use embassy_time::Instant as EmbassyInstant;
use microtun_embassy::{
    RESOLVER_CHANNEL_DEPTH, ResolverBuffers, ResolverChannels, ResolverConfig, TunnelDevice,
    TunnelRunner, TunnelState, TunnelStatus,
    core::{
        Config as TunnelConfig, Duration, Instant, IpInet, PinnedPeer, ResolverCommand,
        ResolverEvent,
        device_config::DeviceConfig,
        firewall::InboundPolicy,
        ip::{host_cidr, parse_ip_inet},
        key::{decode_key, decode_key_into},
    },
    new_tunnel_with_mtu, resolver_task,
};
use rand_core::{CryptoRng, RngCore};

use crate::net::resolve_tracker_host;

pub const TUNNEL_QUEUE_DEPTH: usize = 4;
pub const OUTER_UDP_PACKETS: usize = 4;
pub const INNER_STACK_SOCKETS: usize = 5;
pub const LISTEN_PORT: u16 = 51820;

const RESOLVER_TCP_BUFFER: usize = 1024;
const PEERS_API_PORT: u16 = microtun_embassy::peers_api::PEERS_API_PORT;

static RESOLVER_COMMANDS: Channel<
    CriticalSectionRawMutex,
    ResolverCommand,
    RESOLVER_CHANNEL_DEPTH,
> = Channel::new();
static RESOLVER_EVENTS: Channel<CriticalSectionRawMutex, ResolverEvent, RESOLVER_CHANNEL_DEPTH> =
    Channel::new();

/// Result of constructing the common tunnel and its inner network stack.
pub struct Setup<R>
where
    R: RngCore + CryptoRng,
{
    pub runner: TunnelRunner<'static, R>,
    pub inner_stack: Stack<'static>,
    pub inner_runner: Runner<'static, TunnelDevice<'static>>,
    pub status: TunnelStatus<'static>,
    pub tracker_tunnel_addr: IpAddr,
}

/// Resolve the Tracker, construct the pinned peer, and create the tunnel's inner stack.
pub async fn setup<R>(
    outer_stack: Stack<'static>,
    inner_seed: u64,
    config: &DeviceConfig,
    rng: R,
    tunnel_state: &'static mut TunnelState<TUNNEL_QUEUE_DEPTH, TUNNEL_QUEUE_DEPTH>,
    inner_resources: &'static mut StackResources<INNER_STACK_SOCKETS>,
    unix_time: Option<(u64, u32)>,
) -> Setup<R>
where
    R: RngCore + CryptoRng,
{
    let tracker_outer_ip = resolve_tracker_host(outer_stack, config.tracker.host.as_str()).await;

    let tunnel_mtu = config.tunnel.mtu.map_or(microtun_embassy::MTU, usize::from);
    let (channel_runner, tunnel_device, status) = new_tunnel_with_mtu(tunnel_state, tunnel_mtu);
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

    let (inner_stack, inner_runner) =
        embassy_net::new(tunnel_device, inner_cfg, inner_resources, inner_seed);

    let tracker_tunnel = parse_ip_inet(config.tracker.tunnel_address.as_str())
        .expect("validated Tracker tunnel address");
    let tracker_tunnel_addr = tracker_tunnel.address();
    let tracker_public_key =
        decode_key(config.tracker.public_key.as_str()).expect("validated Tracker public key");
    let pinned = [PinnedPeer {
        public_key: tracker_public_key,
        endpoint: Some(SocketAddr::from((
            tracker_outer_ip.octets(),
            config.tracker.port,
        ))),
        relay: None,
        address: host_cidr(tracker_tunnel_addr),
        inbound_policy: InboundPolicy::EstablishedOnly,
        persistent_keepalive: Some(Duration::from_secs(25)),
    }];

    let mut private_key = [0u8; 32];
    decode_key_into(config.tunnel.private_key.as_str(), &mut private_key)
        .expect("validated device private key");

    let now = Instant::from_millis(EmbassyInstant::now().as_millis());
    let mut runner = TunnelRunner::new(
        TunnelConfig::new(private_key, &pinned),
        rng,
        channel_runner,
        status,
        LISTEN_PORT,
        config.tunnel.enable_forwarding,
        now,
    )
    .expect("create microtun runner");

    if let Some((unix_secs, unix_nanos)) = unix_time {
        runner.set_unix_time(unix_secs, unix_nanos, now);
    }

    Setup {
        runner,
        inner_stack,
        inner_runner,
        status,
        tracker_tunnel_addr,
    }
}

pub async fn run<R>(
    runner: TunnelRunner<'static, R>,
    outer_stack: Stack<'static>,
    udp_rx_meta: &mut [PacketMetadata],
    udp_rx_buf: &mut [u8],
    udp_tx_meta: &mut [PacketMetadata],
    udp_tx_buf: &mut [u8],
) -> !
where
    R: RngCore + CryptoRng,
{
    runner
        .run(
            outer_stack,
            RESOLVER_COMMANDS.sender(),
            RESOLVER_EVENTS.receiver(),
            udp_rx_meta,
            udp_rx_buf,
            udp_tx_meta,
            udp_tx_buf,
        )
        .await
}

/// Run the peer resolver with a 256-bit seed drawn from the platform RNG.
///
/// The resolver expands this with a CSPRNG and uses fresh entropy for every
/// WebSocket connection it opens.
pub async fn run_peer_resolver(
    inner_stack: Stack<'static>,
    local_public_key: [u8; 32],
    tracker_tunnel_addr: IpAddr,
    websocket_seed: [u8; 32],
) -> ! {
    let mut rx = [0u8; RESOLVER_TCP_BUFFER];
    let mut tx = [0u8; RESOLVER_TCP_BUFFER];

    let cfg = ResolverConfig {
        server: IpEndpoint::new(tracker_tunnel_addr.into(), PEERS_API_PORT),
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
        websocket_seed,
    )
    .await
}
