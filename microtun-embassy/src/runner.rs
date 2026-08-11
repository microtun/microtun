//! The tunnel runner: one task owns [`Core`] and drives it.
//!
//! Each selected async source maps to one named
//! [`Core`](microtun_core::Core) call. With `microtun-core/async`, the core
//! awaits the sink while its borrowed output remains valid, so encrypted UDP
//! datagrams and plaintext device packets are delivered directly without a
//! local ownership bridge or output queue.

use core::net::SocketAddr;

use defmt_or_log::{debug, info, trace, warn};
use embassy_futures::select::{Either4, select4};
use embassy_net::{
    IpEndpoint, Stack,
    udp::{PacketMetadata, UdpSocket},
};
use embassy_net_driver_channel::Runner as ChannelRunner;
use embassy_time::{Instant as EmbassyInstant, Timer};
use heapless::Deque;
use microtun_core::{
    Config, Core, Event, Instant, ResolveRequest, ResolverCommand, Sink, StaticRelayPolicy,
    ip::unmap_socket_addr,
};
use rand_core::{CryptoRng, RngCore};

use crate::resolver::{CommandSender, EventReceiver};

/// Tunnel (inner) MTU. 1280 is the IPv6 minimum link MTU and leaves ample
/// headroom for the outer transport and optional relay envelope.
pub const MTU: usize = 1280;

/// Maximum encrypted outer UDP payload.
pub const OUTER_SIZE: usize = microtun_core::MAX_UDP_SIZE;

/// Embedded peer/session/replay/route capacities.
pub const MAX_PEERS: usize = 8;
pub const MAX_SESSIONS: usize = 8;
/// Replay bitmap words per established session.
pub const REPLAY_WORDS: usize = 128;
pub const MAX_ROUTES: usize = 16;

/// Embedded post-cookie handshake rate limit. The core defaults match
/// wireguard-go; constrained embassy targets retain the project's tighter
/// sustained and burst policy through `CoreConfig`.
const RATE_LIMIT_PER_SEC: u32 = 2;
const RATE_LIMIT_BURST: u32 = 4;

/// Keep Embassy's active-table policy embedded-sized even when the optional
/// `alloc` backend moves the storage itself to the heap. `microtun-core/alloc`
/// deliberately has host-sized defaults; forwarding that feature must not turn
/// a small MCU into a host-sized deployment.
const RATE_LIMIT_ENTRIES: usize = 64;
const FIREWALL_FLOW_ENTRIES: usize = 16;
const FIREWALL_FLOWS_PER_PEER: usize = 8;

/// The concrete core type this runner drives.
pub type TunnelCore<RNG> =
    Core<RNG, StaticRelayPolicy, MAX_PEERS, MAX_SESSIONS, REPLAY_WORDS, MAX_ROUTES>;

/// Direct async destination for the core's borrowed packet outputs.
struct TunnelSink<'s, 'd, 'o, 'r> {
    device: &'s mut ChannelRunner<'d, MTU>,
    outer: &'s UdpSocket<'o>,
    resolver_commands: &'s CommandSender<'r>,
    pending_unwatches: &'s mut Deque<[u8; 32], MAX_PEERS>,
}

impl<'s, 'd, 'o, 'r> TunnelSink<'s, 'd, 'o, 'r> {
    fn new(
        device: &'s mut ChannelRunner<'d, MTU>,
        outer: &'s UdpSocket<'o>,
        resolver_commands: &'s CommandSender<'r>,
        pending_unwatches: &'s mut Deque<[u8; 32], MAX_PEERS>,
    ) -> Self {
        Self {
            device,
            outer,
            resolver_commands,
            pending_unwatches,
        }
    }

    fn flush_unwatches(&mut self) -> bool {
        while let Some(public_key) = self.pending_unwatches.front().copied() {
            if self
                .resolver_commands
                .try_send(ResolverCommand::Unwatch(public_key))
                .is_err()
            {
                return false;
            }
            self.pending_unwatches.pop_front();
        }
        true
    }
}

impl Sink for TunnelSink<'_, '_, '_, '_> {
    async fn outer_datagram(&mut self, destination: SocketAddr, datagram: &[u8]) {
        let destination = unmap_socket_addr(destination);
        match self
            .outer
            .send_to(datagram, socketaddr_to_endpoint(destination))
            .await
        {
            Ok(()) => trace!(
                "sent outer datagram: len={} port={}",
                datagram.len(),
                destination.port()
            ),
            Err(error) => warn!(
                "outer datagram send failed: len={} port={} error={:?}",
                datagram.len(),
                destination.port(),
                error
            ),
        }
    }

    async fn inner_packet(
        &mut self,
        _src_peer_key: &[u8; 32],
        _src_endpoint: Option<SocketAddr>,
        packet: &[u8],
    ) {
        if packet.len() > MTU {
            warn!(
                "dropping oversized inner packet: len={} capacity={}",
                packet.len(),
                MTU
            );
            return;
        }

        {
            let rx = self.device.rx_buf().await;
            if packet.len() > rx.len() {
                warn!(
                    "dropping oversized inner packet: len={} capacity={}",
                    packet.len(),
                    rx.len()
                );
                return;
            }
            rx[..packet.len()].copy_from_slice(packet);
        }
        self.device.rx_done(packet.len());
        trace!("delivered inner packet: len={}", packet.len());
    }

    fn resolve(&mut self, request: ResolveRequest) -> bool {
        self.flush_unwatches()
            && self
                .resolver_commands
                .try_send(ResolverCommand::Resolve(request))
                .is_ok()
    }

    fn event(&mut self, event: Event) {
        if let Event::PeerEvicted { public_key } = event {
            if (!self.flush_unwatches()
                || self
                    .resolver_commands
                    .try_send(ResolverCommand::Unwatch(public_key))
                    .is_err())
                && self.pending_unwatches.push_back(public_key).is_err()
            {
                warn!("pending unwatch queue full; dropping peer eviction");
            }
        }
    }
}

/// Owns the protocol state machine and its async transport plumbing.
pub struct TunnelRunner<'a, RNG: RngCore + CryptoRng> {
    engine: TunnelCore<RNG>,
    device: ChannelRunner<'a, MTU>,
    listen_port: u16,
    forwarding: bool,
}

impl<'a, RNG: RngCore + CryptoRng> TunnelRunner<'a, RNG> {
    pub fn new(
        mut config: Config<'_>,
        rng: RNG,
        device: ChannelRunner<'a, MTU>,
        listen_port: u16,
        now: Instant,
    ) -> Result<Self, microtun_core::Error> {
        // Tighten up the rate limits on embedded targets.
        config.core_config.rate_limit_per_sec = RATE_LIMIT_PER_SEC;
        config.core_config.rate_limit_burst = RATE_LIMIT_BURST;
        config.core_config.rate_limit_entries = RATE_LIMIT_ENTRIES;
        config.core_config.firewall_flow_entries = FIREWALL_FLOW_ENTRIES;
        config.core_config.firewall_flows_per_peer = FIREWALL_FLOWS_PER_PEER;

        info!(
            "creating embassy tunnel runner: listen_port={}",
            listen_port
        );
        Ok(Self {
            engine: Core::new(config, rng, StaticRelayPolicy::DenyAll, now)?,
            device,
            listen_port,
            forwarding: false,
        })
    }

    /// Opt in to forwarding type-5 relay packets between authenticated peers.
    pub fn enable_forwarding(&mut self, enabled: bool) {
        self.forwarding = enabled;
        info!("relay forwarding configured: enabled={}", enabled);
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.engine.public_key()
    }

    pub fn set_unix_time(&mut self, unix_secs: u64, nanos: u32, now: Instant) {
        self.engine.set_unix_time(unix_secs, nanos, now);
    }

    /// Run the tunnel forever.
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        mut self,
        outer_stack: Stack<'_>,
        resolve_tx: CommandSender<'_>,
        resolve_rx: EventReceiver<'_>,
        udp_rx_meta: &mut [PacketMetadata],
        udp_rx_buf: &mut [u8],
        udp_tx_meta: &mut [PacketMetadata],
        udp_tx_buf: &mut [u8],
    ) -> ! {
        let mut outer = UdpSocket::new(
            outer_stack,
            udp_rx_meta,
            udp_rx_buf,
            udp_tx_meta,
            udp_tx_buf,
        );
        outer.bind(self.listen_port).expect("bind outer UDP port");
        info!("embassy outer UDP socket bound: port={}", self.listen_port);

        self.device
            .set_link_state(embassy_net_driver_channel::driver::LinkState::Up);

        let mut outer_datagram = [0u8; OUTER_SIZE];
        let mut pending_unwatches = Deque::<[u8; 32], MAX_PEERS>::new();
        // Split the borrow once: the device is both an awaited event source
        // and a sink destination, so it cannot live inside a long-lived sink.
        let forwarding = self.forwarding;
        let engine = &mut self.engine;
        let device = &mut self.device;
        *engine.relay_policy_mut() = StaticRelayPolicy::forwarding(forwarding);

        loop {
            let poll_deadline = engine.poll_at();
            let timer = async {
                match poll_deadline {
                    Some(at) => Timer::at(to_embassy(at)).await,
                    None => core::future::pending::<()>().await,
                }
            };

            // `select4` is ordered. Put due protocol work first, then
            // resolver events, so a busy packet source cannot starve either
            // the session-maintenance path or resolver-channel backpressure.
            match select4(
                timer,
                resolve_rx.receive(),
                outer.recv_from(&mut outer_datagram),
                device.tx_buf(),
            )
            .await
            {
                // A protocol deadline came due.
                Either4::First(()) => {
                    let fired_at = now();
                    let mut sink =
                        TunnelSink::new(&mut *device, &outer, &resolve_tx, &mut pending_unwatches);
                    trace!("protocol timer fired");
                    if !engine.handle_timeout(fired_at, &mut sink).await {
                        trace!("protocol timer had no due work");
                    }
                }
                // The resolver task produced a lookup completion or watched-peer update.
                Either4::Second(response) => {
                    let mut sink =
                        TunnelSink::new(&mut *device, &outer, &resolve_tx, &mut pending_unwatches);
                    if engine
                        .resolver_event_completed(now(), response, &mut sink)
                        .await
                        .is_err()
                    {
                        debug!("core rejected resolver event");
                    }
                }
                // An encrypted datagram arrived on the outer network.
                Either4::Third(res) => {
                    if let Ok((n, meta)) = res {
                        trace!("outer UDP datagram received: len={}", n);
                        let source = endpoint_to_socketaddr(meta.endpoint);
                        let mut sink = TunnelSink::new(
                            &mut *device,
                            &outer,
                            &resolve_tx,
                            &mut pending_unwatches,
                        );
                        if engine
                            .receive_outer(now(), source, &mut outer_datagram[..n], &mut sink)
                            .await
                            .is_err()
                        {
                            debug!("core dropped inbound outer datagram");
                        }
                    }
                }
                // The inner stack wants to send a plaintext IP packet.
                Either4::Fourth(tx) => {
                    let n = tx.len().min(MTU);
                    trace!("inner packet queued by stack: len={}", n);
                    outer_datagram[..n].copy_from_slice(&tx[..n]);
                    device.tx_done();
                    let mut sink =
                        TunnelSink::new(&mut *device, &outer, &resolve_tx, &mut pending_unwatches);
                    if engine
                        .send_inner(now(), &outer_datagram[..n], &mut sink)
                        .await
                        .is_err()
                    {
                        debug!("core dropped outbound inner packet");
                    }
                }
            }

            while let Some(public_key) = pending_unwatches.front().copied() {
                if resolve_tx
                    .try_send(ResolverCommand::Unwatch(public_key))
                    .is_err()
                {
                    break;
                }
                pending_unwatches.pop_front();
            }
        }
    }
}

/// The core's monotonic clock, taken from embassy's.
#[inline]
fn now() -> Instant {
    Instant::from_millis(EmbassyInstant::now().as_millis())
}

#[inline]
fn to_embassy(at: Instant) -> EmbassyInstant {
    EmbassyInstant::from_millis(at.as_millis())
}

fn endpoint_to_socketaddr(endpoint: IpEndpoint) -> core::net::SocketAddr {
    unmap_socket_addr(core::net::SocketAddr::new(
        endpoint.addr.into(),
        endpoint.port,
    ))
}

fn socketaddr_to_endpoint(address: core::net::SocketAddr) -> IpEndpoint {
    let address = unmap_socket_addr(address);
    IpEndpoint::new(address.ip().into(), address.port())
}
