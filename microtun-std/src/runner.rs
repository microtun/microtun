//! Tokio tunnel runner.
//!
//! One task owns the [`Core`] and maps each selected event to one core call.
//! The supplied [`TunnelDevice`] is intentionally small: receive a plaintext
//! packet asynchronously, and inject a plaintext packet asynchronously.
//! Linux TUN, userspace IP stacks, and test harnesses can all adapt to that
//! contract.

use std::{
    collections::VecDeque, error::Error as StdError, fmt, future::Future, io, net::SocketAddr,
    time::Duration,
};

use microtun_core::{
    Config, Core, Event, Instant, MAX_PEER_ADDRESSES, ResolveRequest, ResolverCommand,
    ResolverEvent, Sink, StaticRelayPolicy, ip::unmap_socket_addr,
};
use rand_core::{CryptoRng, RngCore};
use tokio::{sync::mpsc, time::Instant as TokioInstant};

use crate::resolver::{PeersApiResolver, PeersApiTransport, resolver_task};

/// Maximum encrypted outer UDP payload.
pub const OUTER_SIZE: usize = microtun_core::MAX_UDP_SIZE;

/// Size of the buffer [`TunnelRunner::run`] reads outer datagrams into: one
/// byte more than the largest datagram the core will accept.
///
/// `recvfrom(2)` truncates a UDP datagram to the buffer it is given and
/// reports the truncated length, so reading into exactly [`OUTER_SIZE`] bytes
/// makes an oversized datagram indistinguishable from a well-formed one — it
/// then fails length classification or the transport AEAD further in, and a
/// path-MTU misconfiguration presents as unexplained packet loss rather than
/// as an error. The spare byte restores the signal: a read that fills the
/// buffer had more to give.
///
/// This stands in for `MSG_TRUNC`, which `tokio::net::UdpSocket` does not
/// expose and which would require `libc` and an `unsafe` block that this
/// crate forbids. It is also portable, where `MSG_TRUNC` is Linux-only.
const OUTER_RECV_SIZE: usize = OUTER_SIZE + 1;

/// Maximum buffer passed to a host tunnel device for one IP packet.
pub const MAX_IP_PACKET_SIZE: usize = u16::MAX as usize + 1;

// Host peer/session/replay/route capacities.
//
// This crate enables `microtun-core/alloc`, so these are upper bounds on
// heap-backed pools rather than the lengths of inline arrays: a `TunnelCore`
// is small enough to move around freely and does not have to be boxed or
// placed in a `static`. They are still real limits — a full peer table evicts
// the least-recently-active dynamic peer, and a full route cache is an error —
// so they are sized for a host rather than made unbounded.
//
// The index-addressed pools are allocated at their full length when the core
// is built, so raising these trades a one-off heap allocation (roughly
// `MAX_PEERS` × 200 B plus `MAX_SESSIONS` × roughly 1.2 KiB with
// `REPLAY_WORDS = 128`)
// for headroom, and costs nothing on the stack.

/// Maximum number of peers, including pinned and dynamically resolved peers.
pub const MAX_PEERS: usize = 128;
/// Maximum number of session slots, shared by handshakes and live sessions.
pub const MAX_SESSIONS: usize = 256;
/// Replay bitmap words per established session. 128 matches the reference
/// implementations' 8,128-counter trailing window.
pub const REPLAY_WORDS: usize = 128;
/// Default route-cache sizing for the host runner. Resolver answers may carry
/// more than four unique prefixes, but the core still admits at most this many
/// routes overall.
pub const MAX_ROUTES: usize = MAX_PEERS * MAX_PEER_ADDRESSES;
/// Bounded request and response queue depth used by [`TunnelRunner::run`].
pub const RESOLVER_QUEUE_DEPTH: usize = 8;

/// The concrete core type driven by the standard-runtime runner.
pub type TunnelCore<RNG> =
    Core<RNG, StaticRelayPolicy, MAX_PEERS, MAX_SESSIONS, REPLAY_WORDS, MAX_ROUTES>;

/// Plaintext packet device used by [`TunnelRunner`].
///
/// Both operations may wait for transport capacity. `send` receives the
/// authenticated source peer key and, for direct peers, the outer UDP source
/// that carried the packet. The async core feature keeps the borrowed packet
/// valid until `send` completes, so runtimes can apply backpressure instead of
/// copying or dropping it.
pub trait TunnelDevice {
    async fn recv(&self, packet: &mut [u8]) -> io::Result<usize>;
    async fn send(
        &self,
        src_peer_key: &[u8; 32],
        src_endpoint: Option<SocketAddr>,
        packet: &[u8],
    ) -> io::Result<usize>;
}

/// Synchronous runtime observations emitted by the tunnel engine.
///
/// Observers must return promptly: callbacks run inline with authenticated
/// packet processing. Applications that need asynchronous work should update a
/// shared latest-value store or use a non-blocking queue from the callback.
pub trait TunnelObserver: Send + Sync {
    /// Observe one runtime event from [`microtun_core::Core`].
    fn event(&self, _event: Event) {}
}

impl TunnelObserver for () {}

/// Errors produced while constructing or running a host tunnel.
#[derive(Debug)]
pub enum Error {
    Core(microtun_core::Error),
    Io(io::Error),
    ResolverExited,
    ResolverTask(tokio::task::JoinError),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(error) => write!(formatter, "core error: {error:?}"),
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::ResolverExited => formatter.write_str("resolver task exited unexpectedly"),
            Self::ResolverTask(error) => write!(formatter, "resolver task failed: {error}"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::ResolverTask(error) => Some(error),
            Self::Core(_) | Self::ResolverExited => None,
        }
    }
}

impl From<microtun_core::Error> for Error {
    fn from(error: microtun_core::Error) -> Self {
        Self::Core(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

struct TunnelSink<'a, D> {
    device: &'a D,
    outer: &'a tokio::net::UdpSocket,
    observer: &'a dyn TunnelObserver,
    resolver_commands: &'a mpsc::Sender<ResolverCommand>,
    pending_unwatches: &'a mut VecDeque<[u8; 32]>,
}

impl<'a, D> TunnelSink<'a, D> {
    fn new(
        device: &'a D,
        outer: &'a tokio::net::UdpSocket,
        observer: &'a dyn TunnelObserver,
        resolver_commands: &'a mpsc::Sender<ResolverCommand>,
        pending_unwatches: &'a mut VecDeque<[u8; 32]>,
    ) -> Self {
        Self {
            device,
            outer,
            observer,
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

impl<D: TunnelDevice> Sink for TunnelSink<'_, D> {
    async fn outer_datagram(&mut self, destination: SocketAddr, datagram: &[u8]) {
        let destination = unmap_socket_addr(destination);
        let socket_destination = self.outer.local_addr().map_or(destination, |local| {
            destination_for_socket(local, destination)
        });
        log::trace!(
            "sending UDP datagram to {destination}: {} bytes",
            datagram.len()
        );
        match self.outer.send_to(datagram, socket_destination).await {
            Ok(length) if length != datagram.len() => {
                log::warn!(
                    "short UDP send to {destination}: wrote {length} of {} bytes",
                    datagram.len()
                );
            }
            Ok(_) => log::trace!(
                "sent UDP datagram to {destination}: {} bytes",
                datagram.len()
            ),
            Err(error) => log::warn!("UDP output to {destination} failed: {error}"),
        }
    }

    async fn inner_packet(
        &mut self,
        src_peer_key: &[u8; 32],
        src_endpoint: Option<SocketAddr>,
        packet: &[u8],
    ) {
        match self.device.send(src_peer_key, src_endpoint, packet).await {
            Ok(length) if length != packet.len() => {
                log::warn!(
                    "short inner packet write: wrote {length} of {} bytes",
                    packet.len()
                );
            }
            Ok(_) => log::trace!("delivered inner packet: {} bytes", packet.len()),
            Err(error) => log::warn!("inner packet delivery failed: {error}"),
        }
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
            if !self.flush_unwatches()
                || self
                    .resolver_commands
                    .try_send(ResolverCommand::Unwatch(public_key))
                    .is_err()
            {
                self.pending_unwatches.push_back(public_key);
            }
        }
        self.observer.event(event);
    }
}

/// Owns the protocol state machine and its Tokio transport plumbing.
pub struct TunnelRunner<D, RNG: RngCore + CryptoRng> {
    engine: TunnelCore<RNG>,
    device: D,
    outer: tokio::net::UdpSocket,
    clock_base: TokioInstant,
    observer: Box<dyn TunnelObserver>,
}

impl<D, RNG> fmt::Debug for TunnelRunner<D, RNG>
where
    RNG: RngCore + CryptoRng,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TunnelRunner")
            .field("outer", &self.outer)
            .field("clock_base", &self.clock_base)
            .finish_non_exhaustive()
    }
}

impl<D, RNG> TunnelRunner<D, RNG>
where
    D: TunnelDevice,
    RNG: RngCore + CryptoRng,
{
    /// Construct a runner around an already-bound outer UDP socket.
    pub fn new(
        config: Config<'_>,
        rng: RNG,
        device: D,
        outer: tokio::net::UdpSocket,
    ) -> Result<Self, Error> {
        let clock_base = TokioInstant::now();
        log::info!("constructing tunnel runner");
        let engine = Core::new(config, rng, StaticRelayPolicy::DenyAll, now(clock_base))?;
        Ok(Self {
            engine,
            device,
            outer,
            clock_base,
            observer: Box::new(()),
        })
    }

    /// Bind an outer UDP socket and construct a runner.
    pub async fn bind(
        config: Config<'_>,
        rng: RNG,
        device: D,
        listen: SocketAddr,
    ) -> Result<Self, Error> {
        let listen = unmap_socket_addr(listen);
        log::debug!("binding outer UDP socket on {listen}");
        let outer = tokio::net::UdpSocket::bind(listen).await?;
        Self::new(config, rng, device, outer)
    }

    /// Opt in to forwarding type-5 relay packets between authenticated peers.
    pub fn enable_forwarding(&mut self, enabled: bool) {
        *self.engine.relay_policy_mut() = StaticRelayPolicy::forwarding(enabled);
        log::info!("relay forwarding configured: {enabled}");
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.engine.public_key()
    }

    /// Install a synchronous observer for authenticated runtime state changes.
    pub fn with_observer(mut self, observer: impl TunnelObserver + 'static) -> Self {
        self.observer = Box::new(observer);
        self
    }

    /// Supply wall-clock time for handshake timestamps.
    pub fn set_unix_time(&mut self, unix_secs: u64, nanos: u32) {
        log::debug!("updating core wall clock: unix_secs={unix_secs} nanos={nanos}");
        self.engine
            .set_unix_time(unix_secs, nanos, now(self.clock_base));
    }

    /// Run the tunnel until `shutdown` completes or an I/O task fails.
    ///
    /// A resolver task is created automatically. One long-lived Peers API server
    /// connection carries ordinary lookups and dynamic-peer watch updates.
    /// Resolve requests use the sink's non-blocking acceptance callback; peer
    /// eviction events are translated into unwatch commands and retained by the
    /// runner until the bounded resolver channel accepts them.
    pub async fn run<S, T>(self, resolver: PeersApiResolver<T>, shutdown: S) -> Result<(), Error>
    where
        S: Future<Output = io::Result<()>>,
        T: PeersApiTransport,
    {
        let (resolve_tx, resolve_requests) = mpsc::channel::<ResolverCommand>(RESOLVER_QUEUE_DEPTH);
        let (resolve_responses, resolve_rx) = mpsc::channel::<ResolverEvent>(RESOLVER_QUEUE_DEPTH);
        log::info!("starting tunnel and resolver tasks");
        let resolver_task =
            tokio::spawn(resolver_task(resolver, resolve_requests, resolve_responses));

        self.run_with_resolver_task(resolve_tx, resolve_rx, resolver_task, shutdown)
            .await
    }

    /// Run a tunnel whose complete peer set is pinned at startup.
    ///
    /// No Peers API resolver task is started; unresolved dynamic lookups are dropped.
    pub async fn run_pinned<S>(self, shutdown: S) -> Result<(), Error>
    where
        S: Future<Output = io::Result<()>>,
    {
        let (resolve_tx, _resolve_requests) = mpsc::channel::<ResolverCommand>(1);
        let (_resolve_responses, resolve_rx) = mpsc::channel::<ResolverEvent>(1);
        let resolver_task = tokio::spawn(std::future::pending::<()>());
        self.run_with_resolver_task(resolve_tx, resolve_rx, resolver_task, shutdown)
            .await
    }

    /// Run with caller-provided resolver channels and task.
    ///
    /// This mirrors the explicit task wiring exposed by `microtun-embassy` and
    /// is useful for custom resolvers. The command sender must be bounded:
    /// resolve requests are accepted non-blockingly, while unwatch commands are
    /// derived from peer-eviction events and retried by the runner if needed.
    pub async fn run_with_resolver_task<S>(
        mut self,
        resolve_tx: mpsc::Sender<ResolverCommand>,
        mut resolve_rx: mpsc::Receiver<ResolverEvent>,
        mut resolver_task: tokio::task::JoinHandle<()>,
        shutdown: S,
    ) -> Result<(), Error>
    where
        S: Future<Output = io::Result<()>>,
    {
        let mut inner_packet = vec![0u8; MAX_IP_PACKET_SIZE];
        let mut outer_datagram = vec![0u8; OUTER_RECV_SIZE];
        let mut pending_unwatches = VecDeque::new();

        let engine = &mut self.engine;
        let device = &self.device;
        let outer = &self.outer;
        let observer = &*self.observer;
        let clock_base = self.clock_base;
        tokio::pin!(shutdown);

        loop {
            let poll_deadline = engine.poll_at();
            let timer = async {
                match poll_deadline {
                    Some(at) => {
                        let target = clock_base + Duration::from_millis(at.as_millis());
                        tokio::time::sleep_until(target).await;
                    }
                    None => std::future::pending::<()>().await,
                }
            };

            tokio::select! {
                result = outer.recv_from(&mut outer_datagram) => {
                    match result {
                        Ok((length, source)) => {
                            let source = unmap_socket_addr(source);
                            log::trace!(
                                "received outer datagram from {source}: {length} bytes"
                            );
                            // A read that fills OUTER_RECV_SIZE was truncated: the
                            // datagram was larger than anything the core accepts, and
                            // the bytes beyond the buffer are gone. Drop it here and
                            // say so, rather than passing a silently shortened packet
                            // down to fail authentication for the wrong reason.
                            if length > OUTER_SIZE {
                                log::debug!(
                                    "dropping oversized outer datagram from {source}: \
                                     more than {OUTER_SIZE} bytes"
                                );
                            } else {
                                let mut sink = TunnelSink::new(
                                    device,
                                    outer,
                                    observer,
                                    &resolve_tx,
                                    &mut pending_unwatches,
                                );
                                if let Err(error) = engine
                                    .receive_outer(
                                        now(clock_base),
                                        source,
                                        &mut outer_datagram[..length],
                                        &mut sink,
                                    )
                                    .await
                                {
                                    log::debug!("inbound datagram dropped: {error:?}");
                                }
                            }
                        }
                        Err(error) => {
                            // UDP receive failures are packet-level/transient errors.
                            // Keep the socket runner alive and retry on the next loop.
                            log::warn!("UDP receive failed; retrying: {error}");
                        }
                    }
                }
                result = device.recv(&mut inner_packet) => {
                    let length = result?;
                    log::trace!("received inner packet from device: {length} bytes");
                    if length > inner_packet.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "tunnel device returned a packet length larger than its buffer",
                        ).into());
                    }
                    let mut sink = TunnelSink::new(
                        device,
                        outer,
                        observer,
                        &resolve_tx,
                        &mut pending_unwatches,
                    );
                    if let Err(error) = engine
                        .send_inner(
                            now(clock_base),
                            &inner_packet[..length],
                            &mut sink,
                        )
                        .await
                    {
                        log::debug!("outbound packet dropped: {error:?}");
                    }
                }
                Some(response) = resolve_rx.recv() => {
                    let mut sink = TunnelSink::new(
                        device,
                        outer,
                        observer,
                        &resolve_tx,
                        &mut pending_unwatches,
                    );
                    if let Err(error) = engine
                        .resolver_event_completed(now(clock_base), response, &mut sink)
                        .await
                    {
                        log::debug!("resolver event dropped: {error:?}");
                    }
                }
                _ = timer => {
                    let fired_at = now(clock_base);
                    log::trace!("core protocol timer fired");
                    let mut sink = TunnelSink::new(
                        device,
                        outer,
                        observer,
                        &resolve_tx,
                        &mut pending_unwatches,
                    );
                    if !engine.handle_timeout(fired_at, &mut sink).await {
                        log::trace!("core protocol timer had no due work");
                    }
                }
                result = &mut shutdown => {
                    result?;
                    log::info!("shutdown requested; stopping resolver task");
                    resolver_task.abort();
                    return Ok(());
                }
                result = &mut resolver_task => {
                    return match result {
                        Ok(()) => {
                            log::error!("resolver task exited unexpectedly");
                            Err(Error::ResolverExited)
                        }
                        Err(error) => {
                            log::error!("resolver task failed: {error}");
                            Err(Error::ResolverTask(error))
                        }
                    };
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

#[inline]
fn now(clock_base: TokioInstant) -> Instant {
    Instant::from_millis(clock_base.elapsed().as_millis() as u64)
}

/// Adapt a canonical destination to the address family of the actual socket.
///
/// The core and public runtime boundaries keep IPv4 peers as native IPv4, but
/// an already-bound dual-stack IPv6 socket must receive a mapped destination
/// at the final syscall boundary. Nothing stores or compares this temporary
/// transport representation.
fn destination_for_socket(local: SocketAddr, destination: SocketAddr) -> SocketAddr {
    match (local, destination) {
        (SocketAddr::V6(_), SocketAddr::V4(v4)) => {
            SocketAddr::new((*v4.ip()).to_ipv6_mapped().into(), v4.port())
        }
        (_, destination) => destination,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_socket_maps_native_ipv4_only_at_send_boundary() {
        let local = "[::]:51820".parse().unwrap();
        let destination = "192.0.2.7:41414".parse().unwrap();

        assert_eq!(
            destination_for_socket(local, destination),
            "[::ffff:192.0.2.7]:41414".parse().unwrap()
        );

        let ipv4_local = "0.0.0.0:51820".parse().unwrap();
        assert_eq!(destination_for_socket(ipv4_local, destination), destination);
    }
}
