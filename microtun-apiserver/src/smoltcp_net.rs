//! A virtual TCP listener on top of the tunnel device.
//!
//! `microtun-std` hands this module decrypted, cryptokey-routed IP packets
//! together with the static public key of the peer whose session carried them
//! and, for direct peers, that packet's authenticated outer UDP source. smoltcp
//! turns those into TCP streams, and the RPC layer serves JSON-RPC
//! over the streams. What this module has to preserve across that boundary is
//! the *identity*: an accepted stream must carry the key of the peer that
//! opened it, because that key is the only thing the RPC layer admits on.
//!
//! # How the key survives the trip through smoltcp
//!
//! A connection is identified by the endpoint that opened it. On the way in,
//! every packet carrying a bare `SYN` has its source address and port recorded
//! against the peer key and authenticated outer UDP endpoint that delivered
//! it; on accept, the established socket's remote endpoint is looked up in that
//! table and the entry removed. The table is bounded and evicts oldest-first,
//! so half-open attempts cannot grow it.
//!
//! Endpoints are unambiguous here for the same reason source addresses are
//! trustworthy at all: the core drops any inner packet whose source is not one
//! the sending peer owns, so a recorded `(address, port)` cannot have been
//! forged by a different peer while the first peer holds it.
//!
//! The alternative — tagging whichever socket happens to reach `Established`
//! during the poll that consumed a given packet — forces the device to consume
//! exactly one packet per poll, which is both a throughput ceiling and a
//! correctness property that nothing in the type system enforces. Endpoints
//! need neither.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use microtun_std::{
    TunnelDevice,
    core::{IpCidr, MAX_INNER_SIZE},
};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device as PhyDevice, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{Socket, SocketBuffer, State as TcpState},
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::{
        HardwareAddress, IpAddress, IpCidr as SmolIpCidr, IpListenEndpoint, IpProtocol, Ipv4Packet,
        Ipv6Packet, TcpPacket,
    },
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex as AsyncMutex, Notify, mpsc},
    time::{Duration, Instant},
};

const TCP_RX_BUFFER: usize = 16 * 1024;
const TCP_TX_BUFFER: usize = 16 * 1024;
const STACK_QUEUE_DEPTH: usize = 64;
const SMOLTCP_POLL_INTERVAL: Duration = Duration::from_millis(10);
const TCP_KEEP_ALIVE: SmolDuration = SmolDuration::from_secs(15);
const TCP_IDLE_TIMEOUT: SmolDuration = SmolDuration::from_secs(45);

/// How many connection attempts may be awaiting accept before the oldest is
/// forgotten. A peer that opens connections and never completes them can only
/// cost this much memory, and only its own entries are at risk of eviction
/// once it exceeds the whole listener backlog on its own.
const MAX_PENDING_ENDPOINTS: usize = 512;

/// A connecting peer's endpoint: address plus source port.
type Endpoint = (IpAddr, u16);

pub struct SmolTcpNic {
    inbound_tx: mpsc::Sender<Vec<u8>>,
    outbound_rx: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
    pending: Arc<Mutex<PendingKeys>>,
    notify: Arc<Notify>,
}

impl SmolTcpNic {
    pub fn new(local_addresses: impl IntoIterator<Item = IpCidr>) -> (Self, SmolTcpStack) {
        let (inbound_tx, inbound_rx) = mpsc::channel(STACK_QUEUE_DEPTH);
        let (outbound_tx, outbound_rx) = mpsc::channel(STACK_QUEUE_DEPTH);
        let notify = Arc::new(Notify::new());
        let pending = Arc::new(Mutex::new(PendingKeys::default()));

        let nic = Self {
            inbound_tx,
            outbound_rx: AsyncMutex::new(outbound_rx),
            pending: Arc::clone(&pending),
            notify: Arc::clone(&notify),
        };
        let stack = SmolTcpStack::new(local_addresses, inbound_rx, outbound_tx, pending, notify);
        (nic, stack)
    }
}

impl TunnelDevice for SmolTcpNic {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let packet =
            self.outbound_rx.lock().await.recv().await.ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "smoltcp output closed")
            })?;
        if packet.len() > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "smoltcp emitted a packet larger than the tunnel buffer",
            ));
        }
        let len = packet.len();
        buf[..len].copy_from_slice(&packet);
        Ok(len)
    }

    async fn send(
        &self,
        src_peer_key: &[u8; 32],
        _src_endpoint: Option<SocketAddr>,
        packet: &[u8],
    ) -> io::Result<usize> {
        // The authenticated key is only attached here, where the core still
        // has it in hand. Everything downstream refers to the connection by
        // its inner TCP endpoint.
        if let Some(endpoint) = syn_endpoint(packet) {
            self.pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .record(endpoint, *src_peer_key);
        }
        self.inbound_tx
            .send(packet.to_vec())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "smoltcp input closed"))?;
        self.notify.notify_waiters();
        Ok(packet.len())
    }
}

/// The endpoint a bare `SYN` came from, if this packet is one.
///
/// Anything else — an ACK, a data segment, a non-TCP packet, a truncated
/// header — is not the start of a connection and contributes nothing.
fn syn_endpoint(packet: &[u8]) -> Option<Endpoint> {
    let version = packet.first()? >> 4;
    match version {
        4 => {
            let ip = Ipv4Packet::new_checked(packet).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let source = IpAddr::V4(ip.src_addr());
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            opening_port(&tcp).map(|port| (source, port))
        }
        6 => {
            let ip = Ipv6Packet::new_checked(packet).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let source = IpAddr::V6(ip.src_addr());
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            opening_port(&tcp).map(|port| (source, port))
        }
        _ => None,
    }
}

fn opening_port<T: AsRef<[u8]>>(tcp: &TcpPacket<T>) -> Option<u16> {
    (tcp.syn() && !tcp.ack()).then(|| tcp.src_port())
}

/// Endpoints that have opened a connection, and the authenticated tunnel
/// observation that did.
///
/// Entries are consumed by `accept` and evicted oldest-first past
/// [`MAX_PENDING_ENDPOINTS`], so neither a completed connection nor an
/// abandoned one accumulates.
#[derive(Debug, Default)]
struct PendingKeys {
    connections: HashMap<Endpoint, [u8; 32]>,
    order: VecDeque<Endpoint>,
}

impl PendingKeys {
    fn record(&mut self, endpoint: Endpoint, key: [u8; 32]) {
        if self.connections.insert(endpoint, key).is_none() {
            self.order.push_back(endpoint);
        }
        while self.order.len() > MAX_PENDING_ENDPOINTS {
            if let Some(oldest) = self.order.pop_front() {
                self.connections.remove(&oldest);
            }
        }
    }

    fn take(&mut self, endpoint: &Endpoint) -> Option<[u8; 32]> {
        let key = self.connections.remove(endpoint)?;
        if let Some(position) = self.order.iter().position(|queued| queued == endpoint) {
            self.order.remove(position);
        }
        Some(key)
    }
}

#[derive(Clone)]
pub struct SmolTcpStack {
    inner: Arc<Mutex<Inner>>,
    pending: Arc<Mutex<PendingKeys>>,
    notify: Arc<Notify>,
}

/// There is exactly one listening port, so the accept bookkeeping is a queue
/// and a waker rather than a map of them.
struct Inner {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: QueueDevice,
    port: Option<u16>,
    listeners: Vec<SocketHandle>,
    accept_queue: VecDeque<SocketHandle>,
    accept_waker: Option<Waker>,
    /// Every poll wakes every parked stream regardless of which socket became
    /// ready, so there is nothing for a per-handle index to select on.
    stream_wakers: Vec<Waker>,
    closing_streams: HashSet<SocketHandle>,
}

impl SmolTcpStack {
    fn new(
        local_addresses: impl IntoIterator<Item = IpCidr>,
        inbound_rx: mpsc::Receiver<Vec<u8>>,
        outbound_tx: mpsc::Sender<Vec<u8>>,
        pending: Arc<Mutex<PendingKeys>>,
        notify: Arc<Notify>,
    ) -> Self {
        let mut device = QueueDevice::new(inbound_rx, outbound_tx, Arc::clone(&notify));
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x5eed_5eed;

        let mut iface = Interface::new(config, &mut device, smol_instant());
        iface.update_ip_addrs(|addrs| {
            for address in local_addresses {
                // Convert the core `cidr::IpCidr` into smoltcp's `IpCidr`.
                // `first_address` is the network address, which for the /32
                // and /128 host prefixes a Peers API server is configured with
                // is simply the server's own address.
                let cidr = match address {
                    IpCidr::V4(net) => {
                        SmolIpCidr::new(IpAddress::Ipv4(net.first_address()), net.network_length())
                    }
                    IpCidr::V6(net) => {
                        SmolIpCidr::new(IpAddress::Ipv6(net.first_address()), net.network_length())
                    }
                };
                addrs
                    .push(cidr)
                    .expect("Peers API server addresses should fit");
            }
        });

        Self {
            inner: Arc::new(Mutex::new(Inner {
                iface,
                sockets: SocketSet::new(Vec::new()),
                device,
                port: None,
                listeners: Vec::new(),
                accept_queue: VecDeque::new(),
                accept_waker: None,
                stream_wakers: Vec::new(),
                closing_streams: HashSet::new(),
            })),
            pending,
            notify,
        }
    }

    pub fn listen(&self, port: u16, backlog: usize) -> io::Result<SmolTcpListener> {
        let mut inner = self.lock();
        if inner.port.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "this stack already has a listener",
            ));
        }
        for _ in 0..backlog.max(1) {
            let handle = inner.add_listening_socket(port)?;
            inner.listeners.push(handle);
        }
        inner.port = Some(port);
        Ok(SmolTcpListener {
            stack: self.clone(),
        })
    }

    pub async fn run(self) -> ! {
        let mut ticker = tokio::time::interval(SMOLTCP_POLL_INTERVAL);
        loop {
            self.poll_once();
            tokio::select! {
                _ = ticker.tick() => {},
                _ = self.notify.notified() => {},
            }
        }
    }

    fn poll_once(&self) {
        let mut inner = self.lock();
        inner.poll_iface();
        inner.harvest_accepts();
        inner.cleanup_closed_streams();
        inner.wake_parked_streams();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, PendingKeys> {
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Inner {
    fn poll_iface(&mut self) {
        let Self {
            iface,
            sockets,
            device,
            ..
        } = self;
        let _ = iface.poll(smol_instant(), device, sockets);
    }

    fn add_listening_socket(&mut self, port: u16) -> io::Result<SocketHandle> {
        let rx = SocketBuffer::new(vec![0; TCP_RX_BUFFER]);
        let tx = SocketBuffer::new(vec![0; TCP_TX_BUFFER]);
        let mut socket = Socket::new(rx, tx);
        // Every accepted RPC connection inherits these settings from the
        // listening socket. Keep-alives make an otherwise quiet watch session
        // observable, and the timeout reclaims peers that disappear without a
        // FIN/RST (for example, an MCU reset).
        socket.set_keep_alive(Some(TCP_KEEP_ALIVE));
        socket.set_timeout(Some(TCP_IDLE_TIMEOUT));
        socket
            .listen(IpListenEndpoint { addr: None, port })
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("smoltcp listen failed: {err:?}"),
                )
            })?;
        Ok(self.sockets.add(socket))
    }

    /// Move newly established sockets to the accept queue and replace the
    /// listeners they consumed.
    fn harvest_accepts(&mut self) {
        let Some(port) = self.port else {
            return;
        };

        let mut established = Vec::new();
        let mut index = 0;
        while index < self.listeners.len() {
            let handle = self.listeners[index];
            let socket = self.sockets.get::<Socket>(handle);
            if socket.state() == TcpState::Established && socket.remote_endpoint().is_some() {
                established.push(handle);
                self.listeners.swap_remove(index);
            } else {
                index += 1;
            }
        }

        if established.is_empty() {
            return;
        }

        let replenish = established.len();
        self.accept_queue.extend(established);
        for _ in 0..replenish {
            match self.add_listening_socket(port) {
                Ok(handle) => self.listeners.push(handle),
                Err(error) => {
                    tracing::warn!("failed to replenish smoltcp listener on port {port}: {error:?}")
                }
            }
        }
        if let Some(waker) = self.accept_waker.take() {
            waker.wake();
        }
    }

    fn cleanup_closed_streams(&mut self) {
        let handles: Vec<SocketHandle> = self.closing_streams.iter().copied().collect();

        for handle in handles {
            if self.sockets.get::<Socket>(handle).state() == TcpState::Closed {
                self.sockets.remove(handle);
                self.closing_streams.remove(&handle);
            }
        }
    }

    fn wake_parked_streams(&mut self) {
        for waker in self.stream_wakers.drain(..) {
            waker.wake();
        }
    }

    fn park_stream(&mut self, waker: &Waker) {
        self.stream_wakers.push(waker.clone());
    }
}

pub struct SmolTcpListener {
    stack: SmolTcpStack,
}

impl SmolTcpListener {
    pub async fn accept(&self) -> io::Result<SmolTcpStream> {
        std::future::poll_fn(|cx| {
            let mut inner = self.stack.lock();
            let Some(handle) = inner.accept_queue.pop_front() else {
                inner.accept_waker = Some(cx.waker().clone());
                return Poll::Pending;
            };

            // An accepted socket always has a remote endpoint; `harvest_accepts`
            // only queues sockets that do.
            let endpoint = inner
                .sockets
                .get::<Socket>(handle)
                .remote_endpoint()
                .and_then(|endpoint| std_address(endpoint.addr).map(|addr| (addr, endpoint.port)));
            drop(inner);

            let pending = endpoint
                .as_ref()
                .and_then(|endpoint| self.stack.pending().take(endpoint));

            Poll::Ready(Ok(SmolTcpStream {
                stack: self.stack.clone(),
                handle,
                remote_peer_key: pending,
                #[cfg(test)]
                remote_address: endpoint.map(|(addr, port)| SocketAddr::new(addr, port)),
                closed: false,
            }))
        })
        .await
    }
}

fn std_address(address: IpAddress) -> Option<IpAddr> {
    match address {
        IpAddress::Ipv4(v4) => Some(IpAddr::V4(v4)),
        IpAddress::Ipv6(v6) => Some(IpAddr::V6(v6)),
    }
}

pub struct SmolTcpStream {
    stack: SmolTcpStack,
    handle: SocketHandle,
    remote_peer_key: Option<[u8; 32]>,
    #[cfg(test)]
    remote_address: Option<SocketAddr>,
    closed: bool,
}

impl SmolTcpStream {
    /// The static public key of the peer that opened this connection, captured
    /// at accept and immutable thereafter. `None` fails closed: the RPC layer
    /// admits nothing without a key.
    pub fn remote_peer_key(&self) -> Option<[u8; 32]> {
        self.remote_peer_key
    }

    /// The inner address and ephemeral port this connection came from, as the
    /// virtual stack saw them, captured at accept alongside the key. Retained
    /// for tests; nothing in the RPC layer may attribute a request by address.
    #[cfg(test)]
    pub fn remote_address(&self) -> Option<SocketAddr> {
        self.remote_address
    }
}

impl AsyncRead for SmolTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut inner = this.stack.lock();
        let socket = inner.sockets.get_mut::<Socket>(this.handle);

        if socket.can_recv() && dst.remaining() > 0 {
            let len = socket
                .recv_slice(dst.initialize_unfilled())
                .map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        format!("smoltcp recv failed: {err:?}"),
                    )
                })?;
            dst.advance(len);
            this.stack.notify.notify_waiters();
            Poll::Ready(Ok(()))
        } else if !socket.may_recv() {
            Poll::Ready(Ok(()))
        } else {
            inner.park_stream(cx.waker());
            Poll::Pending
        }
    }
}

impl AsyncWrite for SmolTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut inner = this.stack.lock();
        let socket = inner.sockets.get_mut::<Socket>(this.handle);

        if socket.can_send() {
            let len = socket.send_slice(buf).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("smoltcp send failed: {err:?}"),
                )
            })?;
            this.stack.notify.notify_waiters();
            Poll::Ready(Ok(len))
        } else if !socket.may_send() {
            Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
        } else {
            inner.park_stream(cx.waker());
            Poll::Pending
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().stack.notify.notify_waiters();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.closed {
            this.stack
                .lock()
                .sockets
                .get_mut::<Socket>(this.handle)
                .close();
            this.closed = true;
            this.stack.notify.notify_waiters();
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for SmolTcpStream {
    fn drop(&mut self) {
        {
            let mut inner = self.stack.lock();
            let socket = inner.sockets.get_mut::<Socket>(self.handle);
            if socket.is_open() {
                socket.close();
            }
            if socket.state() == TcpState::Closed {
                inner.sockets.remove(self.handle);
                inner.closing_streams.remove(&self.handle);
            } else {
                inner.closing_streams.insert(self.handle);
            }
        }
        self.stack.notify.notify_waiters();
    }
}

/// The `phy::Device` bridging smoltcp to the tunnel's packet channels.
///
/// `receive` drains whatever is queued: nothing downstream depends on how many
/// packets a single poll consumes.
struct QueueDevice {
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    notify: Arc<Notify>,
}

impl QueueDevice {
    fn new(
        inbound_rx: mpsc::Receiver<Vec<u8>>,
        outbound_tx: mpsc::Sender<Vec<u8>>,
        notify: Arc<Notify>,
    ) -> Self {
        Self {
            inbound_rx,
            outbound_tx,
            notify,
        }
    }
}

impl PhyDevice for QueueDevice {
    type RxToken<'a>
        = QueueRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = QueueTxToken
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.inbound_rx.try_recv().ok()?;
        Some((
            QueueRxToken { packet },
            QueueTxToken {
                tx: self.outbound_tx.clone(),
                notify: Arc::clone(&self.notify),
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(QueueTxToken {
            tx: self.outbound_tx.clone(),
            notify: Arc::clone(&self.notify),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = MAX_INNER_SIZE;
        caps.medium = Medium::Ip;
        caps
    }
}

struct QueueRxToken {
    packet: Vec<u8>,
}

impl RxToken for QueueRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

struct QueueTxToken {
    tx: mpsc::Sender<Vec<u8>>,
    notify: Arc<Notify>,
}

impl TxToken for QueueTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        if self.tx.try_send(packet).is_ok() {
            self.notify.notify_waiters();
        }
        result
    }
}

fn smol_instant() -> SmolInstant {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = *START.get_or_init(Instant::now);
    SmolInstant::from_millis(start.elapsed().as_millis() as i64)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use smoltcp::{
        phy::ChecksumCapabilities,
        wire::{Ipv4Repr, TcpControl, TcpRepr, TcpSeqNumber},
    };

    use super::*;

    const SERVER_V4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const SERVER_V4_ALT: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 4);
    const RPC_PORT: u16 = 80;

    fn server_addresses() -> [IpCidr; 1] {
        ["10.0.0.1/32".parse().unwrap()]
    }

    /// A deterministic public key derived from a single discriminant byte.
    fn expected(disc: u8) -> [u8; 32] {
        [disc; 32]
    }

    /// Build a valid IPv4 + TCP segment (with correct IP and TCP checksums).
    #[allow(clippy::too_many_arguments)]
    fn segment(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        control: TcpControl,
        seq: i32,
        ack: Option<i32>,
        mss: Option<u16>,
        payload: &[u8],
    ) -> Vec<u8> {
        let caps = ChecksumCapabilities::default();

        let tcp_repr = TcpRepr {
            src_port,
            dst_port,
            control,
            seq_number: TcpSeqNumber(seq),
            ack_number: ack.map(TcpSeqNumber),
            window_len: 64240,
            window_scale: None,
            max_seg_size: mss,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload,
        };
        let tcp_len = tcp_repr.buffer_len();

        let ip_repr = Ipv4Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_len,
            hop_limit: 64,
        };
        let ip_hdr_len = ip_repr.buffer_len();

        let mut buf = vec![0u8; ip_hdr_len + tcp_len];
        {
            let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf[..]);
            ip_repr.emit(&mut ip_pkt, &caps);
        }
        {
            let mut tcp_pkt = TcpPacket::new_unchecked(&mut buf[ip_hdr_len..]);
            tcp_repr.emit(
                &mut tcp_pkt,
                &IpAddress::Ipv4(src),
                &IpAddress::Ipv4(dst),
                &caps,
            );
        }
        buf
    }

    /// What the server emitted: (destination port, seq, ack, control).
    fn parse_segment(bytes: &[u8]) -> (u16, i32, Option<i32>, TcpControl) {
        let caps = ChecksumCapabilities::default();
        let ip_pkt = Ipv4Packet::new_checked(bytes).expect("server emitted a valid IPv4 packet");
        let ip_repr = Ipv4Repr::parse(&ip_pkt, &caps).expect("server IPv4 header parses");
        let tcp_pkt = TcpPacket::new_checked(ip_pkt.payload()).expect("server emitted valid TCP");
        let tcp_repr = TcpRepr::parse(
            &tcp_pkt,
            &IpAddress::Ipv4(ip_repr.src_addr),
            &IpAddress::Ipv4(ip_repr.dst_addr),
            &caps,
        )
        .expect("server TCP segment parses");
        (
            tcp_repr.dst_port,
            tcp_repr.seq_number.0,
            tcp_repr.ack_number.map(|seq| seq.0),
            tcp_repr.control,
        )
    }

    /// A simulated remote WireGuard peer opening TCP connections to the server.
    struct SimPeer {
        key: [u8; 32],
        ip: Ipv4Addr,
        port: u16,
        isn: i32,
        server_seq: i32,
    }

    impl SimPeer {
        fn new(disc: u8, last_octet: u8, port: u16, isn: i32) -> Self {
            Self {
                key: expected(disc),
                ip: Ipv4Addr::new(10, 0, 0, last_octet),
                port,
                isn,
                server_seq: 0,
            }
        }

        fn endpoint(&self) -> Endpoint {
            (IpAddr::V4(self.ip), self.port)
        }

        fn syn(&self) -> Vec<u8> {
            segment(
                self.ip,
                SERVER_V4,
                self.port,
                RPC_PORT,
                TcpControl::Syn,
                self.isn,
                None,
                Some(1400),
                &[],
            )
        }

        fn ack(&self) -> Vec<u8> {
            segment(
                self.ip,
                SERVER_V4,
                self.port,
                RPC_PORT,
                TcpControl::None,
                self.isn + 1,
                Some(self.server_seq + 1),
                None,
                &[],
            )
        }

        fn data(&self, payload: &[u8]) -> Vec<u8> {
            segment(
                self.ip,
                SERVER_V4,
                self.port,
                RPC_PORT,
                TcpControl::Psh,
                self.isn + 1,
                Some(self.server_seq + 1),
                None,
                payload,
            )
        }
    }

    /// Inject one inbound packet through the REAL NIC send path, tagging it with
    /// the authenticated key exactly as the tunnel runner does.
    fn outer_endpoint(key: [u8; 32]) -> SocketAddr {
        SocketAddr::from(([198, 51, 100, key[0]], 51820))
    }

    async fn inject(nic: &SmolTcpNic, pkt: &[u8], key: [u8; 32]) {
        nic.send(&key, Some(outer_endpoint(key)), pkt)
            .await
            .expect("virtual NIC must accept the authenticated packet");
    }

    /// Pull one packet the server stack has emitted, without blocking.
    fn drain_one(nic: &mut SmolTcpNic) -> Option<Vec<u8>> {
        nic.outbound_rx.get_mut().try_recv().ok()
    }

    /// Drive the three-way handshake to completion for `peer`.
    async fn handshake(nic: &mut SmolTcpNic, stack: &SmolTcpStack, peer: &mut SimPeer) {
        inject(nic, &peer.syn(), peer.key).await;
        stack.poll_once();

        let synack = drain_one(nic).expect("server must answer SYN with SYN-ACK");
        let (dst_port, server_seq, ack, control) = parse_segment(&synack);
        assert_eq!(
            control,
            TcpControl::Syn,
            "second handshake segment is a SYN"
        );
        assert_eq!(dst_port, peer.port);
        assert_eq!(
            ack,
            Some(peer.isn + 1),
            "SYN-ACK must acknowledge our ISN+1"
        );
        peer.server_seq = server_seq;

        inject(nic, &peer.ack(), peer.key).await;
        stack.poll_once();
    }

    /// The endpoint smoltcp recorded as the remote end of an accepted stream.
    fn stream_endpoint(stack: &SmolTcpStack, stream: &SmolTcpStream) -> Endpoint {
        let inner = stack.lock();
        let endpoint = inner
            .sockets
            .get::<Socket>(stream.handle)
            .remote_endpoint()
            .expect("an accepted (Established) socket always has a remote endpoint");
        (
            std_address(endpoint.addr).expect("a real address family"),
            endpoint.port,
        )
    }

    // -----------------------------------------------------------------------
    // The parser that replaces poll-order attribution.
    // -----------------------------------------------------------------------
    #[test]
    fn syn_endpoint_reads_the_opening_endpoint() {
        let peer = SimPeer::new(0x01, 4, 45000, 100);
        assert_eq!(syn_endpoint(&peer.syn()), Some(peer.endpoint()));

        // Only a bare SYN opens a connection.
        assert_eq!(syn_endpoint(&peer.ack()), None);
        assert_eq!(syn_endpoint(&peer.data(b"hello")), None);

        // Garbage and truncation are refused rather than guessed at.
        assert_eq!(syn_endpoint(&[]), None);
        assert_eq!(syn_endpoint(&[0x45, 0x00]), None);
        assert_eq!(syn_endpoint(&[0x00; 40]), None);
    }

    // -----------------------------------------------------------------------
    // The device is free to drain the queue: no attribution depends on how
    // many packets a poll consumes.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn the_device_drains_every_queued_packet_in_one_poll() {
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(8);
        let (out_tx, _out_rx) = mpsc::channel::<Vec<u8>>(8);
        let mut device = QueueDevice::new(in_rx, out_tx, Arc::new(Notify::new()));

        in_tx.send(vec![1, 2, 3]).await.unwrap();
        in_tx.send(vec![4, 5, 6]).await.unwrap();

        assert!(PhyDevice::receive(&mut device, smol_instant()).is_some());
        assert!(PhyDevice::receive(&mut device, smol_instant()).is_some());
        assert!(
            PhyDevice::receive(&mut device, smol_instant()).is_none(),
            "an empty queue yields nothing"
        );
    }

    #[test]
    fn pending_keys_are_bounded_and_evict_oldest_first() {
        let mut pending = PendingKeys::default();
        for index in 0..(MAX_PENDING_ENDPOINTS as u32 + 100) {
            let ip = IpAddr::V4(Ipv4Addr::from(index.to_be_bytes()));
            pending.record((ip, 1000), expected(0x01));
        }
        assert_eq!(pending.connections.len(), MAX_PENDING_ENDPOINTS);
        assert_eq!(pending.order.len(), MAX_PENDING_ENDPOINTS);

        // The very first endpoint recorded is gone; the last is not.
        let first = IpAddr::V4(Ipv4Addr::from(0u32.to_be_bytes()));
        let last = IpAddr::V4(Ipv4Addr::from(
            (MAX_PENDING_ENDPOINTS as u32 + 99).to_be_bytes(),
        ));
        assert_eq!(pending.take(&(first, 1000)), None);
        assert_eq!(pending.take(&(last, 1000)), Some(expected(0x01)));
    }

    // -----------------------------------------------------------------------
    // Baseline: a single peer is attributed its own key.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn single_peer_is_attributed_its_own_key() {
        let (mut nic, stack) = SmolTcpNic::new(server_addresses());
        let listener = stack.listen(RPC_PORT, 8).unwrap();

        let mut peer = SimPeer::new(0x07, 2, 40000, 1000);
        handshake(&mut nic, &stack, &mut peer).await;

        let stream = listener.accept().await.unwrap();
        assert_eq!(stream.remote_peer_key(), Some(expected(0x07)));
        assert_eq!(stream_endpoint(&stack, &stream), peer.endpoint());

        let (address, port) = peer.endpoint();
        assert_eq!(
            stream.remote_address(),
            Some(SocketAddr::new(address, port))
        );
    }

    // -----------------------------------------------------------------------
    // Core anti-spoofing property: two peers whose handshakes interleave (and
    // whose ACK order is the REVERSE of their SYN order) are each attributed
    // their own key.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn interleaved_peers_are_never_cross_attributed() {
        let (mut nic, stack) = SmolTcpNic::new(server_addresses());
        let listener = stack.listen(RPC_PORT, 8).unwrap();

        let mut a = SimPeer::new(0xAA, 2, 40001, 1000);
        let mut b = SimPeer::new(0xBB, 3, 40002, 9000);

        inject(&nic, &a.syn(), a.key).await;
        stack.poll_once();
        a.server_seq = parse_segment(&drain_one(&mut nic).expect("A SYN-ACK")).1;

        inject(&nic, &b.syn(), b.key).await;
        stack.poll_once();
        b.server_seq = parse_segment(&drain_one(&mut nic).expect("B SYN-ACK")).1;

        // ACKs in REVERSE order: B establishes first, then A.
        inject(&nic, &b.ack(), b.key).await;
        stack.poll_once();
        inject(&nic, &a.ack(), a.key).await;
        stack.poll_once();

        let first = listener.accept().await.unwrap();
        let second = listener.accept().await.unwrap();

        for stream in [&first, &second] {
            let endpoint = stream_endpoint(&stack, stream);
            let key = stream
                .remote_peer_key()
                .expect("authenticated stream has a key");
            if endpoint == a.endpoint() {
                assert_eq!(key, expected(0xAA), "peer A's stream must carry A's key");
            } else if endpoint == b.endpoint() {
                assert_eq!(key, expected(0xBB), "peer B's stream must carry B's key");
            } else {
                panic!("unexpected remote endpoint {endpoint:?}");
            }
        }
        assert_ne!(first.remote_peer_key(), second.remote_peer_key());
    }

    // -----------------------------------------------------------------------
    // The case the old poll-order scheme had to forbid: both handshakes fully
    // batched, so several sockets establish inside a single poll. Endpoints
    // keep them apart.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn handshakes_batched_into_one_poll_are_attributed_separately() {
        let (mut nic, stack) = SmolTcpNic::new(server_addresses());
        let listener = stack.listen(RPC_PORT, 8).unwrap();

        let mut a = SimPeer::new(0xCA, 2, 41001, 2000);
        let mut b = SimPeer::new(0xCB, 3, 41002, 7000);

        // Both SYNs, then ONE poll.
        inject(&nic, &a.syn(), a.key).await;
        inject(&nic, &b.syn(), b.key).await;
        stack.poll_once();

        for _ in 0..2 {
            let (dst_port, seq, _, control) =
                parse_segment(&drain_one(&mut nic).expect("a SYN-ACK per SYN"));
            assert_eq!(control, TcpControl::Syn);
            if dst_port == a.port {
                a.server_seq = seq;
            } else if dst_port == b.port {
                b.server_seq = seq;
            } else {
                panic!("SYN-ACK to an unknown port {dst_port}");
            }
        }

        // Both ACKs, then ONE poll: two sockets establish together.
        inject(&nic, &a.ack(), a.key).await;
        inject(&nic, &b.ack(), b.key).await;
        stack.poll_once();

        let first = listener.accept().await.unwrap();
        let second = listener.accept().await.unwrap();
        for stream in [&first, &second] {
            let endpoint = stream_endpoint(&stack, stream);
            let want = if endpoint == a.endpoint() {
                expected(0xCA)
            } else {
                expected(0xCB)
            };
            assert_eq!(
                stream.remote_peer_key(),
                Some(want),
                "a shared poll must not collapse two origins"
            );
        }
        assert_ne!(first.remote_peer_key(), second.remote_peer_key());
    }

    // -----------------------------------------------------------------------
    // The key is captured at accept: later traffic from another peer cannot
    // retroactively change an already-accepted stream's key.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn key_is_immutable_after_accept() {
        let (mut nic, stack) = SmolTcpNic::new(server_addresses());
        let listener = stack.listen(RPC_PORT, 8).unwrap();

        let mut a = SimPeer::new(0xA0, 2, 42001, 3000);
        handshake(&mut nic, &stack, &mut a).await;
        let stream = listener.accept().await.unwrap();
        assert_eq!(stream.remote_peer_key(), Some(expected(0xA0)));

        // A different peer sends a (bogus, unmatched) segment afterwards.
        let b = SimPeer::new(0xB0, 3, 42002, 8000);
        inject(&nic, &b.data(b"noise"), b.key).await;
        stack.poll_once();
        let _ = drain_one(&mut nic);

        assert_eq!(
            stream.remote_peer_key(),
            Some(expected(0xA0)),
            "an accepted stream's key must never change"
        );
    }

    // -----------------------------------------------------------------------
    // Accept consumes the pending entry, so a later connection from the same
    // endpoint cannot inherit the previous peer's key.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn accept_consumes_the_pending_entry() {
        let (mut nic, stack) = SmolTcpNic::new(server_addresses());
        let listener = stack.listen(RPC_PORT, 8).unwrap();

        let mut a = SimPeer::new(0x11, 2, 43001, 4000);
        handshake(&mut nic, &stack, &mut a).await;
        let first = listener.accept().await.unwrap();
        assert_eq!(first.remote_peer_key(), Some(expected(0x11)));
        assert!(
            stack.pending().take(&a.endpoint()).is_none(),
            "accept must remove the endpoint entry, leaving nothing to inherit"
        );

        let mut b = SimPeer::new(0x22, 3, 43002, 6000);
        handshake(&mut nic, &stack, &mut b).await;
        let second = listener.accept().await.unwrap();
        assert_eq!(second.remote_peer_key(), Some(expected(0x22)));
    }

    // -----------------------------------------------------------------------
    // Fail-closed: a connection with no recorded key surfaces `None`, which
    // the RPC admission layer answers with a null result.
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn an_unrecorded_connection_yields_no_key() {
        let (mut nic, stack) = SmolTcpNic::new(server_addresses());
        let listener = stack.listen(RPC_PORT, 8).unwrap();

        let mut a = SimPeer::new(0x33, 2, 44001, 5000);
        handshake(&mut nic, &stack, &mut a).await;

        // Evict the entry before accept reaches it.
        assert!(stack.pending().take(&a.endpoint()).is_some());

        let stream = listener.accept().await.unwrap();
        assert_eq!(
            stream.remote_peer_key(),
            None,
            "no recorded key must surface as None (fail-closed, -> null result)"
        );
    }

    #[tokio::test]
    async fn ipv6_local_address_constructs_and_listens() {
        let v6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let (_nic, stack) =
            SmolTcpNic::new([format!("{v6}/128").parse().expect("valid IPv6 prefix")]);
        stack
            .listen(RPC_PORT, 4)
            .expect("listening on an IPv6 stack must succeed");
    }

    #[tokio::test]
    async fn accepts_connections_on_every_server_address() {
        let (mut nic, stack) = SmolTcpNic::new([
            "10.0.0.1/32".parse().unwrap(),
            "10.0.0.2/32".parse().unwrap(),
            "10.0.0.3/32".parse().unwrap(),
            "10.0.0.4/32".parse().unwrap(),
        ]);
        let listener = stack.listen(RPC_PORT, 4).unwrap();

        let mut peer = SimPeer::new(0x42, 9, 41000, 1000);
        let syn = segment(
            peer.ip,
            SERVER_V4_ALT,
            peer.port,
            RPC_PORT,
            TcpControl::Syn,
            peer.isn,
            None,
            Some(1400),
            &[],
        );
        inject(&nic, &syn, peer.key).await;
        stack.poll_once();

        let synack = drain_one(&mut nic).expect("server must answer on every configured address");
        let (_, server_seq, _, control) = parse_segment(&synack);
        assert_eq!(control, TcpControl::Syn);
        peer.server_seq = server_seq;

        let ack = segment(
            peer.ip,
            SERVER_V4_ALT,
            peer.port,
            RPC_PORT,
            TcpControl::None,
            peer.isn + 1,
            Some(peer.server_seq + 1),
            None,
            &[],
        );
        inject(&nic, &ack, peer.key).await;
        stack.poll_once();

        let stream = listener.accept().await.unwrap();
        assert_eq!(stream.remote_peer_key(), Some(peer.key));
    }

    #[tokio::test]
    async fn a_second_listener_is_refused() {
        let (_nic, stack) = SmolTcpNic::new(server_addresses());
        let _first = stack.listen(RPC_PORT, 4).expect("first listener");
        assert!(stack.listen(8080, 4).is_err());
    }
}
