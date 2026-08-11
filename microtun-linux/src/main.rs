//! microtun daemon for Linux hosts.
//!
//! Platform-independent Tokio driving and Peers API resolution live in
//! [`microtun_std`]. This binary is intentionally limited to WireGuard-style INI
//! configuration, Linux TUN setup, logging, and process lifecycle.
//!
//! Run: `microtun /etc/microtun/microtun.conf` (needs `CAP_NET_ADMIN`).

mod config;

use std::{io, net::SocketAddr, time::Duration as StdDuration};

use microtun_std::{
    PeersApiResolver, PeersApiTransport, TunnelDevice, TunnelRunner,
    core::{
        Config, Duration, IpInet, PinnedPeer, firewall::InboundPolicy, ip::unmap_socket_addr,
        key::encode_key,
    },
};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::{TcpSocket, TcpStream, lookup_host};

const TCP_KEEP_ALIVE: StdDuration = StdDuration::from_secs(15);
const TCP_KEEP_ALIVE_RETRIES: u32 = 2;
const TCP_IDLE_TIMEOUT: StdDuration = StdDuration::from_secs(45);

/// Linux `tun-rs` adapter for the runtime-independent host runner.
struct TunDevice(tun_rs::AsyncDevice);

impl TunnelDevice for TunDevice {
    async fn recv(&self, packet: &mut [u8]) -> io::Result<usize> {
        self.0.recv(packet).await
    }

    async fn send(
        &self,
        _src_peer_key: &[u8; 32],
        _src_endpoint: Option<SocketAddr>,
        packet: &[u8],
    ) -> io::Result<usize> {
        self.0.send(packet).await
    }
}

/// Opens Peers API server connections pinned to the tunnel interface.
///
/// This is the whole of the resolver's transport security on this side, which
/// is why `microtun-std` refuses to supply a default: a lookup that leaves by
/// any other route is a lookup answered by whoever is listening there. Binding
/// to the device rather than trusting the routing table means a stale or more
/// specific system route cannot silently redirect it, and the connection fails
/// outright when the tunnel is down.
///
/// `SO_BINDTODEVICE` needs `CAP_NET_RAW`, the same requirement the HTTP client
/// this replaces had for its interface binding. There are no redirects or
/// proxy environment variables left to disable.
#[derive(Clone)]
struct TunTransport {
    interface: String,
}

impl PeersApiTransport for TunTransport {
    type Stream = TcpStream;

    async fn connect(&self, api: SocketAddr) -> io::Result<TcpStream> {
        let socket = match api {
            SocketAddr::V4(_) => TcpSocket::new_v4()?,
            SocketAddr::V6(_) => TcpSocket::new_v6()?,
        };
        let socket_ref = SockRef::from(&socket);
        socket_ref.bind_device(Some(self.interface.as_bytes()))?;
        // Resolver sessions are intentionally long-lived and often quiet.
        // Kernel keep-alives make a dead path observable; TCP_USER_TIMEOUT
        // bounds how long an unresponsive peer can retain this connection.
        socket_ref.set_tcp_keepalive(
            &TcpKeepalive::new()
                .with_time(TCP_KEEP_ALIVE)
                .with_interval(TCP_KEEP_ALIVE)
                .with_retries(TCP_KEEP_ALIVE_RETRIES),
        )?;
        socket_ref.set_tcp_user_timeout(Some(TCP_IDLE_TIMEOUT))?;
        socket.connect(api).await
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    tracing::debug!("linux logger initialized");

    let path = std::env::args().nth(1).unwrap_or_else(|| {
        tracing::error!("usage: microtun <config.conf>");
        std::process::exit(2);
    });
    let runtime_config = match config::load(&path) {
        Ok(runtime_config) => runtime_config,
        Err(error) => {
            tracing::error!(%error, "configuration failed");
            std::process::exit(1);
        }
    };

    if let Err(error) = run(runtime_config).await {
        tracing::error!(%error, "fatal tunnel error");
        std::process::exit(1);
    }
}

async fn run(runtime: config::Runtime) -> Result<(), Box<dyn std::error::Error>> {
    let config::Runtime {
        private_key,
        api_server_public_key,
        api_server_endpoint,
        api_server_addresses,
        listen,
        tun_name,
        tun_address,
        tun_mtu,
        peers_api,
        enable_forwarding,
    } = runtime;

    let api_server_endpoint = resolve_api_server_endpoint(&api_server_endpoint, listen).await?;

    let pinned = [PinnedPeer {
        public_key: api_server_public_key,
        endpoint: Some(api_server_endpoint),
        relay: None,
        addresses: &api_server_addresses,
        // We don't allow unsolicited inbound from the Peers API server.
        inbound_policy: InboundPolicy::EstablishedOnly,
        persistent_keepalive: Some(Duration::from_secs(25)),
    }];
    let core_config = Config::new(*private_key, &pinned);

    let builder = tun_rs::DeviceBuilder::new()
        .name(tun_name.clone())
        .mtu(tun_mtu);
    let builder = match &tun_address {
        IpInet::V4(address) => builder.ipv4(address.address(), address.network_length(), None),
        IpInet::V6(address) => builder.ipv6(address.address(), address.network_length()),
    };
    let device = builder.build_async()?;
    // `{:#}` keeps the prefix length on a /32 or /128, which the plain
    // Display would drop.
    let tun_address_text = format!("{tun_address:#}");
    tracing::info!(tun.name = %tun_name, tun.address = %tun_address_text, tun.mtu = tun_mtu, "TUN interface is up");

    let rng = rand::rngs::OsRng;
    let mut runner = TunnelRunner::bind(core_config, rng, TunDevice(device), listen).await?;
    tracing::info!(%listen, "outer UDP socket bound");

    runner.enable_forwarding(enable_forwarding);
    if enable_forwarding {
        tracing::warn!("relay forwarding enabled");
    }

    let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    runner.set_unix_time(unix.as_secs(), unix.subsec_nanos());

    let public_key = encode_key(&runner.public_key());
    tracing::info!(public_key = %public_key, "tunnel identity ready");

    let resolver = PeersApiResolver::new(
        peers_api,
        TunTransport {
            interface: tun_name.clone(),
        },
    );
    tracing::info!(
        peers_api = %peers_api,
        tun.name = %tun_name,
        "Peers API server RPC connections bound to the TUN interface"
    );

    runner.run(resolver, tokio::signal::ctrl_c()).await?;
    tracing::info!("shutting down cleanly");
    Ok(())
}

/// Resolve a DNS bootstrap endpoint once at startup.
///
/// The tunnel cannot be used for this lookup because the resolved outer
/// endpoint is itself required to establish the tunnel. IPv4-bound outer UDP
/// sockets therefore select an A result; IPv6 sockets prefer AAAA and may use
/// an A result through the runner's IPv4-mapped send path.
async fn resolve_api_server_endpoint(
    endpoint: &config::ApiServerEndpoint,
    listen: SocketAddr,
) -> io::Result<SocketAddr> {
    if let Some(address) = endpoint.socket_addr() {
        return Ok(address);
    }

    let (host, port) = endpoint
        .dns_target()
        .expect("non-socket ApiServerEndpoint must be DNS");
    let resolved = lookup_host((host, port)).await.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot resolve ApiServer Endpoint `{host}:{port}`: {error}"),
        )
    })?;

    let mut first_v4 = None;
    let mut first_v6 = None;
    for address in resolved.map(unmap_socket_addr) {
        match address {
            SocketAddr::V4(_) if first_v4.is_none() => first_v4 = Some(address),
            SocketAddr::V6(_) if first_v6.is_none() => first_v6 = Some(address),
            _ => {}
        }
    }

    let selected = match listen {
        SocketAddr::V4(_) => first_v4,
        SocketAddr::V6(_) => first_v6.or(first_v4),
    }
    .ok_or_else(|| {
        let family = if listen.is_ipv4() { "IPv4" } else { "IPv6 or IPv4" };
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!(
                "ApiServer Endpoint `{host}:{port}` resolved to no {family} address usable by outer socket `{listen}`"
            ),
        )
    })?;

    tracing::info!(endpoint = %endpoint, resolved = %selected, "resolved ApiServer endpoint");
    Ok(selected)
}
