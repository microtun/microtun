//! microtun daemon for Linux hosts.
//!
//! Platform-independent Tokio driving and Peers API resolution live in
//! [`microtun_std`]. This binary uses the same provisioning INI schema as
//! `microtun-device-config`, plus Linux TUN setup, logging, and process lifecycle.
//!
//! Run: `microtun /etc/microtun/microtun.conf` (defaults to `mtun0`; needs `CAP_NET_ADMIN`).

use std::{
    env, fs, io,
    net::{Ipv4Addr, SocketAddr},
    time::Duration as StdDuration,
};

use microtun_device_config::{DeviceConfig, decode_ini};
use microtun_std::{
    PeersApiResolver, PeersApiTransport, TunnelDevice, TunnelRunner,
    core::{
        Config, Duration, IpInet, PinnedPeer,
        firewall::InboundPolicy,
        ip::{host_cidr, parse_ip_inet, unmap_socket_addr},
        key::{decode_key, decode_key_into, encode_key},
    },
};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::{TcpSocket, TcpStream, lookup_host};
use zeroize::Zeroizing;

const DEFAULT_TUN_NAME: &str = "mtun0";
const DEFAULT_LISTEN_PORT: u16 = 51820;
const DEFAULT_MTU: u16 = 1280;
const PEERS_API_PORT: u16 = 80;
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

    let cli = match parse_cli(env::args().skip(1)) {
        Ok(cli) => cli,
        Err(CliError::Help) => {
            print_usage();
            return;
        }
        Err(CliError::Message(message)) => {
            tracing::error!(%message, "invalid command line");
            print_usage();
            std::process::exit(2);
        }
    };
    let device_config = {
        let config_bytes = match fs::read(&cli.config_path) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(error) => {
                tracing::error!(path = %cli.config_path, %error, "cannot read configuration");
                std::process::exit(1);
            }
        };
        match decode_ini(&config_bytes) {
            Ok(config) => config,
            Err(error) => {
                tracing::error!(path = %cli.config_path, %error, "configuration failed");
                std::process::exit(1);
            }
        }
    };

    if let Err(error) = run(device_config, cli.tun_name).await {
        tracing::error!(%error, "fatal tunnel error");
        std::process::exit(1);
    }
}

const USAGE: &str = concat!(
    "usage: microtun [--interface <name>] <config.conf>\n",
    "       microtun [-i <name>] <config.conf>\n",
    "\n",
    "Defaults to interface `mtun0` when --interface/-i is omitted."
);

#[derive(Debug)]
struct Cli {
    tun_name: String,
    config_path: String,
}

#[derive(Debug)]
enum CliError {
    Help,
    Message(String),
}

fn parse_cli(args: impl IntoIterator<Item = String>) -> Result<Cli, CliError> {
    let mut tun_name = None;
    let mut config_path = None;
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Err(CliError::Help),
            "-i" | "--interface" => {
                let value = args.next().ok_or_else(|| {
                    CliError::Message(format!("`{arg}` requires an interface name"))
                })?;
                set_interface(&mut tun_name, value)?;
            }
            _ if arg.starts_with("--interface=") => {
                let value = arg["--interface=".len()..].to_string();
                set_interface(&mut tun_name, value)?;
            }
            _ if arg.starts_with('-') => {
                return Err(CliError::Message(format!("unknown option `{arg}`")));
            }
            _ => {
                if config_path.replace(arg).is_some() {
                    return Err(CliError::Message(
                        "expected exactly one configuration file".into(),
                    ));
                }
            }
        }
    }

    let tun_name = tun_name.unwrap_or_else(|| DEFAULT_TUN_NAME.to_owned());
    let config_path =
        config_path.ok_or_else(|| CliError::Message("missing configuration file".into()))?;

    Ok(Cli {
        tun_name,
        config_path,
    })
}

fn set_interface(slot: &mut Option<String>, value: String) -> Result<(), CliError> {
    if value.is_empty() {
        return Err(CliError::Message("interface name must not be empty".into()));
    }
    if slot.replace(value).is_some() {
        return Err(CliError::Message(
            "`--interface` may only be specified once".into(),
        ));
    }
    Ok(())
}

fn print_usage() {
    eprintln!("{USAGE}");
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn parses_interface_flag_and_config_path() {
        let cli = parse_cli([
            "--interface".to_string(),
            "mtun7".to_string(),
            "client.conf".to_string(),
        ])
        .expect("valid command line");
        assert_eq!(cli.tun_name, "mtun7");
        assert_eq!(cli.config_path, "client.conf");
    }

    #[test]
    fn accepts_short_and_equals_interface_forms() {
        let short = parse_cli([
            "client.conf".to_string(),
            "-i".to_string(),
            "mtun7".to_string(),
        ])
        .expect("short interface option");
        assert_eq!(short.tun_name, "mtun7");

        let equals = parse_cli(["--interface=mtun8".to_string(), "client.conf".to_string()])
            .expect("equals interface option");
        assert_eq!(equals.tun_name, "mtun8");
    }
}

async fn run(
    device_config: DeviceConfig,
    tun_name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let DeviceConfig {
        tunnel, api_server, ..
    } = device_config;

    // microtun-device-config has already validated these values. Decode them
    // here, at the boundary where the Linux runtime needs their concrete forms.
    let mut private_key = Zeroizing::new([0u8; 32]);
    decode_key_into(tunnel.private_key.as_str(), &mut private_key)?;
    let api_server_public_key = decode_key(api_server.public_key.as_str())?;
    let tun_address = parse_ip_inet(tunnel.tunnel_address.as_str())?;
    let api_server_address = parse_ip_inet(api_server.tunnel_address.as_str())?;
    let api_server_host = api_server_address.address();
    // ApiServer.TunnelAddress identifies one peer. A supplied prefix is accepted
    // as input metadata, but must not make the API server claim the whole subnet.
    let api_server_route = host_cidr(api_server_host);
    let listen = SocketAddr::from((
        [0, 0, 0, 0],
        tunnel.listen_port.unwrap_or(DEFAULT_LISTEN_PORT),
    ));
    let tun_mtu = tunnel.mtu.unwrap_or(DEFAULT_MTU);
    let peers_api = SocketAddr::new(api_server_host, PEERS_API_PORT);

    let api_server_endpoint =
        resolve_api_server_endpoint(api_server.host.as_str(), api_server.port, listen).await?;

    let pinned = [PinnedPeer {
        public_key: api_server_public_key,
        endpoint: Some(api_server_endpoint),
        relay: None,
        address: api_server_route,
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
    let mut runner = TunnelRunner::bind(
        core_config,
        rng,
        TunDevice(device),
        listen,
        tunnel.enable_forwarding,
    )
    .await?;
    tracing::info!(%listen, "outer UDP socket bound");

    if tunnel.enable_forwarding {
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
    host: &str,
    port: u16,
    listen: SocketAddr,
) -> io::Result<SocketAddr> {
    if let Ok(address) = host.parse::<Ipv4Addr>() {
        return Ok(SocketAddr::from((address, port)));
    }

    let resolved = lookup_host((host, port)).await.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot resolve ApiServer Host/Port `{host}:{port}`: {error}"),
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
                "ApiServer Host/Port `{host}:{port}` resolved to no {family} address usable by outer socket `{listen}`"
            ),
        )
    })?;

    tracing::info!(host, port, resolved = %selected, "resolved ApiServer Host");
    Ok(selected)
}
