//! Shared Telnet CLI types, formatting helpers, status output, and commands.

use core::fmt::{self, Display};

use embassy_net::Stack;
use embassy_time::Instant as EmbassyInstant;
use embedded_io_async::Write as AsyncWrite;
use microtun_embassy::{
    TunnelStatus,
    core::{Instant, PeerConnectionState, PeerOrigin, key::encode_key},
};
pub use microtun_net_util::ping::{DEFAULT_PING_COUNT, MAX_PING_COUNT};
use microtun_telnet_cli::{Error as CliError, IoError, ValueEnum, write_fmt};

use crate::table::Table;

pub const TELNET_TCP_BUFFER: usize = 1024;
pub const TELNET_PORT: u16 = 23;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum PingIface {
    /// Use the physical/uplink network interface.
    Net,
    /// Use the secure-tunnel interface.
    Tunnel,
}

impl PingIface {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Net => "net",
            Self::Tunnel => "tunnel",
        }
    }
}

pub async fn ping<W>(
    out: &mut W,
    iface_name: &str,
    iface: Stack<'static>,
    target: core::net::IpAddr,
    count: u8,
) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    microtun_net_util::ping::ping(out, iface_name, iface, target, count)
        .await
        .map_err(CliError::from)
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum SysField {
    /// Show the current device mode.
    Mode,
    /// Show whether a provisioning record is installed.
    Provisioned,
    /// Show the board model.
    Board,
    /// Show the Git-derived firmware version string.
    Version,
    /// Show the stable provisioning/device identifier.
    Id,
    /// Show the reason for the last reset.
    ResetReason,
    /// Show the MCU internal temperature.
    Temp,
    /// Show time since boot.
    Uptime,
    /// Show the synchronized wall-clock time.
    Time,
    /// Show RAM usage.
    Memory,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum TunnelAction {
    /// Show tunnel interface and peer status.
    Show,
    /// Show this device's tunnel public key.
    Key,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum IoAction {
    /// Turn the output on.
    On,
    /// Turn the output off.
    Off,
    /// Invert the current output state.
    Toggle,
}

pub async fn line<W>(out: &mut W, args: fmt::Arguments<'_>) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    write_fmt::<256, _>(out, args).await?;
    out.write_all(b"\r\n").await?;
    Ok(())
}

pub async fn println<W>(out: &mut W, text: &str) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    out.write_all(text.as_bytes()).await?;
    out.write_all(b"\r\n").await?;
    Ok(())
}

const DEFAULT_TABLE: Table = Table::new(&[]);

pub const SYS_TABLE: Table = Table::new(&[
    "mode",
    "provisioned",
    "board",
    "id",
    "version",
    "reset-reason",
    "temp",
    "uptime",
    "time",
    "memory",
]);

pub async fn field<W, D>(out: &mut W, name: &str, value: &D) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
    D: Display + ?Sized,
{
    DEFAULT_TABLE.field(out, name, value).await
}

pub async fn time_field<W>(
    out: &mut W,
    table: Table,
    name: &str,
    time: Option<(u64, u32)>,
) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    match time {
        Some((seconds, nanos)) => {
            table
                .field_fmt(out, name, format_args!("unix={seconds}.{nanos:09}"))
                .await
        }
        None => table.field(out, name, "unavailable").await,
    }
}

pub async fn time<W>(
    out: &mut W,
    field_name: Option<&str>,
    time: Option<(u64, u32)>,
) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    match field_name {
        Some(name) => time_field(out, DEFAULT_TABLE, name, time).await,
        None => match time {
            Some((seconds, nanos)) => line(out, format_args!("unix={seconds}.{nanos:09}")).await,
            None => println(out, "unavailable").await.map_err(CliError::from),
        },
    }
}

pub async fn net_field<W>(
    out: &mut W,
    table: Table,
    name: &str,
    address: Option<&dyn Display>,
    gateway: Option<&dyn Display>,
) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    match (address, gateway) {
        (Some(address), Some(gateway)) => {
            table
                .field_fmt(out, name, format_args!("{address} gateway={gateway}"))
                .await
        }
        (Some(address), None) => table.field(out, name, address).await,
        (None, _) => table.field(out, name, "unconfigured").await,
    }
}

pub async fn net<W>(
    out: &mut W,
    field_name: Option<&str>,
    address: Option<&dyn Display>,
    gateway: Option<&dyn Display>,
) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    match field_name {
        Some(name) => net_field(out, DEFAULT_TABLE, name, address, gateway).await,
        None => match (address, gateway) {
            (Some(address), Some(gateway)) => {
                line(out, format_args!("{address} gateway={gateway}")).await
            }
            (Some(address), None) => line(out, format_args!("{address}")).await,
            (None, _) => println(out, "unconfigured").await.map_err(CliError::from),
        },
    }
}

pub async fn write_net_base<W>(
    out: &mut W,
    table: Table,
    stack: Stack<'static>,
    mac: [u8; 6],
) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    table
        .field(out, "link", if stack.is_link_up() { "up" } else { "down" })
        .await?;

    let config = stack.config_v4();
    let address = config
        .as_ref()
        .map(|config| &config.address as &dyn Display);
    let gateway = config
        .as_ref()
        .and_then(|config| config.gateway.as_ref())
        .map(|gateway| gateway as &dyn Display);
    net_field(out, table, "ip", address, gateway).await?;

    table
        .field_fmt(
            out,
            "mac",
            format_args!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            ),
        )
        .await
}

pub async fn write_link_status<W>(out: &mut W, stack: Stack<'static>) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    println(out, if stack.is_link_up() { "up" } else { "down" })
        .await
        .map_err(CliError::from)
}

pub async fn write_ip_status<W>(out: &mut W, stack: Stack<'static>) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    let config = stack.config_v4();
    let address = config
        .as_ref()
        .map(|config| &config.address as &dyn Display);
    let gateway = config
        .as_ref()
        .and_then(|config| config.gateway.as_ref())
        .map(|gateway| gateway as &dyn Display);
    net(out, None, address, gateway).await
}

pub async fn write_mac_status<W>(out: &mut W, mac: [u8; 6]) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    line(
        out,
        format_args!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        ),
    )
    .await
}

fn peer_origin_name(origin: PeerOrigin) -> &'static str {
    match origin {
        PeerOrigin::Pinned => "pinned",
        PeerOrigin::Dynamic => "dynamic",
    }
}

fn peer_connection_name(state: PeerConnectionState) -> &'static str {
    match state {
        PeerConnectionState::Idle => "idle",
        PeerConnectionState::Handshaking => "handshaking",
        PeerConnectionState::AwaitingConfirmation => "awaiting-confirmation",
        PeerConnectionState::Established => "established",
        PeerConnectionState::Rekeying => "rekeying",
    }
}

pub async fn write_tunnel_status<W>(
    out: &mut W,
    status: TunnelStatus<'_>,
    inner_stack: &Stack<'static>,
) -> Result<(), CliError>
where
    W: AsyncWrite<Error = IoError> + ?Sized,
{
    let snapshot = status.snapshot();
    let public_key = encode_key(&snapshot.public_key);
    println(out, "interface:").await?;
    line(out, format_args!("  public key: {}", public_key.as_str())).await?;
    let tunnel_v4 = inner_stack.config_v4();
    let tunnel_v6 = inner_stack.config_v6();
    if let Some(config) = tunnel_v4.as_ref() {
        line(out, format_args!("  address: {}", config.address)).await?;
    } else if let Some(config) = tunnel_v6.as_ref() {
        line(out, format_args!("  address: {}", config.address)).await?;
    } else {
        println(out, "  address: unconfigured").await?;
    }
    line(
        out,
        format_args!("  listening port: {}", snapshot.listen_port),
    )
    .await?;

    let now = Instant::from_millis(EmbassyInstant::now().as_millis());
    let mut peer_count = 0usize;
    for peer in snapshot.peers.iter().flatten() {
        peer_count += 1;
        println(out, "").await?;
        let peer_key = encode_key(&peer.public_key);
        line(out, format_args!("peer: {}", peer_key.as_str())).await?;
        line(
            out,
            format_args!(
                "  type: {}  state: {}",
                peer_origin_name(peer.origin),
                peer_connection_name(peer.connection)
            ),
        )
        .await?;
        match peer.endpoint {
            Some(endpoint) => {
                line(
                    out,
                    format_args!(
                        "  endpoint: {endpoint} ({})",
                        if peer.endpoint_confirmed {
                            "confirmed"
                        } else {
                            "configured"
                        }
                    ),
                )
                .await?;
            }
            None => line(out, format_args!("  endpoint: none")).await?,
        }
        if let Some(relay) = peer.relay {
            let relay_key = encode_key(&relay);
            line(out, format_args!("  relay: {}", relay_key.as_str())).await?;
        }
        line(out, format_args!("  tunnel addresses: {}", peer.address)).await?;
        match peer.latest_handshake {
            Some(at) => {
                let age_ms = now.saturating_since(at).as_millis();
                if age_ms < 1_000 {
                    line(out, format_args!("  latest handshake: {age_ms}ms ago")).await?;
                } else {
                    line(
                        out,
                        format_args!("  latest handshake: {}s ago", age_ms / 1_000),
                    )
                    .await?;
                }
            }
            None => line(out, format_args!("  latest handshake: never")).await?,
        }
        line(
            out,
            format_args!("  transfer: rx={}B tx={}B", peer.rx_bytes, peer.tx_bytes),
        )
        .await?;
        match peer.persistent_keepalive {
            Some(interval) if interval.as_millis() % 1_000 == 0 => {
                line(
                    out,
                    format_args!("  persistent keepalive: {}s", interval.as_millis() / 1_000),
                )
                .await?;
            }
            Some(interval) => {
                line(
                    out,
                    format_args!("  persistent keepalive: {}ms", interval.as_millis()),
                )
                .await?;
            }
            None => line(out, format_args!("  persistent keepalive: off")).await?,
        }
    }

    if peer_count == 0 {
        line(out, format_args!("  peers: none")).await?;
    }
    Ok(())
}
