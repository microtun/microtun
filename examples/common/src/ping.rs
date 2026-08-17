use core::net::IpAddr;

use embassy_net::{
    Stack,
    icmp::{
        PacketMetadata,
        ping::{PingError, PingManager, PingParams},
    },
};
use embassy_time::{Duration, Timer};
use microtun_telnet_cli::{CliWrite, Error as CliError, ValueEnum};

pub const DEFAULT_PING_COUNT: u8 = 4;
pub const MAX_PING_COUNT: u8 = 16;
const PING_BUFFER_SIZE: usize = 64;
const PING_TIMEOUT: Duration = Duration::from_secs(2);
const PING_INTERVAL: Duration = Duration::from_secs(1);

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

async fn line<W>(out: &mut W, args: core::fmt::Arguments<'_>) -> Result<(), CliError>
where
    W: CliWrite + ?Sized,
{
    out.write_fmt(args).await?;
    out.write_bytes(b"\r\n").await?;
    Ok(())
}

pub async fn ping<W>(
    out: &mut W,
    iface_name: &str,
    iface: Stack<'static>,
    target: IpAddr,
    count: u8,
) -> Result<(), CliError>
where
    W: CliWrite + ?Sized,
{
    if count == 0 || count > MAX_PING_COUNT {
        line(
            out,
            format_args!("error: count must be between 1 and {MAX_PING_COUNT}"),
        )
        .await?;
        return Ok(());
    }

    if !iface.is_link_up() {
        line(
            out,
            format_args!("error: {iface_name} interface link is down"),
        )
        .await?;
        return Ok(());
    }

    let ipv6_source = match target {
        IpAddr::V4(_) if iface.config_v4().is_none() => {
            line(
                out,
                format_args!("error: {iface_name} interface has no IPv4 address"),
            )
            .await?;
            return Ok(());
        }
        IpAddr::V4(_) => None,
        IpAddr::V6(_) => match iface.config_v6() {
            Some(config) => Some(config.address.address()),
            None => {
                line(
                    out,
                    format_args!("error: {iface_name} interface has no IPv6 address"),
                )
                .await?;
                return Ok(());
            }
        },
    };

    let mut rx_meta = [PacketMetadata::EMPTY];
    let mut tx_meta = [PacketMetadata::EMPTY];
    let mut rx_buffer = [0u8; PING_BUFFER_SIZE];
    let mut tx_buffer = [0u8; PING_BUFFER_SIZE];
    let mut manager = PingManager::new(
        iface,
        &mut rx_meta,
        &mut rx_buffer,
        &mut tx_meta,
        &mut tx_buffer,
    );

    let mut params = PingParams::new(target);
    params
        .set_count(1)
        .set_timeout(PING_TIMEOUT)
        .set_rate_limit(Duration::from_millis(0));

    if let Some(source) = ipv6_source {
        params.set_source(source);
    }

    line(
        out,
        format_args!("PING {iface_name} {target}: {count} request(s)"),
    )
    .await?;

    let mut received = 0u8;
    let mut total_rtt_ms = 0u64;
    let mut transmitted = 0u8;

    for sequence in 1..=count {
        transmitted = transmitted.saturating_add(1);
        match manager.ping(&params).await {
            Ok(rtt) => {
                received = received.saturating_add(1);
                total_rtt_ms = total_rtt_ms.saturating_add(rtt.as_millis());
                line(
                    out,
                    format_args!(
                        "reply from {target}: iface={iface_name} seq={sequence} time={}ms",
                        rtt.as_millis()
                    ),
                )
                .await?;
            }
            Err(PingError::DestinationHostUnreachable) => {
                line(
                    out,
                    format_args!("timeout from {target}: iface={iface_name} seq={sequence}"),
                )
                .await?;
            }
            Err(error) => {
                line(
                    out,
                    format_args!("error pinging {target} via {iface_name}: {error:?}"),
                )
                .await?;
                break;
            }
        }

        if sequence != count {
            Timer::after(PING_INTERVAL).await;
        }
    }

    let loss = if transmitted == 0 {
        0
    } else {
        u16::from(transmitted.saturating_sub(received)) * 100 / u16::from(transmitted)
    };
    line(
        out,
        format_args!(
            "--- {iface_name} {target} ping statistics: {transmitted} transmitted, {received} received, {loss}% loss"
        ),
    )
    .await?;
    if received != 0 {
        line(
            out,
            format_args!("rtt avg={}ms", total_rtt_ms / u64::from(received)),
        )
        .await?;
    }

    Ok(())
}
