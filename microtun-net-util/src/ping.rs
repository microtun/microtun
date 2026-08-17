//! ICMP echo support for Embassy-net stacks.
//!
//! The ping runner owns the networking behavior and text output while callers
//! provide any [`embedded_io_async::Write`] implementation.

use core::{fmt::Write as _, net::IpAddr};

use embassy_net::{
    Stack,
    icmp::{
        BindError, PacketMetadata, RecvError, SendError,
        ping::{PingError as EmbassyPingError, PingManager, PingParams},
    },
};
use embassy_time::{Duration, Timer};
use embedded_io_async::Write;
use heapless::String;

pub const DEFAULT_PING_COUNT: u8 = 4;
pub const MAX_PING_COUNT: u8 = 16;
const PING_BUFFER_SIZE: usize = 64;
const PING_TIMEOUT: Duration = Duration::from_secs(2);
const PING_INTERVAL: Duration = Duration::from_secs(1);

fn format_ip(target: IpAddr) -> String<40> {
    // The longest textual IP address is an uncompressed IPv6 address at 39
    // bytes, so formatting into 40 bytes cannot overflow.
    let mut text = String::new();
    write!(&mut text, "{target}").expect("IpAddr formatting exceeded 40 bytes");
    text
}

fn format_u64(value: u64) -> String<20> {
    // u64::MAX is 20 decimal digits.
    let mut text = String::new();
    write!(&mut text, "{value}").expect("u64 formatting exceeded 20 bytes");
    text
}

async fn text<W>(out: &mut W, value: &str) -> Result<(), W::Error>
where
    W: Write + ?Sized,
{
    out.write_all(value.as_bytes()).await
}

async fn number<W>(out: &mut W, value: u64) -> Result<(), W::Error>
where
    W: Write + ?Sized,
{
    let value = format_u64(value);
    text(out, value.as_str()).await
}

async fn newline<W>(out: &mut W) -> Result<(), W::Error>
where
    W: Write + ?Sized,
{
    out.write_all(b"\r\n").await
}

async fn ping_error<W>(out: &mut W, error: EmbassyPingError) -> Result<(), W::Error>
where
    W: Write + ?Sized,
{
    let message = match error {
        EmbassyPingError::DestinationHostUnreachable => "DestinationHostUnreachable",
        EmbassyPingError::InvalidTargetAddress => "InvalidTargetAddress",
        EmbassyPingError::InvalidSourceAddress => "InvalidSourceAddress",
        EmbassyPingError::SocketSendTimeout => "SocketSendTimeout",
        EmbassyPingError::SocketBindError(BindError::InvalidState) => {
            "SocketBindError(InvalidState)"
        }
        EmbassyPingError::SocketBindError(BindError::InvalidEndpoint) => {
            "SocketBindError(InvalidEndpoint)"
        }
        EmbassyPingError::SocketBindError(BindError::NoRoute) => "SocketBindError(NoRoute)",
        EmbassyPingError::SocketSendError(SendError::NoRoute) => "SocketSendError(NoRoute)",
        EmbassyPingError::SocketSendError(SendError::SocketNotBound) => {
            "SocketSendError(SocketNotBound)"
        }
        EmbassyPingError::SocketSendError(SendError::PacketTooLarge) => {
            "SocketSendError(PacketTooLarge)"
        }
        EmbassyPingError::SocketRecvError(RecvError::Truncated) => "SocketRecvError(Truncated)",
    };

    text(out, message).await
}

/// Ping `target` through an explicit Embassy network stack.
///
/// Validation failures and per-probe ICMP errors are reported through `out`,
/// matching the behavior expected by the device CLI. The output is any async
/// embedded-I/O writer, so this utility does not depend on Telnet or another
/// shell crate.
pub async fn ping<W>(
    out: &mut W,
    iface_name: &str,
    iface: Stack<'static>,
    target: IpAddr,
    count: u8,
) -> Result<(), W::Error>
where
    W: Write + ?Sized,
{
    if count == 0 || count > MAX_PING_COUNT {
        text(out, "error: count must be between 1 and ").await?;
        number(out, u64::from(MAX_PING_COUNT)).await?;
        newline(out).await?;
        return Ok(());
    }

    if !iface.is_link_up() {
        text(out, "error: ").await?;
        text(out, iface_name).await?;
        text(out, " interface link is down").await?;
        newline(out).await?;
        return Ok(());
    }

    let ipv6_source = match target {
        IpAddr::V4(_) if iface.config_v4().is_none() => {
            text(out, "error: ").await?;
            text(out, iface_name).await?;
            text(out, " interface has no IPv4 address").await?;
            newline(out).await?;
            return Ok(());
        }
        IpAddr::V4(_) => None,
        IpAddr::V6(_) => match iface.config_v6() {
            Some(config) => Some(config.address.address()),
            None => {
                text(out, "error: ").await?;
                text(out, iface_name).await?;
                text(out, " interface has no IPv6 address").await?;
                newline(out).await?;
                return Ok(());
            }
        },
    };

    let target_text = format_ip(target);
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

    text(out, "PING ").await?;
    text(out, iface_name).await?;
    text(out, " ").await?;
    text(out, target_text.as_str()).await?;
    text(out, ": ").await?;
    number(out, u64::from(count)).await?;
    text(out, " request(s)").await?;
    newline(out).await?;

    let mut received = 0u8;
    let mut total_rtt_ms = 0u64;
    let mut transmitted = 0u8;

    for sequence in 1..=count {
        transmitted = transmitted.saturating_add(1);
        match manager.ping(&params).await {
            Ok(rtt) => {
                received = received.saturating_add(1);
                total_rtt_ms = total_rtt_ms.saturating_add(rtt.as_millis());
                text(out, "reply from ").await?;
                text(out, target_text.as_str()).await?;
                text(out, ": iface=").await?;
                text(out, iface_name).await?;
                text(out, " seq=").await?;
                number(out, u64::from(sequence)).await?;
                text(out, " time=").await?;
                number(out, rtt.as_millis()).await?;
                text(out, "ms").await?;
                newline(out).await?;
            }
            Err(EmbassyPingError::DestinationHostUnreachable) => {
                text(out, "timeout from ").await?;
                text(out, target_text.as_str()).await?;
                text(out, ": iface=").await?;
                text(out, iface_name).await?;
                text(out, " seq=").await?;
                number(out, u64::from(sequence)).await?;
                newline(out).await?;
            }
            Err(error) => {
                text(out, "error pinging ").await?;
                text(out, target_text.as_str()).await?;
                text(out, " via ").await?;
                text(out, iface_name).await?;
                text(out, ": ").await?;
                ping_error(out, error).await?;
                newline(out).await?;
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

    text(out, "--- ").await?;
    text(out, iface_name).await?;
    text(out, " ").await?;
    text(out, target_text.as_str()).await?;
    text(out, " ping statistics: ").await?;
    number(out, u64::from(transmitted)).await?;
    text(out, " transmitted, ").await?;
    number(out, u64::from(received)).await?;
    text(out, " received, ").await?;
    number(out, u64::from(loss)).await?;
    text(out, "% loss").await?;
    newline(out).await?;

    if received != 0 {
        text(out, "rtt avg=").await?;
        number(out, total_rtt_ms / u64::from(received)).await?;
        text(out, "ms").await?;
        newline(out).await?;
    }

    Ok(())
}
