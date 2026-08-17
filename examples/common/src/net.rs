//! Shared network helpers for DNS, TCP socket policy, and SNTP.

use core::net::{IpAddr, SocketAddr};

use defmt_or_log::{info, warn};
use embassy_net::{
    IpAddress, Ipv4Address, Stack,
    dns::DnsQueryType,
    udp::{PacketMetadata, UdpSocket},
};
use embassy_time::{Duration, Instant, Timer, with_timeout};
use sntpc::{NtpContext, NtpResult, NtpTimestampGenerator, get_time};
use sntpc_net_embassy::UdpSocketWrapper;

pub const TCP_KEEP_ALIVE: Duration = Duration::from_secs(15);
pub const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(45);

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_DELAY: Duration = Duration::from_secs(2);
const NTP_TIMEOUT: Duration = Duration::from_secs(5);
const NTP_PACKET_BUFFER: usize = 128;
const NTP_LOCAL_PORT: u16 = 49152;

// DNS

async fn resolve_ipv4(stack: Stack<'static>, host: &str, service: &str) -> Ipv4Address {
    loop {
        info!("resolving {} host {}", service, host);
        let addresses =
            match with_timeout(DNS_TIMEOUT, stack.dns_query(host, DnsQueryType::A)).await {
                Ok(Ok(addresses)) => addresses,
                Ok(Err(error)) => {
                    warn!("{} DNS lookup failed: {:?}", service, error);
                    Timer::after(RETRY_DELAY).await;
                    continue;
                }
                Err(_) => {
                    warn!("{} DNS lookup timed out", service);
                    Timer::after(RETRY_DELAY).await;
                    continue;
                }
            };

        if let Some(address) = addresses.into_iter().find_map(|address| match address {
            IpAddress::Ipv4(ip) => Some(ip),
            _ => None,
        }) {
            info!("{} {} resolved to {}", service, host, address);
            return address;
        }

        warn!("{} DNS lookup returned no IPv4 address", service);
        Timer::after(RETRY_DELAY).await;
    }
}

pub async fn resolve_tracker_host(stack: Stack<'static>, host: &str) -> Ipv4Address {
    if let Ok(address) = host.parse::<core::net::Ipv4Addr>() {
        let octets = address.octets();
        return Ipv4Address::new(octets[0], octets[1], octets[2], octets[3]);
    }

    resolve_ipv4(stack, host, "Tracker").await
}

// SNTP

#[derive(Clone, Copy)]
struct BootTimestampGenerator {
    sample: Instant,
}

// sntpc only needs an approximate Unix time to select the correct 2^32-second
// NTP era. 2050 is a safe pivot for contemporary deployments; uptime supplies
// the changing part used for request/response timing.
const NTP_ERA_PIVOT_UNIX_SECS: u64 = 2_524_608_000; // 2050-01-01 UTC

impl BootTimestampGenerator {
    fn new() -> Self {
        Self {
            sample: Instant::from_secs(0),
        }
    }
}

impl NtpTimestampGenerator for BootTimestampGenerator {
    fn init(&mut self) {
        self.sample = Instant::now();
    }

    fn timestamp_sec(&self) -> u64 {
        NTP_ERA_PIVOT_UNIX_SECS.saturating_add(self.sample.as_secs())
    }

    fn timestamp_subsec_micros(&self) -> u32 {
        (self.sample.as_micros() % 1_000_000) as u32
    }
}

pub async fn query_ntp_time(stack: Stack<'static>, host: &str, port: u16) -> NtpResult {
    loop {
        let server_ip = resolve_ipv4(stack, host, "NTP server").await;

        let mut rx_meta = [PacketMetadata::EMPTY; 1];
        let mut tx_meta = [PacketMetadata::EMPTY; 1];
        let mut rx = [0u8; NTP_PACKET_BUFFER];
        let mut tx = [0u8; NTP_PACKET_BUFFER];
        let mut socket = UdpSocket::new(stack, &mut rx_meta, &mut rx, &mut tx_meta, &mut tx);
        if let Err(error) = socket.bind(NTP_LOCAL_PORT) {
            warn!("NTP UDP bind failed: {:?}", error);
            Timer::after(RETRY_DELAY).await;
            continue;
        }

        let server = SocketAddr::new(IpAddr::V4(server_ip), port);
        let wrapper = UdpSocketWrapper::new(socket);
        let context = NtpContext::new(BootTimestampGenerator::new());
        match with_timeout(NTP_TIMEOUT, get_time(server, &wrapper, context)).await {
            Ok(Ok(result)) => return result,
            Ok(Err(_)) => {
                warn!("SNTP request failed");
                Timer::after(RETRY_DELAY).await;
            }
            Err(_) => {
                warn!("SNTP request timed out");
                Timer::after(RETRY_DELAY).await;
            }
        }
    }
}

pub fn ntp_unix_time(result: &NtpResult) -> (u64, u32) {
    let unix_secs = result.sec();
    let unix_nanos = ((u64::from(result.sec_fraction()) * 1_000_000_000) >> 32) as u32;
    (unix_secs, unix_nanos)
}
