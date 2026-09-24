//! Network runners and setup-mode services for the Nucleo firmware.

use core::net::IpAddr;

use embassy_net::{Stack, udp::PacketMetadata};
use microtun_embassy::TunnelRunner;
use microtun_firmware_common::{
    configuration::DeviceIdentity,
    net as common_net,
    tunnel::{self as common_tunnel, OUTER_UDP_PACKETS},
};
use static_cell::StaticCell;

use crate::{DEVICE_MODEL, HardwareRng, InnerDevice, OuterDevice};

#[embassy_executor::task]
pub(crate) async fn outer_net_task(mut runner: embassy_net::Runner<'static, OuterDevice>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
pub(crate) async fn inner_net_task(mut runner: embassy_net::Runner<'static, InnerDevice>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
pub(crate) async fn setup_dhcp_task(stack: Stack<'static>) {
    common_net::run_setup_dhcp(stack).await
}

#[embassy_executor::task]
pub(crate) async fn setup_mdns_task(stack: Stack<'static>, identity: DeviceIdentity) {
    common_net::run_setup_mdns(stack, identity, DEVICE_MODEL).await
}

#[embassy_executor::task]
pub(crate) async fn tunnel_task(
    runner: TunnelRunner<'static, HardwareRng>,
    outer_stack: Stack<'static>,
) -> ! {
    // Held in statics rather than on this task's stack. At OUTER_SIZE (1500)
    // times OUTER_UDP_PACKETS this is roughly 12 KiB, which is large enough
    // that burying it in a task stack makes the executor's stack requirement
    // invisible at the call site and turns any future increase into a stack
    // overflow rather than a link error. In a static it shows up in the map
    // alongside the rest of the budget.
    static RX_META: StaticCell<[PacketMetadata; OUTER_UDP_PACKETS]> = StaticCell::new();
    static TX_META: StaticCell<[PacketMetadata; OUTER_UDP_PACKETS]> = StaticCell::new();
    static RX: StaticCell<[u8; microtun_embassy::OUTER_SIZE * OUTER_UDP_PACKETS]> =
        StaticCell::new();
    static TX: StaticCell<[u8; microtun_embassy::OUTER_SIZE * OUTER_UDP_PACKETS]> =
        StaticCell::new();

    let rx_meta = RX_META.init([PacketMetadata::EMPTY; OUTER_UDP_PACKETS]);
    let tx_meta = TX_META.init([PacketMetadata::EMPTY; OUTER_UDP_PACKETS]);
    let rx = RX.init([0u8; microtun_embassy::OUTER_SIZE * OUTER_UDP_PACKETS]);
    let tx = TX.init([0u8; microtun_embassy::OUTER_SIZE * OUTER_UDP_PACKETS]);

    common_tunnel::run(runner, outer_stack, rx_meta, rx, tx_meta, tx).await
}

#[embassy_executor::task]
pub(crate) async fn peers_resolver_task(
    inner_stack: Stack<'static>,
    local_public_key: [u8; 32],
    tracker_tunnel_addr: IpAddr,
    websocket_seed: [u8; 32],
) -> ! {
    common_tunnel::run_peer_resolver(
        inner_stack,
        local_public_key,
        tracker_tunnel_addr,
        websocket_seed,
    )
    .await
}
