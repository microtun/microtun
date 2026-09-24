//! Network services and link diagnostics for the ESP32-C6 firmware.

use core::{cell::RefCell, net::IpAddr};

use embassy_executor::Spawner;
use embassy_net::{Stack, StackResources, udp::PacketMetadata};
use embassy_sync::blocking_mutex::{Mutex as BlockingMutex, raw::CriticalSectionRawMutex};
use embassy_time::{Duration as EmbassyDuration, Timer, with_timeout};
use esp_radio::wifi::{
    Config as WifiConfig, ControllerConfig, Interface, WifiController, ap::AccessPointConfig,
};
use log::{info, warn};
use microtun_embassy::TunnelRunner;
use microtun_firmware_common::{
    configuration::DeviceIdentity,
    net::{self as common_net, fallback_static_ipv4_config},
    tunnel::{self as common_tunnel, OUTER_UDP_PACKETS},
};
use microtun_net_util::{
    FALLBACK_DEVICE_IPV4, FALLBACK_IPV4_PREFIX_LEN, MICROTUN_MDNS_SERVICE, device_ap_ssid,
};
use static_cell::StaticCell;

use crate::{DEVICE_MODEL, HardwareRng, InnerDevice, OuterDevice};

#[derive(Clone, Copy)]
pub(crate) struct WifiLinkSnapshot {
    pub(crate) associated: bool,
    pub(crate) bssid: [u8; 6],
    pub(crate) channel: u8,
    pub(crate) rssi_dbm: Option<i32>,
    pub(crate) reconnects: u32,
}

impl WifiLinkSnapshot {
    const fn empty() -> Self {
        Self {
            associated: false,
            bssid: [0; 6],
            channel: 0,
            rssi_dbm: None,
            reconnects: 0,
        }
    }
}

static WIFI_LINK: BlockingMutex<CriticalSectionRawMutex, RefCell<WifiLinkSnapshot>> =
    BlockingMutex::new(RefCell::new(WifiLinkSnapshot::empty()));

pub(crate) fn wifi_link_snapshot() -> WifiLinkSnapshot {
    WIFI_LINK.lock(|status| *status.borrow())
}

fn publish_wifi_link(snapshot: WifiLinkSnapshot) {
    WIFI_LINK.lock(|status| *status.borrow_mut() = snapshot);
}

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
pub(crate) async fn wifi_connection_task(mut controller: WifiController<'static>) -> ! {
    info!("Wi-Fi connection task started");
    let mut ever_connected = false;
    let mut reconnects = 0u32;

    loop {
        info!("connecting to configured Wi-Fi network");
        match controller.connect_async().await {
            Ok(connected) => {
                info!("Wi-Fi station connected: {:?}", connected);
                if ever_connected {
                    reconnects = reconnects.saturating_add(1);
                } else {
                    ever_connected = true;
                }

                let bssid = connected.bssid;
                let channel = connected.channel;
                loop {
                    publish_wifi_link(WifiLinkSnapshot {
                        associated: true,
                        bssid,
                        channel,
                        rssi_dbm: controller.rssi().ok(),
                        reconnects,
                    });

                    // Refresh RSSI every two seconds while still using the
                    // stable disconnect waiter exposed by esp-radio. This keeps
                    // signal strength useful for diagnosing intermittent links.
                    match with_timeout(
                        EmbassyDuration::from_secs(2),
                        controller.wait_for_disconnect_async(),
                    )
                    .await
                    {
                        Ok(Ok(disconnected)) => {
                            warn!("Wi-Fi disconnected: {:?}", disconnected);
                            break;
                        }
                        Ok(Err(error)) => {
                            warn!("Wi-Fi disconnect wait failed: {:?}", error);
                            break;
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(error) => warn!("Wi-Fi connect failed: {:?}", error),
        }

        publish_wifi_link(WifiLinkSnapshot {
            reconnects,
            ..WifiLinkSnapshot::empty()
        });
        Timer::after_secs(2).await;
    }
}

#[embassy_executor::task]
pub(crate) async fn tunnel_task(
    runner: TunnelRunner<'static, HardwareRng>,
    outer_stack: Stack<'static>,
) -> ! {
    let mut rx_meta = alloc::vec![PacketMetadata::EMPTY; OUTER_UDP_PACKETS].into_boxed_slice();
    let mut tx_meta = alloc::vec![PacketMetadata::EMPTY; OUTER_UDP_PACKETS].into_boxed_slice();
    let mut rx =
        alloc::vec![0u8; microtun_embassy::OUTER_SIZE * OUTER_UDP_PACKETS].into_boxed_slice();
    let mut tx =
        alloc::vec![0u8; microtun_embassy::OUTER_SIZE * OUTER_UDP_PACKETS].into_boxed_slice();

    common_tunnel::run(
        runner,
        outer_stack,
        rx_meta.as_mut(),
        rx.as_mut(),
        tx_meta.as_mut(),
        tx.as_mut(),
    )
    .await
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

/// Bring up the SoftAP an unconfigured device serves setup mode on.
pub(crate) async fn start_setup_ap(
    spawner: Spawner,
    wifi: esp_hal::peripherals::WIFI<'static>,
    identity: &DeviceIdentity,
    seed: u64,
) -> (Stack<'static>, [u8; 6]) {
    let ssid = device_ap_ssid(identity.device_id().as_str()).expect("device ID fits SSID");
    let access_point_config =
        WifiConfig::AccessPoint(AccessPointConfig::default().with_ssid(ssid.as_str()));
    let wifi_interface = Interface::access_point();
    let mac = wifi_interface.mac_address();

    // Creating the controller applies the initial config and starts the radio,
    // so the AP needs no connection task the way the station path does. It must
    // outlive this function, or dropping it would stop the AP.
    static WIFI_CONTROLLER: StaticCell<WifiController<'static>> = StaticCell::new();
    let _controller = WIFI_CONTROLLER.init(
        WifiController::new(
            wifi,
            ControllerConfig::default().with_initial_config(access_point_config),
        )
        .expect("create setup Wi-Fi access point"),
    );

    // The device keeps a predictable fixed address, while a tiny DHCP server configures the
    // setup host automatically after it joins this AP. Static-IP setup still
    // reserves embassy-net's built-in DNS slot. Add DHCP server UDP, mDNS UDP, Telnet TCP,
    // and one transient ICMP slot for the setup shell's `ping net` command. Four slots
    // made ping fail whenever the other services were active.
    static SETUP_RESOURCES: StaticCell<StackResources<5>> = StaticCell::new();
    let (stack, runner) = embassy_net::new(
        wifi_interface,
        embassy_net::Config::ipv4_static(fallback_static_ipv4_config()),
        SETUP_RESOURCES.init(StackResources::new()),
        seed,
    );
    spawner.spawn(outer_net_task(runner).unwrap());

    info!(
        "setup mode: advertising open Wi-Fi network {}",
        ssid.as_str()
    );
    stack.wait_link_up().await;
    spawner.spawn(setup_dhcp_task(stack).unwrap());
    spawner.spawn(setup_mdns_task(stack, *identity).unwrap());
    info!(
        "setup mode: advertising {} over mDNS/DNS-SD",
        MICROTUN_MDNS_SERVICE
    );
    info!(
        "setup mode: join {}; DHCP will configure the host on {}.{}.{}.0/{}",
        ssid.as_str(),
        FALLBACK_DEVICE_IPV4[0],
        FALLBACK_DEVICE_IPV4[1],
        FALLBACK_DEVICE_IPV4[2],
        FALLBACK_IPV4_PREFIX_LEN
    );

    (stack, mac)
}
