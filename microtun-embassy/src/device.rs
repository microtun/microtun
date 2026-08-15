//! The tunnel network device.
//!
//! microtun presents the encrypted tunnel to the rest of the firmware as an
//! [`embassy_net_driver_channel::Device`]. The application builds an ordinary
//! inner `embassy-net` [`Stack`](embassy_net::Stack) on top of this device
//! and thereby gets TCP/UDP sockets whose traffic is transparently
//! WireGuard-encapsulated.
//!
//! Data flow:
//!
//! * **Inner → tunnel (egress):** the inner stack writes an IP packet; it
//!   lands in the driver-channel *tx* queue; the [`TunnelRunner`] awaits it via
//!   `tx_buf`, encrypts it with the core, and sends the resulting outer
//!   datagram over the outer UDP socket.
//! * **Tunnel → inner (ingress):** an outer datagram arrives; the runner
//!   decrypts it; the plaintext inner packet is pushed into the driver-channel
//!   *rx* queue via `rx_buf` for the inner stack to receive.
//!
//! [`TunnelRunner`]: crate::runner::TunnelRunner

use core::task::Context;

use embassy_net_driver_channel::{
    Device, Runner, State,
    driver::{Capabilities, Driver, HardwareAddress, LinkState},
};

use crate::MTU;

/// Backing storage for the tunnel device's zero-copy channels. Allocate one
/// of these `'static` (typically via `static_cell::StaticCell`) and pass it to
/// [`new_tunnel`].
///
/// * `MAX_RX_PACKETS` — maximum decrypted inbound packets queued
/// * `MAX_TX_PACKETS` — maximum plaintext outbound packets queued
pub struct TunnelState<const MAX_RX_PACKETS: usize, const MAX_TX_PACKETS: usize> {
    inner: State<MTU, MAX_RX_PACKETS, MAX_TX_PACKETS>,
}

impl<const MAX_RX_PACKETS: usize, const MAX_TX_PACKETS: usize> Default
    for TunnelState<MAX_RX_PACKETS, MAX_TX_PACKETS>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_RX_PACKETS: usize, const MAX_TX_PACKETS: usize>
    TunnelState<MAX_RX_PACKETS, MAX_TX_PACKETS>
{
    pub const fn new() -> Self {
        Self {
            inner: State::new(),
        }
    }
}

/// Tunnel device whose advertised link MTU can be smaller than the backing
/// channel buffers.
///
/// The buffers remain sized to [`MTU`], while `embassy-net` sees the runtime
/// value through [`Driver::capabilities`]. This lets provisioned devices lower
/// their link MTU without requiring a different firmware build.
pub struct TunnelDevice<'d> {
    inner: Device<'d, MTU>,
    mtu: usize,
}

impl<'d> Driver for TunnelDevice<'d> {
    type RxToken<'a>
        = <Device<'d, MTU> as Driver>::RxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = <Device<'d, MTU> as Driver>::TxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, cx: &mut Context<'_>) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        Driver::receive(&mut self.inner, cx)
    }

    fn transmit(&mut self, cx: &mut Context<'_>) -> Option<Self::TxToken<'_>> {
        Driver::transmit(&mut self.inner, cx)
    }

    fn capabilities(&self) -> Capabilities {
        let mut capabilities = Driver::capabilities(&self.inner);
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }

    fn hardware_address(&self) -> HardwareAddress {
        Driver::hardware_address(&self.inner)
    }

    fn link_state(&mut self, cx: &mut Context<'_>) -> LinkState {
        Driver::link_state(&mut self.inner, cx)
    }
}

/// Create the tunnel device and its runner half.
///
/// The returned [`Device`] is handed to `embassy_net::new` to build the inner
/// stack. The returned [`Runner`] is owned by [`TunnelRunner`](crate::runner::TunnelRunner), which uses it
/// to move packets between the channels and the crypto core.
///
/// A WireGuard tunnel is a point-to-point IP link with no L2 addressing, so
/// the hardware address is [`HardwareAddress::Ip`] and the inner stack must be
/// configured with `medium-ip`.
pub fn new_tunnel<'d, const MAX_RX_PACKETS: usize, const MAX_TX_PACKETS: usize>(
    state: &'d mut TunnelState<MAX_RX_PACKETS, MAX_TX_PACKETS>,
) -> (Runner<'d, MTU>, Device<'d, MTU>) {
    embassy_net_driver_channel::new(&mut state.inner, HardwareAddress::Ip)
}

/// Create a tunnel device that advertises a runtime-selected MTU.
///
/// `mtu` may lower the link MTU from the compile-time buffer size [`MTU`], but
/// cannot exceed it because the driver-channel packet buffers are fixed-size.
pub fn new_tunnel_with_mtu<'d, const MAX_RX_PACKETS: usize, const MAX_TX_PACKETS: usize>(
    state: &'d mut TunnelState<MAX_RX_PACKETS, MAX_TX_PACKETS>,
    mtu: usize,
) -> (Runner<'d, MTU>, TunnelDevice<'d>) {
    assert!(mtu > 0, "tunnel MTU must be non-zero");
    assert!(mtu <= MTU, "tunnel MTU exceeds the embedded buffer size");

    let (runner, device) = embassy_net_driver_channel::new(&mut state.inner, HardwareAddress::Ip);
    (runner, TunnelDevice { inner: device, mtu })
}
