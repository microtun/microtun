//! RFC 2217 Telnet COM-PORT-OPTION server for the board's physical RS232 port.
//!
//! `microtun-telnet` owns Telnet/RFC 2217 negotiation and protocol state. This
//! module only translates typed serial requests to the ESP32-C3 UART/GPIOs and
//! bridges bytes between the UART and the microtun inner TCP stack.

use embassy_futures::select::{Either, select};
use embassy_net::{Stack, tcp::TcpSocket};
use embassy_time::{Duration, Timer, with_timeout};
use embedded_io_async::Write as _;
use esp_hal::uart::{
    Config as UartConfig, DataBits as HalDataBits, Parity as HalParity, RxError,
    StopBits as HalStopBits,
};
use heapless::{Deque, Vec};
use log::{debug, info, warn};
use microtun_telnet::{
    TelnetEvent, serial,
    server::{
        DataBits, InboundFlow, OutboundFlow, Parity, Purge, QueryOrSet, SerialRequest,
        ServerEncodeError, ServerEvent, ServerSession, StopBits,
    },
    write_data,
};

use crate::board::{Rs232Cts, Rs232Rts, Rs232Uart};

pub(crate) const RFC2217_PORT: u16 = 2217;
const TCP_BUFFER: usize = 1024;
const NET_CHUNK: usize = 512;
const UART_CHUNK: usize = 512;
const UART_TX_BURST: usize = 32;
const DEFERRED_RX: usize = 1024;
const CONTROL_BUFFER: usize = 96;
const MODEM_POLL: Duration = Duration::from_millis(50);
const KEEP_ALIVE: Duration = Duration::from_secs(15);
const CTS_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const XON_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const SIGNATURE: &[u8] = b"esp32-c3-dongle";
const XON: u8 = 0x11;
const XOFF: u8 = 0x13;

type Rfc2217Session = ServerSession<256, 12>;

#[derive(Clone, Copy)]
struct PortState {
    baud: u32,
    data_bits: DataBits,
    parity: Parity,
    stop_bits: StopBits,
    outbound_flow: OutboundFlow,
    inbound_flow: InboundFlow,
    dtr: bool,
    rts: bool,
    break_on: bool,
}

impl Default for PortState {
    fn default() -> Self {
        Self {
            baud: 115_200,
            data_bits: DataBits::Eight,
            parity: Parity::None,
            stop_bits: StopBits::One,
            outbound_flow: OutboundFlow::None,
            inbound_flow: InboundFlow::None,
            dtr: true,
            rts: true,
            break_on: false,
        }
    }
}

impl PortState {
    fn uart_config(self) -> UartConfig {
        let data_bits = match self.data_bits {
            DataBits::Five => HalDataBits::_5,
            DataBits::Six => HalDataBits::_6,
            DataBits::Seven => HalDataBits::_7,
            DataBits::Eight => HalDataBits::_8,
        };
        let parity = match self.parity {
            Parity::Odd => HalParity::Odd,
            Parity::Even => HalParity::Even,
            Parity::None | Parity::Mark | Parity::Space => HalParity::None,
        };
        let stop_bits = match self.stop_bits {
            StopBits::One => HalStopBits::_1,
            StopBits::Two => HalStopBits::_2,
            StopBits::OneAndAHalf => HalStopBits::_1p5,
        };

        UartConfig::default()
            .with_baudrate(self.baud)
            .with_data_bits(data_bits)
            .with_parity(parity)
            .with_stop_bits(stop_bits)
    }

    fn hardware_inbound_flow(self) -> bool {
        self.inbound_flow == InboundFlow::RtsCts
    }

    fn hardware_outbound_flow(self) -> bool {
        self.outbound_flow == OutboundFlow::RtsCts
    }

    fn software_inbound_flow(self) -> bool {
        self.inbound_flow == InboundFlow::XonXoff
    }

    fn software_outbound_flow(self) -> bool {
        self.outbound_flow == OutboundFlow::XonXoff
    }
}

fn data_bits_name(value: DataBits) -> &'static str {
    match value {
        DataBits::Five => "5",
        DataBits::Six => "6",
        DataBits::Seven => "7",
        DataBits::Eight => "8",
    }
}

fn parity_name(value: Parity) -> &'static str {
    match value {
        Parity::None => "none",
        Parity::Odd => "odd",
        Parity::Even => "even",
        Parity::Mark => "mark",
        Parity::Space => "space",
    }
}

fn stop_bits_name(value: StopBits) -> &'static str {
    match value {
        StopBits::One => "1",
        StopBits::OneAndAHalf => "1.5",
        StopBits::Two => "2",
    }
}

fn outbound_flow_name(value: OutboundFlow) -> &'static str {
    match value {
        OutboundFlow::None => "none",
        OutboundFlow::XonXoff => "xon/xoff",
        OutboundFlow::RtsCts => "rts/cts",
        OutboundFlow::Dcd => "dcd",
        OutboundFlow::Dsr => "dsr",
    }
}

fn inbound_flow_name(value: InboundFlow) -> &'static str {
    match value {
        InboundFlow::None => "none",
        InboundFlow::XonXoff => "xon/xoff",
        InboundFlow::RtsCts => "rts/cts",
        InboundFlow::Dtr => "dtr",
    }
}

fn log_serial_settings(prefix: &str, state: PortState) {
    info!(
        "RFC2217 {}: baud={} data_bits={} parity={} stop_bits={} outbound_flow={} inbound_flow={} rts={} dtr={}",
        prefix,
        state.baud,
        data_bits_name(state.data_bits),
        parity_name(state.parity),
        stop_bits_name(state.stop_bits),
        outbound_flow_name(state.outbound_flow),
        inbound_flow_name(state.inbound_flow),
        state.rts,
        state.dtr,
    );
}

#[derive(Default)]
struct FlowRuntime {
    // The attached serial device sent XOFF, so data heading from the RFC 2217
    // client to the UART must wait until the device sends XON.
    tx_paused_by_peer: bool,
    // We sent XOFF to the attached serial device because UART RX could not be
    // serviced immediately. Keep this so we only emit transitions and always
    // send a balancing XON before disabling software inbound flow.
    rx_peer_paused: bool,
}

#[derive(Clone, Copy)]
enum SerialAction {
    SignatureQuery(bool),
    Baud(QueryOrSet<u32>),
    DataBits(QueryOrSet<DataBits>),
    Parity(QueryOrSet<Parity>),
    StopBits(QueryOrSet<StopBits>),
    OutboundFlow(QueryOrSet<OutboundFlow>),
    InboundFlow(QueryOrSet<InboundFlow>),
    Rts(QueryOrSet<bool>),
    Dtr(QueryOrSet<bool>),
    Break(QueryOrSet<bool>),
    LineStateMask(u8),
    ModemStateMask(u8),
    Purge(Purge),
    Suspend,
    Resume,
}

impl From<SerialRequest<'_>> for SerialAction {
    fn from(request: SerialRequest<'_>) -> Self {
        match request {
            SerialRequest::Signature(text) => Self::SignatureQuery(text.is_empty()),
            SerialRequest::Baud(value) => Self::Baud(value),
            SerialRequest::DataBits(value) => Self::DataBits(value),
            SerialRequest::Parity(value) => Self::Parity(value),
            SerialRequest::StopBits(value) => Self::StopBits(value),
            SerialRequest::OutboundFlow(value) => Self::OutboundFlow(value),
            SerialRequest::InboundFlow(value) => Self::InboundFlow(value),
            SerialRequest::Rts(value) => Self::Rts(value),
            SerialRequest::Dtr(value) => Self::Dtr(value),
            SerialRequest::Break(value) => Self::Break(value),
            SerialRequest::LineStateMask(value) => Self::LineStateMask(value),
            SerialRequest::ModemStateMask(value) => Self::ModemStateMask(value),
            SerialRequest::Purge(value) => Self::Purge(value),
            SerialRequest::Suspend => Self::Suspend,
            SerialRequest::Resume => Self::Resume,
        }
    }
}

#[derive(Clone, Copy)]
enum NetworkAction {
    None,
    Data(u8),
    Serial(SerialAction),
    Break,
    SerialModeActive,
    SerialModeRefused,
}

fn network_action(event: Option<ServerEvent<'_>>) -> NetworkAction {
    match event {
        None => NetworkAction::None,
        Some(ServerEvent::Data(byte)) => NetworkAction::Data(byte),
        Some(ServerEvent::Serial(request)) => NetworkAction::Serial(request.into()),
        Some(ServerEvent::SerialModeActive) => NetworkAction::SerialModeActive,
        Some(ServerEvent::SerialModeRefused) => NetworkAction::SerialModeRefused,
        Some(ServerEvent::Telnet(TelnetEvent::Break)) => NetworkAction::Break,
        Some(ServerEvent::MalformedSerial(error)) => {
            warn!("malformed RFC2217 command: {:?}", error);
            NetworkAction::None
        }
        Some(ServerEvent::InvalidSerialRequest(error)) => {
            warn!("invalid RFC2217 command: {:?}", error);
            NetworkAction::None
        }
        Some(ServerEvent::Telnet(_)) => NetworkAction::None,
    }
}

fn cts_asserted(cts: &Rs232Cts) -> bool {
    // The SP3232 receiver inverts RS232 control levels: a positive/asserted
    // CTS level at the DE-9 appears low on MCU_CTS.
    cts.is_low()
}

fn modem_state(cts: &Rs232Cts) -> u8 {
    if cts_asserted(cts) {
        serial::modem_state::CTS
    } else {
        0
    }
}

fn drive_rts(rts: &mut Rs232Rts, asserted: bool) {
    // The SP3232 transmitter inverts MCU_RTS, so low is asserted on RS232.
    if asserted {
        rts.set_low();
    } else {
        rts.set_high();
    }
}

fn refresh_rts(state: PortState, rts: &mut Rs232Rts, receive_ready: bool, suspended: bool) {
    let asserted = state.rts && (!state.hardware_inbound_flow() || (receive_ready && !suspended));
    drive_rts(rts, asserted);
}

async fn apply_uart_config(uart: &mut Rs232Uart, state: PortState) -> bool {
    if let Err(error) = uart.flush_async().await {
        warn!("RFC2217 UART flush before reconfigure failed: {:?}", error);
        return false;
    }
    if let Err(error) = uart.apply_config(&state.uart_config()) {
        warn!("RFC2217 rejected UART configuration: {:?}", error);
        return false;
    }
    true
}

async fn reconfigure_uart<F>(uart: &mut Rs232Uart, state: &mut PortState, update: F) -> bool
where
    F: FnOnce(&mut PortState),
{
    let old = *state;
    update(state);
    if !apply_uart_config(uart, *state).await {
        *state = old;
        warn!(
            "RFC2217 UART parameter update failed; keeping baud={} data_bits={} parity={} stop_bits={}",
            old.baud,
            data_bits_name(old.data_bits),
            parity_name(old.parity),
            stop_bits_name(old.stop_bits),
        );
        return false;
    }

    info!(
        "RFC2217 UART parameters applied: baud={} data_bits={} parity={} stop_bits={} (was baud={} data_bits={} parity={} stop_bits={})",
        state.baud,
        data_bits_name(state.data_bits),
        parity_name(state.parity),
        stop_bits_name(state.stop_bits),
        old.baud,
        data_bits_name(old.data_bits),
        parity_name(old.parity),
        stop_bits_name(old.stop_bits),
    );
    true
}

async fn uart_write_raw(uart: &mut Rs232Uart, bytes: &[u8]) -> bool {
    let mut offset = 0;
    while offset < bytes.len() {
        match uart.write_async(&bytes[offset..]).await {
            Ok(0) => return false,
            Ok(written) => offset += written,
            Err(error) => {
                warn!("RFC2217 UART write failed: {:?}", error);
                return false;
            }
        }
    }
    true
}

async fn send_control(socket: &mut TcpSocket<'_>, bytes: &Vec<u8, CONTROL_BUFFER>) -> bool {
    if bytes.is_empty() {
        return true;
    }
    if let Err(error) = socket.write_all(bytes.as_slice()).await {
        warn!("RFC2217 control reply failed: {:?}", error);
        return false;
    }
    socket.flush().await.is_ok()
}

fn encoded(result: Result<(), ServerEncodeError>) -> bool {
    if let Err(error) = result {
        warn!("RFC2217 control encoding failed: {:?}", error);
        false
    } else {
        true
    }
}

async fn notify_line_error(
    socket: &mut TcpSocket<'_>,
    session: &Rfc2217Session,
    error: RxError,
) -> bool {
    let raw = match error {
        RxError::FifoOverflowed => serial::line_state::OVERRUN_ERROR,
        RxError::GlitchOccurred | RxError::FrameFormatViolated => serial::line_state::FRAMING_ERROR,
        RxError::ParityMismatch => serial::line_state::PARITY_ERROR,
        _ => serial::line_state::TIMEOUT_ERROR,
    };
    let Some(message) = session.serial_state().line_state(raw) else {
        return true;
    };

    let mut out = Vec::<u8, CONTROL_BUFFER>::new();
    if !encoded(session.queue_serial(message, &mut out)) {
        return false;
    }
    send_control(socket, &out).await
}

fn consume_received_flow_byte(state: PortState, flow: &mut FlowRuntime, byte: u8) -> bool {
    if !state.software_outbound_flow() {
        return false;
    }

    match byte {
        XOFF => {
            if !flow.tx_paused_by_peer {
                debug!("RFC2217 serial peer sent XOFF; pausing UART TX");
            }
            flow.tx_paused_by_peer = true;
            true
        }
        XON => {
            if flow.tx_paused_by_peer {
                debug!("RFC2217 serial peer sent XON; resuming UART TX");
            }
            flow.tx_paused_by_peer = false;
            true
        }
        _ => false,
    }
}

fn capture_serial_rx(
    state: PortState,
    flow: &mut FlowRuntime,
    deferred: &mut Deque<u8, DEFERRED_RX>,
    bytes: &[u8],
) -> bool {
    for &byte in bytes {
        if consume_received_flow_byte(state, flow, byte) {
            continue;
        }

        if deferred.push_back(byte).is_err() {
            warn!("RFC2217 deferred UART RX buffer overflow; closing session");
            return false;
        }
    }
    true
}

async fn drain_uart_ready(
    socket: &mut TcpSocket<'_>,
    session: &Rfc2217Session,
    uart: &mut Rs232Uart,
    state: PortState,
    flow: &mut FlowRuntime,
    deferred: &mut Deque<u8, DEFERRED_RX>,
) -> bool {
    let mut scratch = [0u8; 64];
    while uart.read_ready() {
        match uart.read_async(&mut scratch).await {
            Ok(0) => break,
            Ok(read) => {
                if !capture_serial_rx(state, flow, deferred, &scratch[..read]) {
                    return false;
                }
            }
            Err(error) => {
                warn!(
                    "RFC2217 UART receive error while servicing flow control: {:?}",
                    error
                );
                if !notify_line_error(socket, session, error).await {
                    return false;
                }
                break;
            }
        }
    }
    true
}

async fn wait_for_xon(
    socket: &mut TcpSocket<'_>,
    session: &Rfc2217Session,
    uart: &mut Rs232Uart,
    state: PortState,
    flow: &mut FlowRuntime,
    deferred: &mut Deque<u8, DEFERRED_RX>,
) -> bool {
    let mut scratch = [0u8; 64];
    while state.software_outbound_flow() && flow.tx_paused_by_peer {
        let read = match with_timeout(XON_WAIT_TIMEOUT, uart.read_async(&mut scratch)).await {
            Ok(Ok(read)) => read,
            Ok(Err(error)) => {
                warn!(
                    "RFC2217 UART receive error while waiting for XON: {:?}",
                    error
                );
                return notify_line_error(socket, session, error).await;
            }
            Err(_) => {
                warn!("RFC2217 XOFF remained active for 30 seconds; closing session");
                return false;
            }
        };

        if read == 0 {
            continue;
        }
        if !capture_serial_rx(state, flow, deferred, &scratch[..read]) {
            return false;
        }
    }
    true
}

async fn uart_write_all(
    socket: &mut TcpSocket<'_>,
    session: &Rfc2217Session,
    uart: &mut Rs232Uart,
    cts: &mut Rs232Cts,
    state: PortState,
    flow: &mut FlowRuntime,
    deferred: &mut Deque<u8, DEFERRED_RX>,
    bytes: &[u8],
) -> bool {
    if bytes.is_empty() {
        return true;
    }

    let mut offset = 0;
    while offset < bytes.len() {
        if state.software_outbound_flow() {
            // Poll RX between short TX bursts so a serial XOFF is acted on
            // quickly instead of only after a complete TCP chunk has already
            // been committed to the UART FIFO. Non-flow bytes are preserved
            // in `deferred` and delivered to the RFC 2217 client later.
            if !drain_uart_ready(socket, session, uart, state, flow, deferred).await
                || !wait_for_xon(socket, session, uart, state, flow, deferred).await
            {
                return false;
            }
        }

        if state.hardware_outbound_flow()
            && !cts_asserted(cts)
            && with_timeout(CTS_WAIT_TIMEOUT, cts.wait_for_low())
                .await
                .is_err()
        {
            warn!("RFC2217 CTS remained deasserted for 30 seconds; closing session");
            return false;
        }

        // Limit software-gated writes to small bursts so CTS and XON/XOFF
        // changes are observed between FIFO fills instead of once per TCP
        // chunk. At 9600 8N1 a 32-byte burst is roughly 33 ms on the wire.
        let end = (offset + UART_TX_BURST).min(bytes.len());
        match uart.write_async(&bytes[offset..end]).await {
            Ok(0) => return false,
            Ok(written) => offset += written,
            Err(error) => {
                warn!("RFC2217 UART write failed: {:?}", error);
                return false;
            }
        }

        // `esp-hal::Uart::write_async` only queues bytes into the hardware TX
        // FIFO; it does not wait for them to appear on the wire. When flow
        // control is active, drain each short burst before checking CTS or
        // XON/XOFF again. This bounds the amount of data sent after a peer
        // requests a stop to at most one burst instead of an entire UART FIFO.
        if state.software_outbound_flow() || state.hardware_outbound_flow() {
            if let Err(error) = uart.flush_async().await {
                warn!(
                    "RFC2217 UART flush during flow-controlled TX failed: {:?}",
                    error
                );
                return false;
            }
        }
    }
    true
}

async fn set_serial_receive_ready(
    uart: &mut Rs232Uart,
    rts: &mut Rs232Rts,
    state: PortState,
    flow: &mut FlowRuntime,
    receive_ready: bool,
    suspended: bool,
) -> bool {
    refresh_rts(state, rts, receive_ready, suspended);

    let should_pause = !receive_ready || suspended;
    if state.software_inbound_flow() {
        if should_pause != flow.rx_peer_paused {
            let byte = if should_pause { XOFF } else { XON };
            if !uart_write_raw(uart, &[byte]).await {
                return false;
            }
            flow.rx_peer_paused = should_pause;
            debug!(
                "RFC2217 sent {} to serial peer for inbound flow control",
                if should_pause { "XOFF" } else { "XON" }
            );
        }
    } else if flow.rx_peer_paused {
        // Never leave the attached serial device paused when software inbound
        // flow control is disabled or the session is being reset.
        if !uart_write_raw(uart, &[XON]).await {
            return false;
        }
        flow.rx_peer_paused = false;
        debug!("RFC2217 sent XON before disabling software inbound flow control");
    }
    true
}

async fn flush_deferred_rx(
    socket: &mut TcpSocket<'_>,
    deferred: &mut Deque<u8, DEFERRED_RX>,
) -> bool {
    if deferred.is_empty() {
        return true;
    }

    let mut chunk = [0u8; UART_CHUNK];
    while !deferred.is_empty() {
        let mut len = 0;
        while len < chunk.len() {
            let Some(byte) = deferred.pop_front() else {
                break;
            };
            chunk[len] = byte;
            len += 1;
        }
        if write_data(socket, &chunk[..len]).await.is_err() {
            return false;
        }
    }
    true
}

async fn send_modem_snapshot(
    socket: &mut TcpSocket<'_>,
    session: &Rfc2217Session,
    current: u8,
) -> bool {
    // Some RFC 2217 clients (notably pySerial) wait for an initial
    // NOTIFY-MODEMSTATE before exposing CTS/DSR/RI/CD. RFC 2217 allows the
    // access server to send modem-state notifications at any time. Respect a
    // client mask of zero, which explicitly suppresses notifications.
    let mask = session.serial_state().modem_state_mask();
    if mask == 0 {
        return true;
    }

    let mut out = Vec::<u8, CONTROL_BUFFER>::new();
    if !encoded(session.notify_modem_state(current & mask, &mut out)) {
        return false;
    }
    send_control(socket, &out).await
}

async fn notify_modem_change(
    socket: &mut TcpSocket<'_>,
    session: &mut Rfc2217Session,
    current: u8,
) -> bool {
    let message = session.serial_state_mut().modem_state_changed(current);
    let Some(message) = message else {
        return true;
    };

    // Keep the protocol baseline current even while negotiation is incomplete,
    // but only emit COM-PORT notifications once RFC 2217 is active.
    if !session.serial_active() || session.serial_state().tx_suspended() {
        return true;
    }

    let mut out = Vec::<u8, CONTROL_BUFFER>::new();
    if !encoded(session.queue_serial(message, &mut out)) {
        return false;
    }
    send_control(socket, &out).await
}

async fn handle_serial_request(
    socket: &mut TcpSocket<'_>,
    session: &mut Rfc2217Session,
    uart: &mut Rs232Uart,
    rts: &mut Rs232Rts,
    state: &mut PortState,
    flow: &mut FlowRuntime,
    deferred: &mut Deque<u8, DEFERRED_RX>,
    request: SerialAction,
) -> bool {
    let mut out = Vec::<u8, CONTROL_BUFFER>::new();

    let ok = match request {
        SerialAction::SignatureQuery(false) => return true,
        SerialAction::SignatureQuery(true) => {
            encoded(session.confirm_signature(SIGNATURE, &mut out))
        }
        SerialAction::Baud(request) => {
            if let QueryOrSet::Set(value) = request {
                info!("RFC2217 SET baud requested: {}", value);
                if (1..=5_000_000).contains(&value) {
                    let _ = reconfigure_uart(uart, state, |state| state.baud = value).await;
                } else {
                    warn!(
                        "RFC2217 rejected baud request {} (supported range 1..=5000000); keeping {}",
                        value, state.baud
                    );
                }
            }
            encoded(session.confirm_baud(state.baud, &mut out))
        }
        SerialAction::DataBits(request) => {
            if let QueryOrSet::Set(value) = request {
                info!("RFC2217 SET data bits requested: {}", data_bits_name(value));
                let _ = reconfigure_uart(uart, state, |state| state.data_bits = value).await;
            }
            encoded(session.confirm_data_bits(state.data_bits, &mut out))
        }
        SerialAction::Parity(request) => {
            if let QueryOrSet::Set(value) = request {
                info!("RFC2217 SET parity requested: {}", parity_name(value));
                if matches!(value, Parity::None | Parity::Odd | Parity::Even) {
                    let _ = reconfigure_uart(uart, state, |state| state.parity = value).await;
                } else {
                    warn!(
                        "RFC2217 parity {} is not supported by this UART; keeping {}",
                        parity_name(value),
                        parity_name(state.parity)
                    );
                }
            }
            // MARK and SPACE are valid RFC 2217 values but unsupported by this
            // UART API; confirm the unchanged setting instead.
            encoded(session.confirm_parity(state.parity, &mut out))
        }
        SerialAction::StopBits(request) => {
            if let QueryOrSet::Set(value) = request {
                info!("RFC2217 SET stop bits requested: {}", stop_bits_name(value));
                let _ = reconfigure_uart(uart, state, |state| state.stop_bits = value).await;
            }
            encoded(session.confirm_stop_bits(state.stop_bits, &mut out))
        }
        SerialAction::OutboundFlow(request) => {
            if let QueryOrSet::Set(value) = request {
                info!(
                    "RFC2217 SET outbound flow requested: {}",
                    outbound_flow_name(value)
                );
                match value {
                    OutboundFlow::None => {
                        state.outbound_flow = value;
                        state.inbound_flow = InboundFlow::None;
                        flow.tx_paused_by_peer = false;
                    }
                    OutboundFlow::XonXoff => {
                        // RFC 2217 defines the outbound flow-control settings
                        // as applying to both directions. A later inbound-only
                        // SET-CONTROL command may override the receive side.
                        state.outbound_flow = value;
                        state.inbound_flow = InboundFlow::XonXoff;
                        flow.tx_paused_by_peer = false;
                    }
                    OutboundFlow::RtsCts => {
                        state.outbound_flow = value;
                        state.inbound_flow = InboundFlow::RtsCts;
                        flow.tx_paused_by_peer = false;
                    }
                    OutboundFlow::Dcd | OutboundFlow::Dsr => {
                        warn!(
                            "RFC2217 outbound flow {} is not routed/supported; keeping {}",
                            outbound_flow_name(value),
                            outbound_flow_name(state.outbound_flow)
                        );
                    }
                }
                if !set_serial_receive_ready(
                    uart,
                    rts,
                    *state,
                    flow,
                    true,
                    session.serial_state().tx_suspended(),
                )
                .await
                {
                    return false;
                }
                info!(
                    "RFC2217 flow control now: outbound={} inbound={}",
                    outbound_flow_name(state.outbound_flow),
                    inbound_flow_name(state.inbound_flow)
                );
            }
            encoded(session.confirm_outbound_flow(state.outbound_flow, &mut out))
        }
        SerialAction::InboundFlow(request) => {
            if let QueryOrSet::Set(value) = request {
                info!(
                    "RFC2217 SET inbound flow requested: {}",
                    inbound_flow_name(value)
                );
                match value {
                    InboundFlow::None | InboundFlow::XonXoff | InboundFlow::RtsCts => {
                        state.inbound_flow = value
                    }
                    InboundFlow::Dtr => {
                        warn!(
                            "RFC2217 inbound flow DTR is not routed/supported; keeping {}",
                            inbound_flow_name(state.inbound_flow)
                        );
                    }
                }
                if !set_serial_receive_ready(
                    uart,
                    rts,
                    *state,
                    flow,
                    true,
                    session.serial_state().tx_suspended(),
                )
                .await
                {
                    return false;
                }
                info!(
                    "RFC2217 flow control now: outbound={} inbound={}",
                    outbound_flow_name(state.outbound_flow),
                    inbound_flow_name(state.inbound_flow)
                );
            }
            encoded(session.confirm_inbound_flow(state.inbound_flow, &mut out))
        }
        SerialAction::Rts(request) => {
            if let QueryOrSet::Set(value) = request {
                info!("RFC2217 SET RTS requested: {}", value);
                state.rts = value;
                if !set_serial_receive_ready(
                    uart,
                    rts,
                    *state,
                    flow,
                    true,
                    session.serial_state().tx_suspended(),
                )
                .await
                {
                    return false;
                }
                info!("RFC2217 RTS logical state now: {}", state.rts);
            }
            encoded(session.confirm_rts(state.rts, &mut out))
        }
        SerialAction::Dtr(request) => {
            if let QueryOrSet::Set(value) = request {
                // DTR is not routed by this board. Preserve a logical state so
                // RFC 2217 clients still get coherent query/confirmation data.
                info!(
                    "RFC2217 SET DTR requested: {} (logical only; DTR is not routed)",
                    value
                );
                state.dtr = value;
            }
            encoded(session.confirm_dtr(state.dtr, &mut out))
        }
        SerialAction::Break(request) => {
            if let QueryOrSet::Set(value) = request {
                info!("RFC2217 SET break requested: {}", value);
                if value {
                    let _ = uart.flush_async().await;
                    // esp-hal exposes a finite break primitive rather than a
                    // latched TX-break state. Emit about 250 ms of break.
                    uart.send_break((state.baud / 4).max(1));
                }
                state.break_on = value;
            }
            encoded(session.confirm_break(state.break_on, &mut out))
        }
        SerialAction::LineStateMask(value) => {
            encoded(session.confirm_line_state_mask(value, &mut out))
        }
        SerialAction::ModemStateMask(value) => {
            encoded(session.confirm_modem_state_mask(value, &mut out))
        }
        SerialAction::Purge(value) => {
            // Drain both the software-side deferred RX queue and immediately
            // available UART RX bytes for RECEIVE/BOTH. There is no public
            // esp-hal API to discard bytes already in the TX FIFO.
            if matches!(value, Purge::Receive | Purge::Both) {
                deferred.clear();
                let mut scratch = [0u8; 64];
                while uart.read_ready() {
                    match uart.read_async(&mut scratch).await {
                        Ok(read) => {
                            if read == 0 {
                                break;
                            }
                            for &byte in &scratch[..read] {
                                let _ = consume_received_flow_byte(*state, flow, byte);
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
            encoded(session.confirm_purge(value, &mut out))
        }
        SerialAction::Suspend => {
            // ServerSession has already applied the protocol suspend state.
            // RFC 2217 does not define an acknowledgement for SUSPEND/RESUME.
            set_serial_receive_ready(uart, rts, *state, flow, false, true).await
        }
        SerialAction::Resume => {
            set_serial_receive_ready(uart, rts, *state, flow, true, false).await
        }
    };

    ok && send_control(socket, &out).await
}

async fn flush_pending(
    socket: &mut TcpSocket<'_>,
    session: &Rfc2217Session,
    uart: &mut Rs232Uart,
    cts: &mut Rs232Cts,
    state: PortState,
    flow: &mut FlowRuntime,
    deferred: &mut Deque<u8, DEFERRED_RX>,
    pending: &mut Vec<u8, NET_CHUNK>,
) -> bool {
    if pending.is_empty() {
        return true;
    }
    let byte_count = pending.len();
    let ok = uart_write_all(
        socket,
        session,
        uart,
        cts,
        state,
        flow,
        deferred,
        pending.as_slice(),
    )
    .await;
    if ok {
        info!("RFC2217 transferred {} bytes to serial port", byte_count);
    }
    pending.clear();
    ok
}

async fn process_network_chunk(
    socket: &mut TcpSocket<'_>,
    uart: &mut Rs232Uart,
    rts: &mut Rs232Rts,
    cts: &mut Rs232Cts,
    session: &mut Rfc2217Session,
    state: &mut PortState,
    flow: &mut FlowRuntime,
    deferred: &mut Deque<u8, DEFERRED_RX>,
    bytes: &[u8],
) -> bool {
    let mut pending = Vec::<u8, NET_CHUNK>::new();

    for &byte in bytes {
        let mut reply = Vec::<u8, 32>::new();
        // Convert any request to an owned action immediately. SerialRequest may
        // borrow ServerSession's subnegotiation buffer, and dropping that borrow
        // lets the hardware handler use ServerSession's confirmation helpers.
        let action = network_action(session.feed(byte, &mut reply));

        if !reply.is_empty()
            && (socket.write_all(reply.as_slice()).await.is_err() || socket.flush().await.is_err())
        {
            return false;
        }

        match action {
            NetworkAction::None => {}
            NetworkAction::Data(value) => {
                if session.serial_active() && pending.push(value).is_err() {
                    if !flush_pending(
                        socket,
                        session,
                        uart,
                        cts,
                        *state,
                        flow,
                        deferred,
                        &mut pending,
                    )
                    .await
                    {
                        return false;
                    }
                    let _ = pending.push(value);
                }
            }
            NetworkAction::Serial(request) => {
                if !flush_pending(
                    socket,
                    session,
                    uart,
                    cts,
                    *state,
                    flow,
                    deferred,
                    &mut pending,
                )
                .await
                    || !handle_serial_request(
                        socket, session, uart, rts, state, flow, deferred, request,
                    )
                    .await
                {
                    return false;
                }
            }
            NetworkAction::Break => {
                if !flush_pending(
                    socket,
                    session,
                    uart,
                    cts,
                    *state,
                    flow,
                    deferred,
                    &mut pending,
                )
                .await
                {
                    return false;
                }
                let _ = uart.flush_async().await;
                uart.send_break((state.baud / 4).max(1));
            }
            NetworkAction::SerialModeActive => {
                info!("RFC2217 COM-PORT mode active");
                if !send_modem_snapshot(socket, session, modem_state(cts)).await {
                    return false;
                }
            }
            NetworkAction::SerialModeRefused => {
                warn!("RFC2217 peer refused required options");
                return false;
            }
        }
    }

    flush_pending(
        socket,
        session,
        uart,
        cts,
        *state,
        flow,
        deferred,
        &mut pending,
    )
    .await
}

async fn run_session(
    socket: &mut TcpSocket<'_>,
    uart: &mut Rs232Uart,
    rts: &mut Rs232Rts,
    cts: &mut Rs232Cts,
) {
    let mut state = PortState::default();
    let mut flow = FlowRuntime::default();
    let mut deferred = Deque::<u8, DEFERRED_RX>::new();
    let _ = apply_uart_config(uart, state).await;
    log_serial_settings("session defaults applied", state);
    refresh_rts(state, rts, true, false);

    let mut session = Rfc2217Session::new();
    let mut hello = Vec::<u8, 32>::new();
    if session.start(&mut hello).is_err()
        || socket.write_all(hello.as_slice()).await.is_err()
        || socket.flush().await.is_err()
    {
        return;
    }

    let mut net = [0u8; NET_CHUNK];
    let mut serial_buf = [0u8; UART_CHUNK];
    let mut last_modem = modem_state(cts);
    // Establish the upstream protocol helper's modem-state baseline so later
    // changes get the correct RFC 2217 delta bits.
    let _ = session.serial_state_mut().modem_state_changed(last_modem);

    loop {
        // Do not consume UART RX bytes until RFC 2217 and BINARY are active;
        // otherwise serial input arriving during Telnet negotiation would be
        // silently discarded. FLOWCONTROL-SUSPEND likewise pauses server-to-
        // client serial delivery.
        let serial_active = session.serial_active();
        let tx_suspended = session.serial_state().tx_suspended();
        if tx_suspended || !serial_active {
            match select(socket.read(&mut net), Timer::after(MODEM_POLL)).await {
                Either::First(Ok(0)) | Either::First(Err(_)) => break,
                Either::First(Ok(read)) => {
                    if !process_network_chunk(
                        socket,
                        uart,
                        rts,
                        cts,
                        &mut session,
                        &mut state,
                        &mut flow,
                        &mut deferred,
                        &net[..read],
                    )
                    .await
                    {
                        break;
                    }
                }
                Either::Second(_) => {}
            }
        } else {
            let io = select(socket.read(&mut net), uart.read_async(&mut serial_buf));
            match select(io, Timer::after(MODEM_POLL)).await {
                Either::First(Either::First(Ok(0))) | Either::First(Either::First(Err(_))) => break,
                Either::First(Either::First(Ok(read))) => {
                    if !process_network_chunk(
                        socket,
                        uart,
                        rts,
                        cts,
                        &mut session,
                        &mut state,
                        &mut flow,
                        &mut deferred,
                        &net[..read],
                    )
                    .await
                    {
                        break;
                    }
                }
                Either::First(Either::Second(Ok(read))) => {
                    if read != 0 && session.serial_active() {
                        if !capture_serial_rx(state, &mut flow, &mut deferred, &serial_buf[..read])
                        {
                            break;
                        }
                    }
                }
                Either::First(Either::Second(Err(error))) => {
                    warn!("RFC2217 UART receive error: {:?}", error);
                    if !notify_line_error(socket, &session, error).await {
                        break;
                    }
                }
                Either::Second(_) => {}
            }
        }

        // UART bytes captured while servicing software flow control are kept
        // in a small deferred queue. Deliver them only while RFC 2217 output
        // is active; FLOWCONTROL-SUSPEND intentionally holds them back.
        let serial_active = session.serial_active();
        let tx_suspended = session.serial_state().tx_suspended();
        if serial_active && !tx_suspended && !deferred.is_empty() {
            if !set_serial_receive_ready(uart, rts, state, &mut flow, false, tx_suspended).await {
                break;
            }

            let sent = flush_deferred_rx(socket, &mut deferred).await;
            let resumed =
                set_serial_receive_ready(uart, rts, state, &mut flow, true, tx_suspended).await;
            if !sent || !resumed {
                break;
            }
        }

        let current_modem = modem_state(cts);
        if current_modem != last_modem {
            if !notify_modem_change(socket, &mut session, current_modem).await {
                break;
            }
            last_modem = current_modem;
        }
    }

    // If we stopped the serial peer with XOFF, release it at the negotiated
    // baud rate before resetting the UART back to firmware defaults.
    let _ = set_serial_receive_ready(uart, rts, state, &mut flow, true, false).await;
    let defaults = PortState::default();
    let _ = apply_uart_config(uart, defaults).await;
    refresh_rts(defaults, rts, true, false);
}

/// Serve RFC 2217 forever on the supplied inner tunnel stack.
#[embassy_executor::task]
pub(crate) async fn rfc2217_task(
    stack: Stack<'static>,
    mut uart: Rs232Uart,
    mut rts: Rs232Rts,
    mut cts: Rs232Cts,
) -> ! {
    let mut rx = [0u8; TCP_BUFFER];
    let mut tx = [0u8; TCP_BUFFER];

    info!(
        "RFC2217 serial server listening on inner TCP port {}",
        RFC2217_PORT
    );
    loop {
        let mut socket = TcpSocket::new(stack, &mut rx, &mut tx);
        socket.set_keep_alive(Some(KEEP_ALIVE));
        // Serial traffic is often interactive and byte-sized; avoid Nagle's
        // added latency when a peer also uses delayed ACKs.
        socket.set_nagle_enabled(false);

        if let Err(error) = socket.accept(RFC2217_PORT).await {
            warn!("RFC2217 accept failed: {:?}", error);
            continue;
        }
        info!("RFC2217 serial client connected");
        run_session(&mut socket, &mut uart, &mut rts, &mut cts).await;
        socket.close();
        let _ = socket.flush().await;
        info!("RFC2217 serial client disconnected");
    }
}
