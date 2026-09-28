use std::{collections::VecDeque, io, time::Duration};

use embedded_io_adapters::tokio_1::FromTokio;
use heapless::Vec as HeaplessVec;
use microtun_telnet::{
    OPT_COM_PORT, Side, TelnetEvent,
    client::{ClientEncodeError, ClientEvent, SerialEvent},
    serial, write_data_unflushed,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time,
};

use crate::commands::serial_settings::{SerialProtocol, SerialSettings};

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum SessionEvent {
    Data(Vec<u8>),
    OptionEnabled { side: Side, option: u8 },
    OptionDisabled { side: Side, option: u8 },
    Serial(SerialEvent),
}

struct SerialSession {
    stream: TcpStream,
    protocol: SerialProtocol,
    pending: VecDeque<SessionEvent>,
}

impl SerialSession {
    async fn connect(target: &str, port: u16, timeout: Duration) -> Result<Self, String> {
        let stream = match time::timeout(timeout, TcpStream::connect((target, port))).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => return Err(format!("connect to {target}:{port}: {error}")),
            Err(_) => return Err(format!("connect to {target}:{port}: timed out")),
        };
        stream
            .set_nodelay(true)
            .map_err(|error| format!("set TCP_NODELAY for {target}:{port}: {error}"))?;

        Ok(Self {
            stream,
            protocol: SerialProtocol::new(),
            pending: VecDeque::new(),
        })
    }

    async fn start_negotiation(&mut self) -> io::Result<()> {
        let mut wire = HeaplessVec::<u8, 32>::new();
        self.protocol
            .enter_serial_mode(&mut wire)
            .map_err(protocol_error)?;
        self.stream.write_all(wire.as_slice()).await
    }

    async fn next_event(&mut self) -> io::Result<Option<SessionEvent>> {
        if let Some(event) = self.pending.pop_front() {
            return Ok(Some(event));
        }

        loop {
            let mut wire = [0u8; 4096];
            let len = self.stream.read(&mut wire).await?;
            if len == 0 {
                return Ok(None);
            }
            self.process_wire_bytes(&wire[..len]).await?;
            if let Some(event) = self.pending.pop_front() {
                return Ok(Some(event));
            }
        }
    }

    async fn process_wire_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut negotiation_replies = Vec::new();
        let mut data = Vec::new();

        for &byte in bytes {
            let mut reply = HeaplessVec::<u8, 32>::new();
            let event = self.protocol.feed(byte, &mut reply);
            negotiation_replies.extend_from_slice(reply.as_slice());

            match event {
                Some(ClientEvent::Data(byte)) => data.push(byte),
                Some(ClientEvent::SerialModeActive) => {
                    flush_data_event(&mut self.pending, &mut data);
                    self.pending.push_back(SessionEvent::OptionEnabled {
                        side: Side::Us,
                        option: OPT_COM_PORT,
                    });
                }
                Some(ClientEvent::SerialModeRefused) => {
                    flush_data_event(&mut self.pending, &mut data);
                    self.pending.push_back(SessionEvent::OptionDisabled {
                        side: Side::Us,
                        option: OPT_COM_PORT,
                    });
                }
                Some(ClientEvent::Serial(event)) => {
                    flush_data_event(&mut self.pending, &mut data);
                    self.pending.push_back(SessionEvent::Serial(event));
                }
                Some(ClientEvent::MalformedSerial(error)) => {
                    tracing::warn!(?error, "malformed serial message");
                }
                Some(ClientEvent::Telnet(TelnetEvent::OptionEnabled { side, option })) => {
                    flush_data_event(&mut self.pending, &mut data);
                    self.pending
                        .push_back(SessionEvent::OptionEnabled { side, option });
                }
                Some(ClientEvent::Telnet(
                    TelnetEvent::OptionDisabled { side, option }
                    | TelnetEvent::OptionRefused { side, option },
                )) => {
                    flush_data_event(&mut self.pending, &mut data);
                    self.pending
                        .push_back(SessionEvent::OptionDisabled { side, option });
                }
                Some(ClientEvent::Telnet(
                    TelnetEvent::Data(_)
                    | TelnetEvent::Interrupt
                    | TelnetEvent::Break
                    | TelnetEvent::AreYouThere
                    | TelnetEvent::EraseCharacter
                    | TelnetEvent::EraseLine
                    | TelnetEvent::Subnegotiation(_),
                ))
                | None => {}
            }
        }

        flush_data_event(&mut self.pending, &mut data);
        if !negotiation_replies.is_empty() {
            self.stream.write_all(&negotiation_replies).await?;
        }
        Ok(())
    }

    async fn send_data(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut stream = FromTokio::new(&mut self.stream);
        write_data_unflushed(&mut stream, bytes).await
    }

    async fn send_serial(&mut self, message: serial::Message<'_>) -> io::Result<()> {
        let mut wire = HeaplessVec::<u8, 512>::new();
        self.protocol
            .queue_serial(message, &mut wire)
            .map_err(protocol_error)?;
        self.stream.write_all(wire.as_slice()).await
    }

    async fn apply_initial_configuration(&mut self, settings: SerialSettings) -> io::Result<()> {
        let mut wire = HeaplessVec::<u8, 64>::new();
        settings
            .queue(&self.protocol, &mut wire)
            .map_err(protocol_error)?;
        if !wire.is_empty() {
            self.stream.write_all(wire.as_slice()).await?;
        }
        Ok(())
    }

    async fn query_initial_configuration(&mut self) -> io::Result<()> {
        let mut wire = HeaplessVec::<u8, 128>::new();
        self.protocol
            .queue_initial_serial_query(&mut wire)
            .map_err(protocol_error)?;
        self.stream.write_all(wire.as_slice()).await
    }
}

fn flush_data_event(pending: &mut VecDeque<SessionEvent>, data: &mut Vec<u8>) {
    if !data.is_empty() {
        pending.push_back(SessionEvent::Data(std::mem::take(data)));
    }
}

fn protocol_error(error: ClientEncodeError) -> io::Error {
    match error {
        ClientEncodeError::SerialInactive => io::Error::new(
            io::ErrorKind::Unsupported,
            "serial COM-PORT-OPTION is not active",
        ),
        ClientEncodeError::BufferFull => io::Error::new(
            io::ErrorKind::InvalidInput,
            "Telnet/serial command exceeds local encode buffer",
        ),
        ClientEncodeError::InvalidOrigin => io::Error::new(
            io::ErrorKind::InvalidInput,
            "server-origin serial message cannot be sent as a client command",
        ),
    }
}

fn log_serial_event(event: &SerialEvent) {
    match event {
        SerialEvent::Signature(text) => {
            tracing::debug!(signature = ?String::from_utf8_lossy(text), "serial server signature");
        }
        SerialEvent::BaudRate(value) => tracing::debug!(baud_rate = *value, "serial baud rate"),
        SerialEvent::DataSize(value) => tracing::debug!(data_bits = *value, "serial data size"),
        SerialEvent::Parity(value) => tracing::debug!(parity = *value, "serial parity"),
        SerialEvent::StopSize(value) => tracing::debug!(stop_size = *value, "serial stop size"),
        SerialEvent::Control(value) => tracing::debug!(control = *value, "serial control"),
        SerialEvent::LineState(value) => {
            tracing::debug!(line_state = %format_args!("0x{value:02x}"), "serial line state");
        }
        SerialEvent::ModemState(value) => {
            tracing::debug!(modem_state = %format_args!("0x{value:02x}"), "serial modem state");
        }
        SerialEvent::FlowControlSuspend => tracing::debug!("serial flow suspended"),
        SerialEvent::FlowControlResume => tracing::debug!("serial flow resumed"),
        SerialEvent::LineStateMask(value) => {
            tracing::debug!(
                line_state_mask = %format_args!("0x{value:02x}"),
                "serial line-state mask"
            );
        }
        SerialEvent::ModemStateMask(value) => {
            tracing::debug!(
                modem_state_mask = %format_args!("0x{value:02x}"),
                "serial modem-state mask"
            );
        }
        SerialEvent::PurgeData(value) => tracing::debug!(purge = *value, "serial purge"),
    }
}

#[derive(Clone, Copy, Debug)]
struct SerialState {
    baud: u32,
    data_bits: u8,
    parity: u8,
    stop_bits: u8,
    flow_out: u8,
    flow_in: u8,
    dtr: bool,
    rts: bool,
    break_state: bool,
}

impl Default for SerialState {
    fn default() -> Self {
        Self {
            baud: 9600,
            data_bits: 8,
            parity: serial::parity::NONE,
            stop_bits: serial::stop_size::ONE,
            flow_out: serial::control::NO_OUTBOUND_FLOW,
            flow_in: serial::control::NO_INBOUND_FLOW,
            dtr: false,
            rts: false,
            break_state: false,
        }
    }
}

impl SerialState {
    fn update(&mut self, event: &SerialEvent) {
        match event {
            SerialEvent::BaudRate(value) if *value != 0 => self.baud = *value,
            SerialEvent::DataSize(value) if (5..=8).contains(value) => self.data_bits = *value,
            SerialEvent::Parity(value)
                if matches!(
                    *value,
                    serial::parity::NONE
                        | serial::parity::ODD
                        | serial::parity::EVEN
                        | serial::parity::MARK
                        | serial::parity::SPACE
                ) =>
            {
                self.parity = *value;
            }
            SerialEvent::StopSize(value)
                if matches!(
                    *value,
                    serial::stop_size::ONE
                        | serial::stop_size::TWO
                        | serial::stop_size::ONE_AND_A_HALF
                ) =>
            {
                self.stop_bits = *value;
            }
            SerialEvent::Control(value) => match *value {
                serial::control::NO_OUTBOUND_FLOW
                | serial::control::XON_XOFF_OUTBOUND
                | serial::control::HARDWARE_OUTBOUND
                | serial::control::DCD_OUTBOUND
                | serial::control::DSR_OUTBOUND => self.flow_out = *value,
                serial::control::NO_INBOUND_FLOW
                | serial::control::XON_XOFF_INBOUND
                | serial::control::HARDWARE_INBOUND
                | serial::control::DTR_INBOUND => self.flow_in = *value,
                serial::control::BREAK_ON => self.break_state = true,
                serial::control::BREAK_OFF => self.break_state = false,
                serial::control::DTR_ON => self.dtr = true,
                serial::control::DTR_OFF => self.dtr = false,
                serial::control::RTS_ON => self.rts = true,
                serial::control::RTS_OFF => self.rts = false,
                _ => {}
            },
            _ => {}
        }
    }
}

#[derive(Debug)]
enum DeviceEvent {
    Data(Vec<u8>),
    Baud(u32),
    DataSize(u8),
    Parity(u8),
    StopSize(u8),
    FlowOut(u8),
    FlowIn(u8),
    Dtr(bool),
    Rts(bool),
    Break(bool),
    Purge(u8),
    FlowSuspend,
    FlowResume,
}

mod cuse_device;

async fn negotiate_serial(
    target: &str,
    port: u16,
    timeout: Duration,
) -> Result<(SerialSession, VecDeque<SessionEvent>), String> {
    let mut session = SerialSession::connect(target, port, timeout).await?;
    session
        .start_negotiation()
        .await
        .map_err(|error| format!("start Telnet/serial negotiation: {error}"))?;

    let mut pre_session = VecDeque::new();
    let negotiation = time::timeout(timeout, async {
        loop {
            match session.next_event().await? {
                Some(SessionEvent::OptionEnabled {
                    side: Side::Us,
                    option: OPT_COM_PORT,
                }) => return Ok::<_, io::Error>(()),
                Some(SessionEvent::OptionDisabled {
                    side: Side::Us,
                    option: OPT_COM_PORT,
                }) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "server refused serial COM-PORT-OPTION",
                    ));
                }
                Some(event) => pre_session.push_back(event),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "server closed during serial negotiation",
                    ));
                }
            }
        }
    })
    .await;

    match negotiation {
        Ok(Ok(())) => Ok((session, pre_session)),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err(format!(
            "serial COM-PORT-OPTION negotiation timed out after {}s",
            timeout.as_secs()
        )),
    }
}

async fn send_device_event(session: &mut SerialSession, event: DeviceEvent) -> io::Result<()> {
    use serial::{Message, Origin};

    match event {
        DeviceEvent::Data(data) => session.send_data(&data).await,
        DeviceEvent::Baud(value) => {
            session
                .send_serial(Message::SetBaudRate {
                    origin: Origin::Client,
                    value,
                })
                .await
        }
        DeviceEvent::DataSize(value) => {
            session
                .send_serial(Message::SetDataSize {
                    origin: Origin::Client,
                    value,
                })
                .await
        }
        DeviceEvent::Parity(value) => {
            session
                .send_serial(Message::SetParity {
                    origin: Origin::Client,
                    value,
                })
                .await
        }
        DeviceEvent::StopSize(value) => {
            session
                .send_serial(Message::SetStopSize {
                    origin: Origin::Client,
                    value,
                })
                .await
        }
        DeviceEvent::FlowOut(value) | DeviceEvent::FlowIn(value) => {
            session
                .send_serial(Message::SetControl {
                    origin: Origin::Client,
                    value,
                })
                .await
        }
        DeviceEvent::Dtr(on) => {
            session
                .send_serial(Message::SetControl {
                    origin: Origin::Client,
                    value: if on {
                        serial::control::DTR_ON
                    } else {
                        serial::control::DTR_OFF
                    },
                })
                .await
        }
        DeviceEvent::Rts(on) => {
            session
                .send_serial(Message::SetControl {
                    origin: Origin::Client,
                    value: if on {
                        serial::control::RTS_ON
                    } else {
                        serial::control::RTS_OFF
                    },
                })
                .await
        }
        DeviceEvent::Break(on) => {
            session
                .send_serial(Message::SetControl {
                    origin: Origin::Client,
                    value: if on {
                        serial::control::BREAK_ON
                    } else {
                        serial::control::BREAK_OFF
                    },
                })
                .await
        }
        DeviceEvent::Purge(value) => {
            session
                .send_serial(Message::PurgeData {
                    origin: Origin::Client,
                    value,
                })
                .await
        }
        DeviceEvent::FlowSuspend => {
            session
                .send_serial(Message::FlowControlSuspend {
                    origin: Origin::Client,
                })
                .await
        }
        DeviceEvent::FlowResume => {
            session
                .send_serial(Message::FlowControlResume {
                    origin: Origin::Client,
                })
                .await
        }
    }
}

pub(crate) async fn run_device(
    target: &str,
    port: u16,
    timeout: Duration,
    device_name: &str,
    settings: SerialSettings,
) -> Result<(), String> {
    let (mut session, mut pre_session) = negotiate_serial(target, port, timeout).await?;

    // Apply requested startup settings before discovery. Their confirmations, plus the discovery
    // replies for unspecified fields, seed the CUSE device's initial termios state.
    session
        .apply_initial_configuration(settings)
        .await
        .map_err(|error| format!("set initial serial configuration: {error}"))?;
    session
        .query_initial_configuration()
        .await
        .map_err(|error| format!("query serial configuration: {error}"))?;

    let mut state = SerialState::default();
    let mut saw_baud = false;
    let mut saw_data = false;
    let mut saw_parity = false;
    let mut saw_stop = false;
    let mut saw_flow_out = false;
    let mut saw_flow_in = false;
    let discovery_window = timeout.min(Duration::from_secs(2));
    let discovery = time::timeout(discovery_window, async {
        loop {
            let Some(event) = session.next_event().await? else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "server closed while querying serial state",
                ));
            };
            if matches!(
                &event,
                SessionEvent::OptionDisabled {
                    side: Side::Us,
                    option: OPT_COM_PORT
                }
            ) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "server disabled serial COM-PORT-OPTION while querying serial state",
                ));
            }
            if let SessionEvent::Serial(ref serial_event) = event {
                state.update(serial_event);
                match serial_event {
                    SerialEvent::BaudRate(value) if *value != 0 => saw_baud = true,
                    SerialEvent::DataSize(value) if (5..=8).contains(value) => saw_data = true,
                    SerialEvent::Parity(value) if *value != serial::parity::REQUEST => {
                        saw_parity = true;
                    }
                    SerialEvent::StopSize(value) if *value != serial::stop_size::REQUEST => {
                        saw_stop = true;
                    }
                    SerialEvent::Control(
                        serial::control::NO_OUTBOUND_FLOW
                        | serial::control::XON_XOFF_OUTBOUND
                        | serial::control::HARDWARE_OUTBOUND
                        | serial::control::DCD_OUTBOUND
                        | serial::control::DSR_OUTBOUND,
                    ) => saw_flow_out = true,
                    SerialEvent::Control(
                        serial::control::NO_INBOUND_FLOW
                        | serial::control::XON_XOFF_INBOUND
                        | serial::control::HARDWARE_INBOUND
                        | serial::control::DTR_INBOUND,
                    ) => saw_flow_in = true,
                    _ => {}
                }
            }
            pre_session.push_back(event);
            if saw_baud && saw_data && saw_parity && saw_stop && saw_flow_out && saw_flow_in {
                return Ok::<_, io::Error>(());
            }
        }
    })
    .await;
    if let Ok(Err(error)) = discovery {
        return Err(format!("query serial state: {error}"));
    }

    let device = cuse_device::Device::start(device_name, state)
        .map_err(|error| format!("create /dev/{device_name}: {error}"))?;
    tracing::info!(%target, port, "serial connected");
    tracing::info!(device = %format_args!("/dev/{device_name}"), "virtual serial device ready");
    tracing::info!(
        "serial settings are controlled through normal termios/ioctl calls on the device"
    );

    let event_reader = device.event_reader();
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<Result<DeviceEvent, String>>(1);
    let reader = std::thread::Builder::new()
        .name("microtun-serial-device".to_owned())
        .spawn(move || {
            loop {
                match event_reader.next_event() {
                    Ok(Some(event)) => {
                        if event_tx.blocking_send(Ok(event)).is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        let _ = event_tx.blocking_send(Err(error));
                        break;
                    }
                }
            }
        })
        .map_err(|error| format!("start virtual serial event reader: {error}"))?;

    let mut remote_tx_suspended = false;
    let result = async {
        while let Some(event) = pre_session.pop_front() {
            match event {
                SessionEvent::Data(bytes) => device.push_rx(&bytes)?,
                SessionEvent::Serial(SerialEvent::FlowControlSuspend) => {
                    remote_tx_suspended = true;
                }
                SessionEvent::Serial(SerialEvent::FlowControlResume) => {
                    remote_tx_suspended = false;
                }
                SessionEvent::Serial(ref serial_event) => {
                    device.remote_update(serial_event);
                    log_serial_event(serial_event);
                }
                SessionEvent::OptionDisabled {
                    side: Side::Us,
                    option: OPT_COM_PORT,
                } => return Err("server disabled serial COM-PORT-OPTION".to_owned()),
                SessionEvent::OptionEnabled { side, option }
                | SessionEvent::OptionDisabled { side, option } => {
                    tracing::debug!(?side, option, "Telnet option changed");
                }
            }
        }

        loop {
            tokio::select! {
                network = session.next_event() => {
                    let event = network
                        .map_err(|error| format!("read Telnet/serial session: {error}"))?;
                    let Some(event) = event else {
                        return Ok(());
                    };
                    match event {
                        SessionEvent::Data(bytes) => device.push_rx(&bytes)?,
                        SessionEvent::Serial(SerialEvent::FlowControlSuspend) => {
                            remote_tx_suspended = true;
                            tracing::debug!("remote suspended client serial transmission");
                        }
                        SessionEvent::Serial(SerialEvent::FlowControlResume) => {
                            remote_tx_suspended = false;
                            tracing::debug!("remote resumed client serial transmission");
                        }
                        SessionEvent::Serial(ref serial_event) => {
                            device.remote_update(serial_event);
                            log_serial_event(serial_event);
                        }
                        SessionEvent::OptionDisabled {
                            side: Side::Us,
                            option: OPT_COM_PORT,
                        } => return Err("server disabled serial COM-PORT-OPTION".to_owned()),
                        SessionEvent::OptionEnabled { side, option }
                        | SessionEvent::OptionDisabled { side, option } => {
                            tracing::debug!(?side, option, "Telnet option changed");
                        }
                    }
                }
                device_event = event_rx.recv(), if !remote_tx_suspended => {
                    match device_event {
                        Some(Ok(event)) => send_device_event(&mut session, event)
                            .await
                            .map_err(|error| format!("send virtual serial control over serial: {error}"))?,
                        Some(Err(error)) => return Err(error),
                        None => return Err("virtual serial event reader stopped unexpectedly".to_owned()),
                    }
                }
                signal = tokio::signal::ctrl_c() => {
                    signal.map_err(|error| format!("wait for Ctrl-C: {error}"))?;
                    return Ok(());
                }
            }
        }
    }
    .await;

    device.shutdown();
    drop(event_rx);
    if reader.join().is_err() && result.is_ok() {
        return Err("virtual serial event reader panicked".to_owned());
    }
    result
}
