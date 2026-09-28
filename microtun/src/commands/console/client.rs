use std::{collections::VecDeque, io, time::Duration};

use embedded_io_adapters::tokio_1::FromTokio;
use embedded_io_async::{ErrorType, Read, Write};
use heapless::Vec as HeaplessVec;
pub(crate) use microtun_telnet::client::{SerialStatus, flow_label, parity_label, stop_label};
use microtun_telnet::{
    client::{ClientEncodeError, ClientEvent, SerialConsoleState as ProtoSerialState},
    write_data_unflushed,
};
use tokio::{io::AsyncWriteExt, net::TcpStream, time};

use crate::commands::serial_settings::{SerialProtocol as Protocol, SerialSettings};

pub(crate) type SerialConsoleState = ProtoSerialState<256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConsoleRead {
    Data(usize),
    StateChanged,
    Timeout,
    Closed,
}

pub(crate) struct TelnetClient {
    stream: TcpStream,
    protocol: Protocol,
    decoded: VecDeque<u8>,
    negotiation_replies: Vec<u8>,
    read_timeout: Duration,
    initial_serial_settings: SerialSettings,
}

impl TelnetClient {
    pub(crate) async fn connect(
        target: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<Self, String> {
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
            protocol: Protocol::new(),
            decoded: VecDeque::new(),
            negotiation_replies: Vec::new(),
            read_timeout: timeout,
            initial_serial_settings: SerialSettings::default(),
        })
    }

    pub(crate) fn serial_state(&self) -> Option<&SerialConsoleState> {
        self.protocol.serial_state()
    }

    pub(crate) fn serial_active(&self) -> bool {
        self.protocol.serial_active()
    }

    pub(crate) async fn enter_serial_mode(&mut self, settings: SerialSettings) -> io::Result<()> {
        if self.protocol.serial_mode() {
            return Ok(());
        }

        self.initial_serial_settings = settings;

        // The protocol core first negotiates BINARY/SGA/COM-PORT. Once COM-PORT becomes active,
        // process_wire_bytes queues any requested startup UART parameters followed by the normal
        // serial-state discovery query.
        let mut wire = HeaplessVec::<u8, 32>::new();
        self.protocol
            .enter_serial_mode(&mut wire)
            .map_err(protocol_error)?;
        self.stream.write_all(wire.as_slice()).await
    }

    fn process_wire_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        for &byte in bytes {
            let mut reply = HeaplessVec::<u8, 32>::new();
            let event = self.protocol.feed(byte, &mut reply);
            self.negotiation_replies.extend_from_slice(reply.as_slice());

            match event {
                Some(ClientEvent::Data(byte)) => self.decoded.push_back(byte),
                Some(ClientEvent::SerialModeActive) => {
                    self.queue_initial_serial_settings()?;
                    self.queue_initial_serial_query();
                }
                Some(
                    ClientEvent::SerialModeRefused
                    | ClientEvent::Telnet(_)
                    | ClientEvent::Serial(_)
                    | ClientEvent::MalformedSerial(_),
                )
                | None => {}
            }
        }
        Ok(())
    }

    fn queue_initial_serial_settings(&mut self) -> io::Result<()> {
        let mut wire = HeaplessVec::<u8, 64>::new();
        self.initial_serial_settings
            .queue(&self.protocol, &mut wire)
            .map_err(protocol_error)?;
        self.negotiation_replies.extend_from_slice(wire.as_slice());
        Ok(())
    }

    fn queue_initial_serial_query(&mut self) {
        let mut wire = HeaplessVec::<u8, 128>::new();
        if matches!(
            self.protocol.queue_initial_serial_query(&mut wire),
            Ok(true)
        ) {
            self.negotiation_replies.extend_from_slice(wire.as_slice());
        }
    }

    async fn send_negotiation_replies(&mut self) -> io::Result<()> {
        if self.negotiation_replies.is_empty() {
            return Ok(());
        }

        let replies = std::mem::take(&mut self.negotiation_replies);
        self.stream.write_all(&replies).await
    }

    async fn send_protocol_bytes(&mut self, wire: &[u8]) -> io::Result<()> {
        self.send_negotiation_replies().await?;
        self.stream.write_all(wire).await
    }

    pub(crate) async fn set_baud(&mut self, value: u32) -> io::Result<()> {
        let mut wire = HeaplessVec::<u8, 16>::new();
        self.protocol
            .set_baud(value, &mut wire)
            .map_err(protocol_error)?;
        self.send_protocol_bytes(wire.as_slice()).await
    }

    pub(crate) async fn set_data_bits(&mut self, value: u8) -> io::Result<()> {
        let mut wire = HeaplessVec::<u8, 16>::new();
        self.protocol
            .set_data_bits(value, &mut wire)
            .map_err(protocol_error)?;
        self.send_protocol_bytes(wire.as_slice()).await
    }

    pub(crate) async fn set_parity(&mut self, value: u8) -> io::Result<()> {
        let mut wire = HeaplessVec::<u8, 16>::new();
        self.protocol
            .set_parity(value, &mut wire)
            .map_err(protocol_error)?;
        self.send_protocol_bytes(wire.as_slice()).await
    }

    pub(crate) async fn set_stop_bits(&mut self, value: u8) -> io::Result<()> {
        let mut wire = HeaplessVec::<u8, 16>::new();
        self.protocol
            .set_stop_bits(value, &mut wire)
            .map_err(protocol_error)?;
        self.send_protocol_bytes(wire.as_slice()).await
    }

    pub(crate) async fn set_flow(&mut self, outbound: u8, inbound: u8) -> io::Result<()> {
        let mut wire = HeaplessVec::<u8, 32>::new();
        self.protocol
            .set_flow(outbound, inbound, &mut wire)
            .map_err(protocol_error)?;
        self.send_protocol_bytes(wire.as_slice()).await
    }

    pub(crate) async fn set_dtr(&mut self, on: bool) -> io::Result<()> {
        let mut wire = HeaplessVec::<u8, 16>::new();
        self.protocol
            .set_dtr(on, &mut wire)
            .map_err(protocol_error)?;
        self.send_protocol_bytes(wire.as_slice()).await
    }

    pub(crate) async fn set_rts(&mut self, on: bool) -> io::Result<()> {
        let mut wire = HeaplessVec::<u8, 16>::new();
        self.protocol
            .set_rts(on, &mut wire)
            .map_err(protocol_error)?;
        self.send_protocol_bytes(wire.as_slice()).await
    }

    pub(crate) async fn send_break_pulse(&mut self) -> io::Result<()> {
        let mut wire = HeaplessVec::<u8, 16>::new();
        self.protocol
            .set_break(true, &mut wire)
            .map_err(protocol_error)?;
        self.send_protocol_bytes(wire.as_slice()).await?;

        time::sleep(Duration::from_millis(250)).await;

        wire.clear();
        self.protocol
            .set_break(false, &mut wire)
            .map_err(protocol_error)?;
        self.send_protocol_bytes(wire.as_slice()).await
    }

    pub(crate) async fn read_console(&mut self, output: &mut [u8]) -> io::Result<ConsoleRead> {
        if output.is_empty() {
            return Ok(ConsoleRead::Data(0));
        }
        if !self.decoded.is_empty() {
            return Ok(ConsoleRead::Data(self.copy_decoded(output)));
        }

        loop {
            match time::timeout(self.read_timeout, self.stream.readable()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) if is_remote_disconnect(error.kind()) => {
                    return Ok(ConsoleRead::Closed);
                }
                Ok(Err(error)) => return Err(error),
                Err(_) => return Ok(ConsoleRead::Timeout),
            }

            let mut wire = [0u8; 4096];
            let serial_before = self.protocol.serial_state().cloned();
            match self.stream.try_read(&mut wire) {
                Ok(0) => return Ok(ConsoleRead::Closed),
                Ok(len) => self.process_wire_bytes(&wire[..len])?,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if is_remote_disconnect(error.kind()) => {
                    return Ok(ConsoleRead::Closed);
                }
                Err(error) => return Err(error),
            }
            self.send_negotiation_replies().await?;

            if !self.decoded.is_empty() {
                return Ok(ConsoleRead::Data(self.copy_decoded(output)));
            }
            if self.protocol.serial_state() != serial_before.as_ref() {
                return Ok(ConsoleRead::StateChanged);
            }
        }
    }

    fn copy_decoded(&mut self, output: &mut [u8]) -> usize {
        let count = output.len().min(self.decoded.len());
        for byte in &mut output[..count] {
            *byte = self.decoded.pop_front().expect("decoded length checked");
        }
        count
    }
}

impl ErrorType for TelnetClient {
    type Error = io::Error;
}

impl Read for TelnetClient {
    async fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.read_console(output).await? {
                ConsoleRead::Data(count) => return Ok(count),
                ConsoleRead::StateChanged => continue,
                ConsoleRead::Closed => return Ok(0),
                ConsoleRead::Timeout => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Telnet read timed out",
                    ));
                }
            }
        }
    }
}

impl Write for TelnetClient {
    async fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.send_negotiation_replies().await?;
        let mut stream = FromTokio::new(&mut self.stream);
        write_data_unflushed(&mut stream, bytes).await?;
        Ok(bytes.len())
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.send_negotiation_replies().await?;
        self.stream.flush().await
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

fn is_remote_disconnect(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
    )
}

#[cfg(test)]
mod tests {
    use heapless::Vec as HeaplessVec;
    use microtun_telnet::{DO, IAC, OPT_COM_PORT, serial};

    use super::{Protocol, SerialSettings};

    #[test]
    fn startup_serial_settings_encode_after_com_port_activation() {
        let mut protocol = Protocol::new();
        let mut negotiation = HeaplessVec::<u8, 32>::new();
        protocol.enter_serial_mode(&mut negotiation).unwrap();

        for byte in [IAC, DO, OPT_COM_PORT] {
            let mut reply = HeaplessVec::<u8, 32>::new();
            let _ = protocol.feed(byte, &mut reply);
        }
        assert!(protocol.serial_active());

        let settings = SerialSettings {
            baud: Some(115_200),
            data_bits: Some(8),
            parity: Some(serial::parity::NONE),
            stop_bits: Some(serial::stop_size::ONE),
            flow: Some(SerialSettings::hardware_flow()),
        };
        let mut wire = HeaplessVec::<u8, 64>::new();
        settings.queue(&protocol, &mut wire).unwrap();

        let mut expected = HeaplessVec::<u8, 64>::new();
        for message in [
            serial::Message::SetBaudRate {
                origin: serial::Origin::Client,
                value: 115_200,
            },
            serial::Message::SetDataSize {
                origin: serial::Origin::Client,
                value: 8,
            },
            serial::Message::SetParity {
                origin: serial::Origin::Client,
                value: serial::parity::NONE,
            },
            serial::Message::SetStopSize {
                origin: serial::Origin::Client,
                value: serial::stop_size::ONE,
            },
            serial::Message::SetControl {
                origin: serial::Origin::Client,
                value: serial::control::HARDWARE_OUTBOUND,
            },
            serial::Message::SetControl {
                origin: serial::Origin::Client,
                value: serial::control::HARDWARE_INBOUND,
            },
        ] {
            assert!(serial::encode(message, &mut expected));
        }

        assert_eq!(wire, expected);
    }
}
