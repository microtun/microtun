use std::{collections::VecDeque, io, time::Duration};

use embedded_io_async::{ErrorType, Read, Write};
use tokio::{io::AsyncWriteExt, net::TcpStream, time};

const IAC: u8 = 0xff;
const WILL: u8 = 0xfb;
const WONT: u8 = 0xfc;
const DO: u8 = 0xfd;
const DONT: u8 = 0xfe;
const SB: u8 = 0xfa;
const SE: u8 = 0xf0;
const TELNET_BINARY: u8 = 0;
const TELNET_ECHO: u8 = 1;
const TELNET_SUPPRESS_GO_AHEAD: u8 = 3;
#[derive(Clone, Copy)]
enum TelnetRxState {
    Data,
    Iac,
    Negotiation(u8),
    Subnegotiation,
    SubnegotiationIac,
}

pub(crate) struct TelnetClient {
    stream: TcpStream,
    rx_state: TelnetRxState,
    decoded: VecDeque<u8>,
    negotiation_replies: Vec<u8>,
    read_timeout: Duration,
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
            rx_state: TelnetRxState::Data,
            decoded: VecDeque::new(),
            negotiation_replies: Vec::new(),
            read_timeout: timeout,
        })
    }

    fn process_wire_bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if let Some(byte) = self.process_wire_byte(byte) {
                self.decoded.push_back(byte);
            }
        }
    }
    fn process_wire_byte(&mut self, byte: u8) -> Option<u8> {
        match self.rx_state {
            TelnetRxState::Data => {
                if byte == IAC {
                    self.rx_state = TelnetRxState::Iac;
                    None
                } else {
                    Some(byte)
                }
            }
            TelnetRxState::Iac => match byte {
                IAC => {
                    self.rx_state = TelnetRxState::Data;
                    Some(IAC)
                }
                WILL | WONT | DO | DONT => {
                    self.rx_state = TelnetRxState::Negotiation(byte);
                    None
                }
                SB => {
                    self.rx_state = TelnetRxState::Subnegotiation;
                    None
                }
                _ => {
                    self.rx_state = TelnetRxState::Data;
                    None
                }
            },
            TelnetRxState::Negotiation(command) => {
                self.queue_negotiation_reply(command, byte);
                self.rx_state = TelnetRxState::Data;
                None
            }
            TelnetRxState::Subnegotiation => {
                if byte == IAC {
                    self.rx_state = TelnetRxState::SubnegotiationIac;
                }
                None
            }
            TelnetRxState::SubnegotiationIac => {
                self.rx_state = if byte == SE {
                    TelnetRxState::Data
                } else {
                    TelnetRxState::Subnegotiation
                };
                None
            }
        }
    }
    fn queue_negotiation_reply(&mut self, command: u8, option: u8) {
        let accepted = matches!(
            option,
            TELNET_BINARY | TELNET_ECHO | TELNET_SUPPRESS_GO_AHEAD
        );
        let reply = match command {
            WILL if accepted => DO,
            WILL => DONT,
            DO if accepted => WILL,
            DO => WONT,
            WONT => DONT,
            DONT => WONT,
            _ => return,
        };
        self.negotiation_replies
            .extend_from_slice(&[IAC, reply, option]);
    }
    async fn send_negotiation_replies(&mut self) -> io::Result<()> {
        if self.negotiation_replies.is_empty() {
            return Ok(());
        }

        let replies = std::mem::take(&mut self.negotiation_replies);
        self.stream.write_all(&replies).await
    }
}

impl ErrorType for TelnetClient {
    type Error = io::Error;
}
impl Read for TelnetClient {
    async fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.decoded.is_empty() {
            match time::timeout(self.read_timeout, self.stream.readable()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) if is_remote_disconnect(error.kind()) => return Ok(0),
                Ok(Err(error)) => return Err(error),
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Telnet read timed out",
                    ));
                }
            }
            let mut wire = [0u8; 4096];
            match self.stream.try_read(&mut wire) {
                Ok(0) => return Ok(0),
                Ok(len) => self.process_wire_bytes(&wire[..len]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if is_remote_disconnect(error.kind()) => return Ok(0),
                Err(error) => return Err(error),
            }

            self.send_negotiation_replies().await?;
        }
        let count = output.len().min(self.decoded.len());
        for byte in &mut output[..count] {
            *byte = self.decoded.pop_front().expect("decoded length checked");
        }
        Ok(count)
    }
}
impl Write for TelnetClient {
    async fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut encoded = Vec::with_capacity(bytes.len() + 16);
        for &byte in bytes {
            encoded.push(byte);
            if byte == IAC {
                encoded.push(IAC);
            }
        }
        self.stream.write_all(&encoded).await?;
        Ok(bytes.len())
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.stream.flush().await
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
