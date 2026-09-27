use std::{collections::VecDeque, io, time::Duration};

use embedded_io_adapters::tokio_1::FromTokio;
use heapless::Vec as HeaplessVec;
use microtun_telnet::{
    OPT_COM_PORT, Side, TelnetEvent,
    client::{ClientEncodeError, ClientEvent, ClientSession, SerialEvent},
    serial, write_data_unflushed,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time,
};

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
    protocol: ClientSession<256, 12, 256>,
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
            protocol: ClientSession::new(),
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
mod cuse {
    use std::{
        collections::VecDeque,
        ffi::c_int,
        mem::{offset_of, size_of},
        ptr,
        sync::{Arc, Condvar, Mutex, MutexGuard},
        time::Duration,
    };

    use nix::libc;

    use super::{DeviceEvent, SerialEvent, SerialState, serial};
    use crate::cuse::{
        Cuse, Device as CuseDevice, Errno, Ioctl, IoctlReply, OpenReply, PollEvents, PollNotifier,
        PollReply, ReadReply, Request, RequestId, RunningCuse, UserBuf, WriteReply,
    };

    const RX_LIMIT: usize = 16 * 1024 * 1024;
    const TX_LIMIT: usize = 4 * 1024 * 1024;
    const IO_CHUNK: usize = 16 * 1024;

    struct PendingRead {
        id: RequestId,
        reply: ReadReply,
    }

    struct PendingWrite {
        id: RequestId,
        data: Vec<u8>,
        reply: WriteReply,
    }

    enum PendingIoctlAction {
        SetTermios {
            input: Vec<u8>,
            termios2: bool,
            flush: bool,
        },
        Tcsbrk {
            send_break: bool,
        },
    }

    struct PendingIoctl {
        id: RequestId,
        action: PendingIoctlAction,
        reply: IoctlReply,
    }

    struct State {
        ready: bool,
        stopping: bool,
        rx: VecDeque<u8>,
        events: VecDeque<DeviceEvent>,
        tx_bytes: usize,
        serial: SerialState,
        termios: libc::termios2,
        hung_up: bool,
        modem_state: u8,
        line_state: u8,
        open_count: usize,
        exclusive: bool,
        reads: VecDeque<PendingRead>,
        writes: VecDeque<PendingWrite>,
        ioctls: VecDeque<PendingIoctl>,
        polls: Vec<PollNotifier>,
    }

    struct Shared {
        state: Mutex<State>,
        ready_cv: Condvar,
        event_cv: Condvar,
    }

    impl Shared {
        fn new(serial: SerialState) -> Self {
            // SAFETY: termios2 is a plain C data structure and zero is a valid baseline.
            let termios = unsafe { std::mem::zeroed() };
            let mut state = State {
                ready: false,
                stopping: false,
                rx: VecDeque::new(),
                events: VecDeque::new(),
                tx_bytes: 0,
                serial,
                termios,
                hung_up: false,
                modem_state: 0,
                line_state: 0,
                open_count: 0,
                exclusive: false,
                reads: VecDeque::new(),
                writes: VecDeque::new(),
                ioctls: VecDeque::new(),
                polls: Vec::new(),
            };
            state.termios.c_cflag = (libc::CREAD | libc::CLOCAL) as _;
            state.termios.c_cc[libc::VMIN] = 1;
            state.termios.c_cc[libc::VTIME] = 0;
            sync_termios_from_serial(&mut state);
            Self {
                state: Mutex::new(state),
                ready_cv: Condvar::new(),
                event_cv: Condvar::new(),
            }
        }

        fn lock(&self) -> MutexGuard<'_, State> {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        fn notify_polls(&self) {
            let polls = {
                let mut state = self.lock();
                std::mem::take(&mut state.polls)
            };
            for notifier in polls {
                notifier.notify();
            }
        }

        fn stop(&self) {
            let (reads, writes, ioctls, polls) = {
                let mut state = self.lock();
                if state.stopping {
                    return;
                }
                state.stopping = true;
                (
                    std::mem::take(&mut state.reads),
                    std::mem::take(&mut state.writes),
                    std::mem::take(&mut state.ioctls),
                    std::mem::take(&mut state.polls),
                )
            };
            self.ready_cv.notify_all();
            self.event_cv.notify_all();
            for pending in reads {
                pending.reply.error(Errno::EIO);
            }
            for pending in writes {
                pending.reply.error(Errno::EIO);
            }
            for pending in ioctls {
                pending.reply.error(Errno::EIO);
            }
            for notifier in polls {
                notifier.notify();
            }
        }

        fn mark_ready(&self) {
            self.lock().ready = true;
            self.ready_cv.notify_all();
        }

        fn wait_ready(&self) -> Result<(), String> {
            let mut state = self.lock();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !state.ready && !state.stopping {
                let now = std::time::Instant::now();
                if now >= deadline {
                    return Err("timed out waiting for CUSE device registration".to_owned());
                }
                let timeout = deadline.saturating_duration_since(now);
                let (next, result) = self
                    .ready_cv
                    .wait_timeout(state, timeout)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                state = next;
                if result.timed_out() && !state.ready {
                    return Err("timed out waiting for CUSE device registration".to_owned());
                }
            }
            if state.ready {
                Ok(())
            } else {
                Err("CUSE session terminated before the device was created".to_owned())
            }
        }

        fn push_rx(&self, data: &[u8]) -> Result<(), String> {
            if data.is_empty() {
                return Ok(());
            }
            let mut completions = Vec::new();
            {
                let mut state = self.lock();
                if state.stopping {
                    return Err("virtual serial device has stopped".to_owned());
                }
                if state.rx.len().saturating_add(data.len()) > RX_LIMIT {
                    return Err("virtual serial receive buffer is full".to_owned());
                }
                state.rx.extend(data.iter().copied());
                while !state.rx.is_empty() {
                    let Some(pending) = state.reads.pop_front() else {
                        break;
                    };
                    let count = pending.reply.size().min(state.rx.len());
                    let mut out = Vec::with_capacity(count);
                    for _ in 0..count {
                        out.push(state.rx.pop_front().expect("receive length checked"));
                    }
                    completions.push((pending.reply, out));
                }
            }
            for (reply, out) in completions {
                reply.data(&out);
            }
            self.notify_polls();
            Ok(())
        }

        fn remote_update(&self, event: &SerialEvent) {
            let mut state = self.lock();
            state.serial.update(event);
            match event {
                SerialEvent::ModemState(value) => state.modem_state = *value,
                SerialEvent::LineState(value) => state.line_state = *value,
                _ => {}
            }
            sync_termios_from_serial(&mut state);
        }

        fn next_event(&self) -> Result<Option<DeviceEvent>, String> {
            let (event, write_replies, ioctl_replies) = {
                let mut state = self.lock();
                while !state.stopping && state.events.is_empty() {
                    state = self
                        .event_cv
                        .wait(state)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
                if state.events.is_empty() {
                    return Ok(None);
                }
                let event = state.events.pop_front().expect("event queue checked above");
                if let DeviceEvent::Data(ref data) = event {
                    state.tx_bytes = state.tx_bytes.saturating_sub(data.len());
                }
                let ioctls = complete_pending_ioctls(&mut state);
                let replies = fill_pending_writes(&mut state);
                (event, replies, ioctls)
            };
            for (reply, count) in write_replies {
                reply.written(count);
            }
            for (reply, result) in ioctl_replies {
                match result {
                    Ok(()) => reply.ok(0),
                    Err(error) => reply.error(error),
                };
            }
            self.event_cv.notify_all();
            self.notify_polls();
            Ok(Some(event))
        }

        fn read(&self, req: &Request, reply: ReadReply) {
            if reply.size() == 0 {
                reply.data(&[]);
                return;
            }
            let mut state = self.lock();
            if state.stopping {
                reply.error(Errno::EIO);
                return;
            }
            if !state.rx.is_empty() {
                let count = reply.size().min(state.rx.len());
                let mut out = Vec::with_capacity(count);
                for _ in 0..count {
                    out.push(state.rx.pop_front().expect("receive length checked"));
                }
                drop(state);
                reply.data(&out);
                self.notify_polls();
            } else if req.flags().is_nonblocking() {
                reply.error(Errno::EAGAIN);
            } else {
                state.reads.push_back(PendingRead {
                    id: req.id(),
                    reply,
                });
            }
        }

        fn write(&self, req: &Request, data: &[u8], reply: WriteReply) {
            if data.is_empty() {
                reply.written(0);
                return;
            }
            let mut state = self.lock();
            if state.stopping {
                reply.error(Errno::EIO);
                return;
            }
            let available = TX_LIMIT.saturating_sub(state.tx_bytes);
            if available != 0 {
                let count = data.len().min(available).min(IO_CHUNK);
                state
                    .events
                    .push_back(DeviceEvent::Data(data[..count].to_vec()));
                state.tx_bytes += count;
                drop(state);
                self.event_cv.notify_one();
                reply.written(count);
                self.notify_polls();
            } else if req.flags().is_nonblocking() {
                reply.error(Errno::EAGAIN);
            } else {
                state.writes.push_back(PendingWrite {
                    id: req.id(),
                    data: data.to_vec(),
                    reply,
                });
            }
        }

        fn open(&self, reply: OpenReply<()>) {
            let mut state = self.lock();
            if state.stopping {
                reply.error(Errno::EIO);
            } else if state.exclusive && state.open_count != 0 {
                reply.error(Errno::EBUSY);
            } else {
                state.open_count += 1;
                reply.ok(());
            }
        }

        fn release(&self) {
            let mut state = self.lock();
            state.open_count = state.open_count.saturating_sub(1);
            if state.open_count == 0 {
                state.exclusive = false;
            }
        }

        fn poll(&self, requested: PollEvents, notifier: Option<PollNotifier>, reply: PollReply) {
            let mut state = self.lock();
            let events = readiness(&state);
            if let Some(notifier) = notifier {
                if !state.stopping
                    && (requested.is_empty() || events.intersection(requested).is_empty())
                {
                    state.polls.push(notifier);
                }
            }
            reply.ready(events);
        }

        fn interrupt(&self, id: RequestId) {
            let mut read = None;
            let mut write = None;
            let mut ioctl = None;
            {
                let mut state = self.lock();
                if let Some(index) = state.reads.iter().position(|pending| pending.id == id) {
                    read = state.reads.remove(index);
                } else if let Some(index) = state.writes.iter().position(|pending| pending.id == id)
                {
                    write = state.writes.remove(index);
                } else if let Some(index) = state.ioctls.iter().position(|pending| pending.id == id)
                {
                    ioctl = state.ioctls.remove(index);
                }
            }
            if let Some(pending) = read {
                pending.reply.error(Errno::EINTR);
            }
            if let Some(pending) = write {
                pending.reply.error(Errno::EINTR);
            }
            if let Some(pending) = ioctl {
                pending.reply.error(Errno::EINTR);
            }
        }

        fn ioctl(&self, req: &Request, ioctl: Ioctl<'_>, reply: IoctlReply) {
            if ioctl.is_compat() {
                reply.error(Errno::ENOSYS);
                return;
            }

            let cmd = ioctl.cmd();
            let legacy_len = offset_of!(libc::termios2, c_ispeed);
            let termios2_len = size_of::<libc::termios2>();
            let mut notify_events = false;
            let mut notify_poll = false;

            macro_rules! retry_input {
                ($len:expr) => {{
                    reply.retry(&[UserBuf::new(ioctl.arg(), $len)], &[]);
                    return;
                }};
            }
            macro_rules! retry_output {
                ($len:expr) => {{
                    reply.retry(&[], &[UserBuf::new(ioctl.arg(), $len)]);
                    return;
                }};
            }

            if cmd == libc::TCGETS as u32 {
                if ioctl.out_size() < legacy_len {
                    retry_output!(legacy_len);
                }
                let state = self.lock();
                let mut value = copy_termios2(&state.termios);
                set_termios_baud(&mut value, &state);
                reply.ok_with(0, prefix_bytes(&value, legacy_len));
                return;
            }
            if cmd == libc::TCSETS as u32
                || cmd == libc::TCSETSW as u32
                || cmd == libc::TCSETSF as u32
            {
                if ioctl.input().len() < legacy_len {
                    retry_input!(legacy_len);
                }
                let flush = cmd == libc::TCSETSF as u32;
                let drain = cmd != libc::TCSETS as u32;
                if drain {
                    let mut state = self.lock();
                    if state.tx_bytes != 0 {
                        if req.flags().is_nonblocking() {
                            drop(state);
                            reply.error(Errno::EAGAIN);
                        } else {
                            state.ioctls.push_back(PendingIoctl {
                                id: req.id(),
                                action: PendingIoctlAction::SetTermios {
                                    input: ioctl.input().to_vec(),
                                    termios2: false,
                                    flush,
                                },
                                reply,
                            });
                        }
                        return;
                    }
                }
                match self.set_termios(ioctl.input(), false, flush) {
                    Ok(()) => reply.ok(0),
                    Err(errno) => reply.error(errno),
                };
                return;
            }
            if cmd == libc::TCGETS2 as u32 {
                if ioctl.out_size() < termios2_len {
                    retry_output!(termios2_len);
                }
                let state = self.lock();
                reply.ok_with(0, struct_bytes(&state.termios));
                return;
            }
            if cmd == libc::TCSETS2 as u32
                || cmd == libc::TCSETSW2 as u32
                || cmd == libc::TCSETSF2 as u32
            {
                if ioctl.input().len() < termios2_len {
                    retry_input!(termios2_len);
                }
                let flush = cmd == libc::TCSETSF2 as u32;
                let drain = cmd != libc::TCSETS2 as u32;
                if drain {
                    let mut state = self.lock();
                    if state.tx_bytes != 0 {
                        if req.flags().is_nonblocking() {
                            drop(state);
                            reply.error(Errno::EAGAIN);
                        } else {
                            state.ioctls.push_back(PendingIoctl {
                                id: req.id(),
                                action: PendingIoctlAction::SetTermios {
                                    input: ioctl.input().to_vec(),
                                    termios2: true,
                                    flush,
                                },
                                reply,
                            });
                        }
                        return;
                    }
                }
                match self.set_termios(ioctl.input(), true, flush) {
                    Ok(()) => reply.ok(0),
                    Err(errno) => reply.error(errno),
                };
                return;
            }
            if cmd == libc::TIOCMGET as u32 {
                if ioctl.out_size() < size_of::<c_int>() {
                    retry_output!(size_of::<c_int>());
                }
                let state = self.lock();
                let value = modem_bits(&state);
                reply.ok_with(0, struct_bytes(&value));
                return;
            }
            if cmd == libc::TIOCMSET as u32
                || cmd == libc::TIOCMBIS as u32
                || cmd == libc::TIOCMBIC as u32
            {
                if ioctl.input().len() < size_of::<c_int>() {
                    retry_input!(size_of::<c_int>());
                }
                let requested = read_int(ioctl.input());
                let mut state = self.lock();
                let current = modem_bits(&state);
                let (bits, mask) = if cmd == libc::TIOCMSET as u32 {
                    (requested, libc::TIOCM_DTR | libc::TIOCM_RTS)
                } else if cmd == libc::TIOCMBIS as u32 {
                    (requested, requested & (libc::TIOCM_DTR | libc::TIOCM_RTS))
                } else {
                    (
                        current & !requested,
                        requested & (libc::TIOCM_DTR | libc::TIOCM_RTS),
                    )
                };
                set_modem_outputs(&mut state, bits, mask);
                notify_events = true;
            } else if cmd == libc::FIONREAD as u32 || cmd == libc::TIOCINQ as u32 {
                if ioctl.out_size() < size_of::<c_int>() {
                    retry_output!(size_of::<c_int>());
                }
                let state = self.lock();
                let value = state.rx.len().min(c_int::MAX as usize) as c_int;
                reply.ok_with(0, struct_bytes(&value));
                return;
            } else if cmd == libc::TIOCOUTQ as u32 {
                if ioctl.out_size() < size_of::<c_int>() {
                    retry_output!(size_of::<c_int>());
                }
                let state = self.lock();
                let value = state.tx_bytes.min(c_int::MAX as usize) as c_int;
                reply.ok_with(0, struct_bytes(&value));
                return;
            } else if cmd == libc::TCFLSH as u32 {
                let which = ioctl.arg() as c_int;
                let mut state = self.lock();
                let purge = match which {
                    libc::TCIFLUSH => {
                        state.rx.clear();
                        serial::purge::RECEIVE
                    }
                    libc::TCOFLUSH => {
                        clear_tx_data(&mut state);
                        serial::purge::TRANSMIT
                    }
                    libc::TCIOFLUSH => {
                        state.rx.clear();
                        clear_tx_data(&mut state);
                        serial::purge::BOTH
                    }
                    _ => {
                        reply.error(Errno::EINVAL);
                        return;
                    }
                };
                state.events.push_back(DeviceEvent::Purge(purge));
                let ioctls = complete_pending_ioctls(&mut state);
                let writes = fill_pending_writes(&mut state);
                drop(state);
                for (pending, count) in writes {
                    pending.written(count);
                }
                for (pending, result) in ioctls {
                    match result {
                        Ok(()) => pending.ok(0),
                        Err(error) => pending.error(error),
                    };
                }
                notify_events = true;
                notify_poll = true;
            } else if cmd == libc::TIOCEXCL as u32 {
                self.lock().exclusive = true;
            } else if cmd == libc::TIOCNXCL as u32 {
                self.lock().exclusive = false;
            } else if cmd == libc::TIOCSBRK as u32 || cmd == libc::TIOCCBRK as u32 {
                let on = cmd == libc::TIOCSBRK as u32;
                let mut state = self.lock();
                if state.serial.break_state != on {
                    state.serial.break_state = on;
                    state.events.push_back(DeviceEvent::Break(on));
                    notify_events = true;
                }
            } else if cmd == libc::TCSBRK as u32 {
                let send_break = ioctl.arg() == 0;
                let mut state = self.lock();
                if state.tx_bytes != 0 {
                    if req.flags().is_nonblocking() {
                        drop(state);
                        reply.error(Errno::EAGAIN);
                    } else {
                        state.ioctls.push_back(PendingIoctl {
                            id: req.id(),
                            action: PendingIoctlAction::Tcsbrk { send_break },
                            reply,
                        });
                    }
                    return;
                }
                if send_break {
                    state.events.push_back(DeviceEvent::Break(true));
                    state.events.push_back(DeviceEvent::Break(false));
                    notify_events = true;
                }
            } else if cmd == libc::TCXONC as u32 {
                let action = ioctl.arg() as c_int;
                let mut state = self.lock();
                match action {
                    libc::TCIOFF => state.events.push_back(DeviceEvent::FlowSuspend),
                    libc::TCION => state.events.push_back(DeviceEvent::FlowResume),
                    libc::TCOOFF | libc::TCOON => {}
                    _ => {
                        reply.error(Errno::EINVAL);
                        return;
                    }
                }
                notify_events = true;
            } else {
                reply.error(Errno::ENOTTY);
                return;
            }

            if notify_events {
                self.event_cv.notify_all();
            }
            if notify_poll {
                self.notify_polls();
            }
            reply.ok(0);
        }

        fn set_termios(&self, input: &[u8], termios2: bool, flush: bool) -> Result<(), Errno> {
            let mut state = self.lock();
            apply_termios(&mut state, input, termios2, flush)?;
            drop(state);
            self.event_cv.notify_all();
            self.notify_polls();
            Ok(())
        }
    }

    fn fill_pending_writes(state: &mut State) -> Vec<(WriteReply, usize)> {
        let mut replies = Vec::new();
        while state.tx_bytes < TX_LIMIT {
            let Some(pending) = state.writes.pop_front() else {
                break;
            };
            let available = TX_LIMIT - state.tx_bytes;
            let count = pending.data.len().min(available).min(IO_CHUNK);
            state
                .events
                .push_back(DeviceEvent::Data(pending.data[..count].to_vec()));
            state.tx_bytes += count;
            replies.push((pending.reply, count));
        }
        replies
    }

    fn complete_pending_ioctls(state: &mut State) -> Vec<(IoctlReply, Result<(), Errno>)> {
        if state.tx_bytes != 0 {
            return Vec::new();
        }
        let mut replies = Vec::new();
        while let Some(pending) = state.ioctls.pop_front() {
            let result = match pending.action {
                PendingIoctlAction::SetTermios {
                    input,
                    termios2,
                    flush,
                } => apply_termios(state, &input, termios2, flush),
                PendingIoctlAction::Tcsbrk { send_break } => {
                    if send_break {
                        state.events.push_back(DeviceEvent::Break(true));
                        state.events.push_back(DeviceEvent::Break(false));
                    }
                    Ok(())
                }
            };
            replies.push((pending.reply, result));
        }
        replies
    }

    fn apply_termios(
        state: &mut State,
        input: &[u8],
        termios2: bool,
        flush: bool,
    ) -> Result<(), Errno> {
        if flush {
            state.rx.clear();
        }
        let mut next = copy_termios2(&state.termios);
        if termios2 {
            copy_into_struct(&mut next, input);
        } else {
            let legacy_len = offset_of!(libc::termios2, c_ispeed);
            copy_prefix_into_struct(&mut next, input, legacy_len);
        }
        let baud = baud_from_termios(&next, termios2).map_err(Errno::from_raw)?;
        apply_local_termios(state, next, baud);
        Ok(())
    }

    fn readiness(state: &State) -> PollEvents {
        let mut events = PollEvents::empty();
        if state.stopping {
            events |= PollEvents::ERR | PollEvents::HUP;
        }
        if !state.rx.is_empty() {
            events |= PollEvents::IN | PollEvents::RDNORM;
        }
        if state.tx_bytes < TX_LIMIT {
            events |= PollEvents::OUT | PollEvents::WRNORM;
        }
        events
    }

    struct SerialDevice {
        shared: Arc<Shared>,
    }

    impl CuseDevice for SerialDevice {
        type Handle = ();

        fn open(&mut self, _req: &Request, reply: OpenReply<()>) {
            self.shared.open(reply);
        }

        fn read(&mut self, req: &Request, _handle: &mut (), reply: ReadReply) {
            self.shared.read(req, reply);
        }

        fn write(&mut self, req: &Request, _handle: &mut (), data: &[u8], reply: WriteReply) {
            self.shared.write(req, data, reply);
        }

        fn ioctl(&mut self, req: &Request, _handle: &mut (), ioctl: Ioctl<'_>, reply: IoctlReply) {
            self.shared.ioctl(req, ioctl, reply);
        }

        fn poll(
            &mut self,
            _req: &Request,
            _handle: &mut (),
            requested: PollEvents,
            notifier: Option<PollNotifier>,
            reply: PollReply,
        ) {
            self.shared.poll(requested, notifier, reply);
        }

        fn release(&mut self, _req: &Request, _handle: ()) {
            self.shared.release();
        }

        fn interrupt(&mut self, id: RequestId) {
            self.shared.interrupt(id);
        }

        fn ready(&mut self) {
            self.shared.mark_ready();
        }
    }

    fn clear_tx_data(state: &mut State) {
        state
            .events
            .retain(|event| !matches!(event, DeviceEvent::Data(_)));
        state.tx_bytes = 0;
    }

    fn set_modem_outputs(state: &mut State, bits: c_int, mask: c_int) {
        if mask & libc::TIOCM_DTR != 0 {
            let on = bits & libc::TIOCM_DTR != 0;
            if state.serial.dtr != on {
                state.serial.dtr = on;
                state.events.push_back(DeviceEvent::Dtr(on));
            }
        }
        if mask & libc::TIOCM_RTS != 0 {
            let on = bits & libc::TIOCM_RTS != 0;
            if state.serial.rts != on {
                state.serial.rts = on;
                state.events.push_back(DeviceEvent::Rts(on));
            }
        }
    }

    fn modem_bits(state: &State) -> c_int {
        let mut bits = 0;
        if state.serial.dtr {
            bits |= libc::TIOCM_DTR;
        }
        if state.serial.rts {
            bits |= libc::TIOCM_RTS;
        }
        if state.modem_state & 0x10 != 0 {
            bits |= libc::TIOCM_CTS;
        }
        if state.modem_state & 0x20 != 0 {
            bits |= libc::TIOCM_DSR;
        }
        if state.modem_state & 0x40 != 0 {
            bits |= libc::TIOCM_RI;
        }
        if state.modem_state & 0x80 != 0 {
            bits |= libc::TIOCM_CAR;
        }
        bits
    }

    fn apply_local_termios(state: &mut State, next: libc::termios2, baud: u32) {
        state.termios = next;

        if baud == 0 {
            if state.serial.dtr {
                state.serial.dtr = false;
                state.events.push_back(DeviceEvent::Dtr(false));
            }
            state.hung_up = true;
        } else {
            if state.hung_up {
                state.hung_up = false;
                if !state.serial.dtr {
                    state.serial.dtr = true;
                    state.events.push_back(DeviceEvent::Dtr(true));
                }
            }
            if state.serial.baud != baud {
                state.serial.baud = baud;
                state.events.push_back(DeviceEvent::Baud(baud));
            }
        }

        let cflag = state.termios.c_cflag;
        let iflag = state.termios.c_iflag;
        let data_bits = data_bits_from_cflag(cflag);
        let parity = parity_from_cflag(cflag);
        let stop_bits = stop_from_cflag(cflag);
        let flow_out = flow_out_from_flags(iflag, cflag);
        let flow_in = flow_in_from_flags(iflag, cflag);

        if state.serial.data_bits != data_bits {
            state.serial.data_bits = data_bits;
            state.events.push_back(DeviceEvent::DataSize(data_bits));
        }
        if state.serial.parity != parity {
            state.serial.parity = parity;
            state.events.push_back(DeviceEvent::Parity(parity));
        }
        if state.serial.stop_bits != stop_bits {
            state.serial.stop_bits = stop_bits;
            state.events.push_back(DeviceEvent::StopSize(stop_bits));
        }
        if state.serial.flow_out != flow_out {
            state.serial.flow_out = flow_out;
            state.events.push_back(DeviceEvent::FlowOut(flow_out));
        }
        if state.serial.flow_in != flow_in {
            state.serial.flow_in = flow_in;
            state.events.push_back(DeviceEvent::FlowIn(flow_in));
        }
        sync_termios_from_serial(state);
    }

    fn sync_termios_from_serial(state: &mut State) {
        let mut cflag = state.termios.c_cflag;
        let mut iflag = state.termios.c_iflag;
        cflag &= !(libc::CSIZE
            | libc::PARENB
            | libc::PARODD
            | libc::CMSPAR
            | libc::CSTOPB
            | libc::CRTSCTS
            | libc::CBAUD
            | libc::CBAUDEX);
        iflag &= !(libc::IXON | libc::IXOFF);

        cflag |= match state.serial.data_bits {
            5 => libc::CS5,
            6 => libc::CS6,
            7 => libc::CS7,
            _ => libc::CS8,
        };
        match state.serial.parity {
            serial::parity::ODD => cflag |= libc::PARENB | libc::PARODD,
            serial::parity::EVEN => cflag |= libc::PARENB,
            serial::parity::MARK => {
                cflag |= libc::PARENB | libc::PARODD | libc::CMSPAR;
            }
            serial::parity::SPACE => cflag |= libc::PARENB | libc::CMSPAR,
            _ => {}
        }
        if state.serial.stop_bits != serial::stop_size::ONE {
            cflag |= libc::CSTOPB;
        }
        if state.serial.flow_out == serial::control::HARDWARE_OUTBOUND
            || state.serial.flow_in == serial::control::HARDWARE_INBOUND
        {
            cflag |= libc::CRTSCTS;
        } else {
            if state.serial.flow_out == serial::control::XON_XOFF_OUTBOUND {
                iflag |= libc::IXON;
            }
            if state.serial.flow_in == serial::control::XON_XOFF_INBOUND {
                iflag |= libc::IXOFF;
            }
        }

        let baud = if state.hung_up { 0 } else { state.serial.baud };
        let code = baud_code(baud);
        cflag |= code;
        state.termios.c_cflag = cflag as _;
        state.termios.c_iflag = iflag as _;
        state.termios.c_ispeed = baud as _;
        state.termios.c_ospeed = baud as _;
    }

    fn set_termios_baud(termios: &mut libc::termios2, state: &State) {
        let mut cflag = termios.c_cflag;
        cflag &= !(libc::CBAUD | libc::CBAUDEX);
        if state.hung_up {
            cflag |= libc::B0;
        } else {
            let code = baud_code(state.serial.baud);
            cflag |= if code == libc::BOTHER {
                libc::B38400
            } else {
                code
            };
        }
        termios.c_cflag = cflag as _;
    }

    fn baud_from_termios(termios: &libc::termios2, allow_bother: bool) -> Result<u32, c_int> {
        let code = termios.c_cflag & (libc::CBAUD | libc::CBAUDEX);
        if allow_bother && code == libc::BOTHER {
            let input = termios.c_ispeed;
            let output = termios.c_ospeed;
            if input != output && input != 0 && output != 0 {
                return Err(libc::EINVAL);
            }
            return Ok(if output != 0 { output } else { input });
        }
        BAUD_CODES
            .iter()
            .find_map(|&(flag, baud)| (flag == code).then_some(baud))
            .ok_or(libc::EINVAL)
    }

    fn baud_code(baud: u32) -> u32 {
        BAUD_CODES
            .iter()
            .find_map(|&(flag, value)| (value == baud).then_some(flag))
            .unwrap_or(libc::BOTHER)
    }

    const BAUD_CODES: &[(u32, u32)] = &[
        (libc::B0, 0),
        (libc::B50, 50),
        (libc::B75, 75),
        (libc::B110, 110),
        (libc::B134, 134),
        (libc::B150, 150),
        (libc::B200, 200),
        (libc::B300, 300),
        (libc::B600, 600),
        (libc::B1200, 1200),
        (libc::B1800, 1800),
        (libc::B2400, 2400),
        (libc::B4800, 4800),
        (libc::B9600, 9600),
        (libc::B19200, 19200),
        (libc::B38400, 38400),
        (libc::B57600, 57600),
        (libc::B115200, 115200),
        (libc::B230400, 230400),
        (libc::B460800, 460800),
        (libc::B500000, 500000),
        (libc::B576000, 576000),
        (libc::B921600, 921600),
        (libc::B1000000, 1_000_000),
        (libc::B1152000, 1_152_000),
        (libc::B1500000, 1_500_000),
        (libc::B2000000, 2_000_000),
        (libc::B2500000, 2_500_000),
        (libc::B3000000, 3_000_000),
        (libc::B3500000, 3_500_000),
        (libc::B4000000, 4_000_000),
    ];

    fn data_bits_from_cflag(cflag: u32) -> u8 {
        match cflag & libc::CSIZE {
            value if value == libc::CS5 => 5,
            value if value == libc::CS6 => 6,
            value if value == libc::CS7 => 7,
            _ => 8,
        }
    }

    fn parity_from_cflag(cflag: u32) -> u8 {
        if cflag & libc::PARENB == 0 {
            return serial::parity::NONE;
        }
        if cflag & libc::CMSPAR != 0 {
            return if cflag & libc::PARODD != 0 {
                serial::parity::MARK
            } else {
                serial::parity::SPACE
            };
        }
        if cflag & libc::PARODD != 0 {
            serial::parity::ODD
        } else {
            serial::parity::EVEN
        }
    }

    fn stop_from_cflag(cflag: u32) -> u8 {
        if cflag & libc::CSTOPB == 0 {
            serial::stop_size::ONE
        } else if data_bits_from_cflag(cflag) == 5 {
            serial::stop_size::ONE_AND_A_HALF
        } else {
            serial::stop_size::TWO
        }
    }

    fn flow_out_from_flags(iflag: u32, cflag: u32) -> u8 {
        if cflag & libc::CRTSCTS != 0 {
            serial::control::HARDWARE_OUTBOUND
        } else if iflag & libc::IXON != 0 {
            serial::control::XON_XOFF_OUTBOUND
        } else {
            serial::control::NO_OUTBOUND_FLOW
        }
    }

    fn flow_in_from_flags(iflag: u32, cflag: u32) -> u8 {
        if cflag & libc::CRTSCTS != 0 {
            serial::control::HARDWARE_INBOUND
        } else if iflag & libc::IXOFF != 0 {
            serial::control::XON_XOFF_INBOUND
        } else {
            serial::control::NO_INBOUND_FLOW
        }
    }

    fn copy_termios2(value: &libc::termios2) -> libc::termios2 {
        // SAFETY: termios2 is POD and the source reference is valid.
        unsafe { ptr::read(value) }
    }

    fn struct_bytes<T>(value: &T) -> &[u8] {
        // SAFETY: callers use this only for plain C integer/termios structures and the returned
        // slice cannot outlive value.
        unsafe { std::slice::from_raw_parts((value as *const T).cast(), size_of::<T>()) }
    }

    fn prefix_bytes(value: &libc::termios2, length: usize) -> &[u8] {
        // SAFETY: length is the offset of a field inside value and therefore within the struct.
        unsafe { std::slice::from_raw_parts((value as *const libc::termios2).cast(), length) }
    }

    fn copy_into_struct(value: &mut libc::termios2, bytes: &[u8]) {
        let count = bytes.len().min(size_of::<libc::termios2>());
        // SAFETY: both buffers are valid for count bytes and do not overlap.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), (value as *mut libc::termios2).cast(), count);
        }
    }

    fn copy_prefix_into_struct(value: &mut libc::termios2, bytes: &[u8], length: usize) {
        let count = bytes.len().min(length);
        // SAFETY: length is within value and buffers do not overlap.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), (value as *mut libc::termios2).cast(), count);
        }
    }

    fn read_int(bytes: &[u8]) -> c_int {
        // SAFETY: caller verifies bytes contains at least one c_int; read_unaligned accepts any
        // byte alignment.
        unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<c_int>()) }
    }

    pub(super) struct Device {
        shared: Arc<Shared>,
        service: Option<RunningCuse<SerialDevice>>,
    }

    impl Device {
        pub(super) fn start(name: &str, serial: SerialState) -> Result<Self, String> {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/cuse")
                .map_err(|error| {
                    format!(
                        "cannot access /dev/cuse: {error} (load the cuse module and grant access to /dev/cuse)"
                    )
                })?;

            let shared = Arc::new(Shared::new(serial));
            let service = Cuse::new(name)
                .unrestricted_ioctl(true)
                .start(SerialDevice {
                    shared: Arc::clone(&shared),
                })
                .map_err(|error| format!("start CUSE device: {error}"))?;
            if let Err(error) = shared.wait_ready() {
                shared.stop();
                service.stop();
                return Err(error);
            }
            Ok(Self {
                shared,
                service: Some(service),
            })
        }

        pub(super) fn event_reader(&self) -> EventReader {
            EventReader {
                shared: Arc::clone(&self.shared),
            }
        }

        pub(super) fn push_rx(&self, data: &[u8]) -> Result<(), String> {
            self.shared.push_rx(data)
        }

        pub(super) fn remote_update(&self, event: &SerialEvent) {
            self.shared.remote_update(event);
        }

        pub(super) fn shutdown(&self) {
            self.shared.stop();
            if let Some(service) = &self.service {
                service.stop();
            }
        }
    }

    impl Drop for Device {
        fn drop(&mut self) {
            self.shared.stop();
            if let Some(service) = self.service.take() {
                let _ = service.shutdown();
            }
        }
    }

    pub(super) struct EventReader {
        shared: Arc<Shared>,
    }

    impl EventReader {
        pub(super) fn next_event(&self) -> Result<Option<DeviceEvent>, String> {
            self.shared.next_event()
        }
    }
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
pub(crate) async fn run_device(
    target: &str,
    port: u16,
    timeout: Duration,
    device_name: &str,
) -> Result<(), String> {
    let (mut session, mut pre_session) = negotiate_serial(target, port, timeout).await?;

    // Query the access server rather than imposing local defaults. Confirmations received before
    // the CUSE device is published seed its initial termios state; later confirmations update it.
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

    let device = cuse::Device::start(device_name, state)
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
