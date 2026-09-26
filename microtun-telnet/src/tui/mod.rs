use std::{io, path::Path};

use crossterm::{
    cursor::Show,
    event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use embedded_io_async::Write;
use futures_util::StreamExt;
use microtun_telnet_proto::serial;
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect, Size},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Gauge, Paragraph},
};
use tui_term::{vt100, widget::PseudoTerminal};

use crate::{
    keymap::{COMMAND_KEY, is_command_key, key_to_telnet_bytes},
    telnet::{
        ConsoleRead, SerialConsoleState, SerialStatus, TelnetClient, flow_label, parity_label,
        stop_label,
    },
    upload::{self, UploadEvent},
};

mod file_picker;

use file_picker::{FilePicker, PickerAction};

const SERIAL_FIELD_COUNT: usize = 8;
const BAUD_RATES: &[u32] = &[
    300, 1200, 2400, 4800, 9600, 19_200, 38_400, 57_600, 115_200, 230_400, 460_800, 921_600,
];
const PARITIES: &[u8] = &[
    serial::parity::NONE,
    serial::parity::ODD,
    serial::parity::EVEN,
    serial::parity::MARK,
    serial::parity::SPACE,
];
const STOP_BITS: &[u8] = &[
    serial::stop_size::ONE,
    serial::stop_size::TWO,
    serial::stop_size::ONE_AND_A_HALF,
];
const FLOW_MODES: &[(u8, u8)] = &[
    (
        serial::control::NO_OUTBOUND_FLOW,
        serial::control::NO_INBOUND_FLOW,
    ),
    (
        serial::control::XON_XOFF_OUTBOUND,
        serial::control::XON_XOFF_INBOUND,
    ),
    (
        serial::control::HARDWARE_OUTBOUND,
        serial::control::HARDWARE_INBOUND,
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TuiEnd {
    Quit,
    RemoteClosed,
}

struct TuiRestore;

impl Drop for TuiRestore {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen, Show);
    }
}

struct TransferProgress {
    name: String,
    sent: u64,
    total: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TuiMode {
    Session,
    CommandPrefix,
    CommandSummary,
    FilePicker,
    SerialControl,
}

struct TuiState {
    target: String,
    port: u16,
    mode: TuiMode,
    file_picker: Option<FilePicker>,
    status: String,
    transfer: Option<TransferProgress>,
    serial: Option<SerialConsoleState>,
    serial_selection: usize,
}

type TuiTerminal = Terminal<CrosstermBackend<io::Stdout>>;

pub(crate) async fn run_session(
    mut client: TelnetClient,
    target: &str,
    port: u16,
) -> Result<(), String> {
    enable_raw_mode().map_err(|error| format!("enable terminal raw mode: {error}"))?;
    let mut stdout = io::stdout();
    if let Err(error) = execute!(stdout, EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(format!("enter alternate terminal screen: {error}"));
    }
    let end = {
        let _restore = TuiRestore;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal =
            Terminal::new(backend).map_err(|error| format!("initialize terminal UI: {error}"))?;
        let size = terminal
            .size()
            .map_err(|error| format!("read terminal size: {error}"))?;
        let (rows, cols) = remote_parser_size(size);
        let mut parser = vt100::Parser::new(rows, cols, 10_000);
        let mut state = TuiState {
            target: target.to_owned(),
            port,
            mode: TuiMode::Session,
            file_picker: None,
            status: "Connected".to_owned(),
            transfer: None,
            serial: None,
            serial_selection: 0,
        };
        run_loop(&mut terminal, &mut client, &mut parser, &mut state).await?
    };

    if end == TuiEnd::RemoteClosed {
        eprintln!("connection closed by remote host");
    }
    Ok(())
}

async fn run_loop(
    terminal: &mut TuiTerminal,
    client: &mut TelnetClient,
    parser: &mut vt100::Parser,
    state: &mut TuiState,
) -> Result<TuiEnd, String> {
    let mut events = EventStream::new();
    let mut network_buf = [0u8; 4096];
    loop {
        refresh_serial_state(client, state);
        resize_remote_parser(terminal, parser)?;
        draw_terminal_ui(terminal, parser, state)?;

        tokio::select! {
            event = events.next() => {
                let event = event
                    .ok_or_else(|| "terminal event stream closed".to_owned())?
                    .map_err(|error| format!("read terminal input: {error}"))?;
                match event {
                    Event::Key(key)
                        if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) =>
                    {
                        match state.mode {
                            TuiMode::Session => {
                                if is_command_key(key) {
                                    state.mode = TuiMode::CommandPrefix;
                                    continue;
                                }
                                if let Some(bytes) = key_to_telnet_bytes(key) {
                                    client
                                        .write_all(&bytes)
                                        .await
                                        .map_err(|error| format!("write Telnet data: {error}"))?;
                                }
                            }
                            TuiMode::CommandPrefix => match key.code {
                                _ if is_command_key(key) => {
                                    client
                                        .write_all(&[COMMAND_KEY])
                                        .await
                                        .map_err(|error| format!("write Telnet data: {error}"))?;
                                    state.status = "Sent Ctrl-A to remote".to_owned();
                                    state.mode = TuiMode::Session;
                                }
                                KeyCode::Char('z') | KeyCode::Char('Z') => {
                                    state.mode = TuiMode::CommandSummary;
                                }
                                KeyCode::Char('s') | KeyCode::Char('S') => {
                                    open_file_picker(state).await;
                                }
                                KeyCode::Char('p') | KeyCode::Char('P') => {
                                    open_serial_control(client, state);
                                }
                                KeyCode::Char('f') | KeyCode::Char('F') => {
                                    send_break(client, state).await?;
                                }
                                KeyCode::Char('c') | KeyCode::Char('C') => {
                                    parser.process(b"\x1b[2J\x1b[H");
                                    state.status = "Screen cleared".to_owned();
                                    state.mode = TuiMode::Session;
                                }
                                KeyCode::Char('q') | KeyCode::Char('Q') => {
                                    return Ok(TuiEnd::Quit);
                                }
                                KeyCode::Esc | KeyCode::Enter => {
                                    state.mode = TuiMode::Session;
                                }
                                _ => {
                                    state.status = "Unknown command; Ctrl-A Z for help".to_owned();
                                    state.mode = TuiMode::Session;
                                }
                            },
                            TuiMode::CommandSummary => match key.code {
                                KeyCode::Esc | KeyCode::Enter => {
                                    state.mode = TuiMode::Session;
                                }
                                KeyCode::Char('s') | KeyCode::Char('S') => {
                                    open_file_picker(state).await;
                                }
                                KeyCode::Char('p') | KeyCode::Char('P') => {
                                    open_serial_control(client, state);
                                }
                                KeyCode::Char('f') | KeyCode::Char('F') => {
                                    send_break(client, state).await?;
                                }
                                KeyCode::Char('c') | KeyCode::Char('C') => {
                                    parser.process(b"\x1b[2J\x1b[H");
                                    state.status = "Screen cleared".to_owned();
                                    state.mode = TuiMode::Session;
                                }
                                KeyCode::Char('q') | KeyCode::Char('Q') => {
                                    return Ok(TuiEnd::Quit);
                                }
                                _ => {}
                            },
                            TuiMode::SerialControl => {
                                handle_serial_control_key(client, state, key).await?;
                            }
                            TuiMode::FilePicker => {
                                let action = match state.file_picker.as_mut() {
                                    Some(picker) => picker.handle_key(key).await,
                                    None => Ok(PickerAction::Cancel),
                                };
                                match action {
                                    Ok(PickerAction::None) => {}
                                    Ok(PickerAction::Cancel) => {
                                        state.file_picker = None;
                                        state.mode = TuiMode::Session;
                                    }
                                    Ok(PickerAction::Upload(path)) => {
                                        state.file_picker = None;
                                        state.mode = TuiMode::Session;
                                        if let Err(error) = execute_upload(
                                            terminal,
                                            client,
                                            parser,
                                            state,
                                            &path,
                                        )
                                        .await
                                        {
                                            state.status = format!("YMODEM failed: {error}");
                                        }
                                    }
                                    Err(error) => {
                                        state.status = format!("File picker: {error}");
                                    }
                                }
                            }
                        }
                    }
                    Event::Resize(_, _) => {
                        resize_remote_parser(terminal, parser)?;
                    }
                    _ => {}
                }
            }
            network = client.read_console(&mut network_buf) => {
                refresh_serial_state(client, state);
                match network {
                    Ok(ConsoleRead::Closed) => return Ok(TuiEnd::RemoteClosed),
                    Ok(ConsoleRead::Data(len)) => parser.process(&network_buf[..len]),
                    Ok(ConsoleRead::StateChanged) | Ok(ConsoleRead::Timeout) => {},
                    Err(error) => return Err(format!("read Telnet connection: {error}")),
                }
            }
        }
    }
}

fn refresh_serial_state(client: &TelnetClient, state: &mut TuiState) {
    state.serial = client.serial_state().cloned();
    if state.status == "Serial mode; negotiating (current UART settings unchanged)" {
        match state.serial.as_ref().map(|serial| serial.status) {
            Some(SerialStatus::Active) => state.status = "Serial mode active".to_owned(),
            Some(SerialStatus::Refused) => {
                state.status = "Serial mode refused (data only)".to_owned();
            }
            Some(SerialStatus::Negotiating) | None => {}
        }
    }
}

async fn set_serial_mode(
    client: &mut TelnetClient,
    state: &mut TuiState,
    enabled: bool,
) -> Result<(), String> {
    if enabled == client.serial_mode() {
        return Ok(());
    }

    if enabled {
        client
            .enter_serial_mode()
            .await
            .map_err(|error| format!("enter serial mode: {error}"))?;
        state.serial = client.serial_state().cloned();
        state.status = "Serial mode; negotiating (current UART settings unchanged)".to_owned();
    } else {
        client
            .leave_serial_mode()
            .await
            .map_err(|error| format!("leave serial mode: {error}"))?;
        state.serial = None;
        state.status = "Telnet mode".to_owned();
    }
    Ok(())
}

fn open_serial_control(client: &TelnetClient, state: &mut TuiState) {
    state.serial = client.serial_state().cloned();
    state.serial_selection = if client.serial_mode() { 1 } else { 0 };
    state.mode = TuiMode::SerialControl;
}

async fn send_break(client: &mut TelnetClient, state: &mut TuiState) -> Result<(), String> {
    if !client.serial_mode() {
        state.status = "Enable serial mode with Ctrl-A P before sending BREAK".to_owned();
        state.mode = TuiMode::Session;
        return Ok(());
    }
    if !client.serial_active() {
        state.status = "serial COM-PORT-OPTION is not active yet".to_owned();
        state.mode = TuiMode::Session;
        return Ok(());
    }

    client
        .send_break_pulse()
        .await
        .map_err(|error| format!("send serial BREAK: {error}"))?;
    state.status = "Sent 250 ms BREAK".to_owned();
    state.serial = client.serial_state().cloned();
    state.mode = TuiMode::Session;
    Ok(())
}

async fn handle_serial_control_key(
    client: &mut TelnetClient,
    state: &mut TuiState,
    key: KeyEvent,
) -> Result<(), String> {
    match key.code {
        KeyCode::Esc => {
            state.mode = TuiMode::Session;
            return Ok(());
        }
        KeyCode::Up => {
            state.serial_selection = state.serial_selection.saturating_sub(1);
            return Ok(());
        }
        KeyCode::Down => {
            state.serial_selection = (state.serial_selection + 1).min(SERIAL_FIELD_COUNT - 1);
            return Ok(());
        }
        KeyCode::Char('f') | KeyCode::Char('F') => {
            if !client.serial_mode() {
                state.status = "Enable serial mode before sending BREAK".to_owned();
            } else if !client.serial_active() {
                state.status = "serial COM-PORT-OPTION is not active yet".to_owned();
            } else {
                client
                    .send_break_pulse()
                    .await
                    .map_err(|error| format!("send serial BREAK: {error}"))?;
                state.status = "Sent 250 ms BREAK".to_owned();
            }
            state.serial = client.serial_state().cloned();
            return Ok(());
        }
        _ => {}
    }

    if state.serial_selection == 0 {
        match key.code {
            KeyCode::Left => {
                set_serial_mode(client, state, false).await?;
            }
            KeyCode::Right => {
                set_serial_mode(client, state, true).await?;
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                set_serial_mode(client, state, !client.serial_mode()).await?;
            }
            _ => {}
        }
        state.serial = client.serial_state().cloned();
        return Ok(());
    }

    if !client.serial_mode() {
        state.status = "Enable serial mode on the first row".to_owned();
        return Ok(());
    }
    if !client.serial_active() {
        state.status = "serial COM-PORT-OPTION is not active yet".to_owned();
        state.serial = client.serial_state().cloned();
        return Ok(());
    }

    match key.code {
        KeyCode::Left => adjust_serial_setting(client, state, -1).await?,
        KeyCode::Right => adjust_serial_setting(client, state, 1).await?,
        KeyCode::Enter | KeyCode::Char(' ') => toggle_serial_setting(client, state).await?,
        _ => {}
    }
    state.serial = client.serial_state().cloned();
    Ok(())
}

async fn adjust_serial_setting(
    client: &mut TelnetClient,
    state: &mut TuiState,
    delta: isize,
) -> Result<(), String> {
    let serial = client.serial_state().cloned().unwrap_or_default();
    match state.serial_selection {
        1 => {
            let value = step_value(BAUD_RATES, serial.baud.unwrap_or(9_600), delta);
            client
                .set_baud(value)
                .await
                .map_err(|error| format!("set serial baud rate: {error}"))?;
            state.status = format!("Requested {value} baud");
        }
        2 => {
            let current = serial.data_bits.unwrap_or(8);
            let value = (current as isize + delta).clamp(5, 8) as u8;
            client
                .set_data_bits(value)
                .await
                .map_err(|error| format!("set serial data bits: {error}"))?;
            state.status = format!("Requested {value} data bits");
        }
        3 => {
            let value = step_value(
                PARITIES,
                serial.parity.unwrap_or(serial::parity::NONE),
                delta,
            );
            client
                .set_parity(value)
                .await
                .map_err(|error| format!("set serial parity: {error}"))?;
            state.status = format!("Requested parity {}", parity_label(value));
        }
        4 => {
            let value = step_value(
                STOP_BITS,
                serial.stop_bits.unwrap_or(serial::stop_size::ONE),
                delta,
            );
            client
                .set_stop_bits(value)
                .await
                .map_err(|error| format!("set serial stop bits: {error}"))?;
            state.status = format!("Requested {} stop bits", stop_label(value));
        }
        5 => {
            let current = (serial.flow_out, serial.flow_in);
            let current_index = FLOW_MODES
                .iter()
                .position(|&(outbound, inbound)| current == (Some(outbound), Some(inbound)))
                .unwrap_or(0);
            let index = step_index(current_index, FLOW_MODES.len(), delta);
            let (outbound, inbound) = FLOW_MODES[index];
            client
                .set_flow(outbound, inbound)
                .await
                .map_err(|error| format!("set serial flow control: {error}"))?;
            state.status = format!(
                "Requested {} flow control",
                flow_label(Some(outbound), Some(inbound))
            );
        }
        6 => {
            let on = delta > 0;
            client
                .set_dtr(on)
                .await
                .map_err(|error| format!("set serial DTR: {error}"))?;
            state.status = format!("Requested DTR {}", if on { "on" } else { "off" });
        }
        7 => {
            let on = delta > 0;
            client
                .set_rts(on)
                .await
                .map_err(|error| format!("set serial RTS: {error}"))?;
            state.status = format!("Requested RTS {}", if on { "on" } else { "off" });
        }
        _ => {}
    }
    Ok(())
}

async fn toggle_serial_setting(
    client: &mut TelnetClient,
    state: &mut TuiState,
) -> Result<(), String> {
    let serial = client.serial_state().cloned().unwrap_or_default();
    match state.serial_selection {
        6 => {
            let on = !serial.dtr.unwrap_or(false);
            client
                .set_dtr(on)
                .await
                .map_err(|error| format!("set serial DTR: {error}"))?;
            state.status = format!("Requested DTR {}", if on { "on" } else { "off" });
        }
        7 => {
            let on = !serial.rts.unwrap_or(false);
            client
                .set_rts(on)
                .await
                .map_err(|error| format!("set serial RTS: {error}"))?;
            state.status = format!("Requested RTS {}", if on { "on" } else { "off" });
        }
        _ => adjust_serial_setting(client, state, 1).await?,
    }
    Ok(())
}

fn step_value<T: Copy + PartialEq>(values: &[T], current: T, delta: isize) -> T {
    let index = values
        .iter()
        .position(|value| *value == current)
        .unwrap_or(0);
    values[step_index(index, values.len(), delta)]
}

fn step_index(index: usize, len: usize, delta: isize) -> usize {
    if delta < 0 {
        index.saturating_sub(1)
    } else {
        (index + 1).min(len.saturating_sub(1))
    }
}

async fn open_file_picker(state: &mut TuiState) {
    match FilePicker::from_current_dir().await {
        Ok(picker) => {
            state.file_picker = Some(picker);
            state.mode = TuiMode::FilePicker;
        }
        Err(error) => {
            state.status = format!("File picker: {error}");
            state.mode = TuiMode::Session;
        }
    }
}

async fn execute_upload(
    terminal: &mut TuiTerminal,
    client: &mut TelnetClient,
    parser: &mut vt100::Parser,
    state: &mut TuiState,
    path: &Path,
) -> Result<(), String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("upload.bin")
        .to_owned();
    state.transfer = Some(TransferProgress {
        name: name.clone(),
        sent: 0,
        total: 0,
    });
    state.status = format!("Sending {}", path.display());
    draw_terminal_ui(terminal, parser, state)?;
    let result = upload::send_file_with(client, path, async |event| {
        match event {
            UploadEvent::Output(byte) => parser.process(&[byte]),
            UploadEvent::Progress { sent, total } => {
                state.transfer = Some(TransferProgress {
                    name: name.clone(),
                    sent: sent as u64,
                    total: total as u64,
                });
            }
        }
        resize_remote_parser(terminal, parser)?;
        draw_terminal_ui(terminal, parser, state)
    })
    .await;
    state.transfer = None;
    match result {
        Ok(size) => {
            state.status = format!("YMODEM complete: {size} bytes");
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn draw_terminal_ui(
    terminal: &mut TuiTerminal,
    parser: &vt100::Parser,
    state: &TuiState,
) -> Result<(), String> {
    terminal
        .draw(|frame| {
            let area = frame.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(1), Constraint::Length(1)])
                .split(area);

            frame.render_widget(PseudoTerminal::new(parser.screen()), chunks[0]);
            let mut status = vec![
                Span::styled(
                    " CTRL-A Z for help ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw("| "),
                Span::raw(&state.status),
            ];
            if let Some(serial) = state.serial.as_ref() {
                status.push(Span::raw(" | "));
                status.push(Span::raw(serial_summary(serial)));
            } else {
                status.push(Span::raw(" | TELNET"));
            }
            status.push(Span::raw(" | "));
            status.push(Span::raw(format!("{}:{} ", state.target, state.port)));
            frame.render_widget(
                Paragraph::new(Line::from(status))
                    .style(Style::default().add_modifier(Modifier::REVERSED)),
                chunks[1],
            );
            if let Some(transfer) = state.transfer.as_ref() {
                let popup = centered_rect(64, 5, area);
                frame.render_widget(Clear, popup);
                let ratio = if transfer.total == 0 {
                    0.0
                } else {
                    (transfer.sent as f64 / transfer.total as f64).clamp(0.0, 1.0)
                };
                let label = if transfer.total == 0 {
                    "Waiting for receiver".to_owned()
                } else {
                    format!("{} / {} bytes", transfer.sent, transfer.total)
                };
                let gauge = Gauge::default()
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(format!(" Send file · {} ", transfer.name)),
                    )
                    .ratio(ratio)
                    .label(label);
                frame.render_widget(gauge, popup);
            } else {
                match state.mode {
                    TuiMode::CommandSummary => render_command_summary(frame, area, state),
                    TuiMode::SerialControl => render_serial_control(frame, area, state),
                    TuiMode::CommandPrefix => {}
                    TuiMode::FilePicker => {
                        if let Some(picker) = state.file_picker.as_ref() {
                            picker.render(frame, area);
                        }
                    }
                    TuiMode::Session => {}
                }
            }
        })
        .map(|_| ())
        .map_err(|error| format!("draw terminal UI: {error}"))
}

fn render_command_summary(frame: &mut ratatui::Frame<'_>, area: Rect, _state: &TuiState) {
    let lines = vec![
        Line::from(""),
        Line::from("  Commands can be called by CTRL-A <key>"),
        Line::from(""),
        Line::from("  Send files................S"),
        Line::from("  Communication parameters.P"),
        Line::from("  Send BREAK................F"),
        Line::from("  Clear Screen..............C"),
        Line::from("  Quit......................Q"),
        Line::from("  Help screen...............Z"),
        Line::from(""),
        Line::from("  Select function or press Enter for none."),
    ];
    let popup = centered_rect(66, 15, area);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Command Summary "),
        ),
        popup,
    );
}

fn serial_summary(serial: &SerialConsoleState) -> String {
    match serial.status {
        SerialStatus::Negotiating => "Serial negotiating".to_owned(),
        SerialStatus::Refused => "Serial refused".to_owned(),
        SerialStatus::Active => {
            let baud = serial
                .baud
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".to_owned());
            let data = serial
                .data_bits
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".to_owned());
            let parity = serial.parity.map(parity_label).unwrap_or("?");
            let stop = serial.stop_bits.map(stop_label).unwrap_or("?");
            let flow = flow_label(serial.flow_out, serial.flow_in);
            let paused = if serial.tx_suspended { " paused" } else { "" };
            format!("Serial {baud} {data}{parity}{stop} {flow}{paused}")
        }
    }
}

fn render_serial_control(frame: &mut ratatui::Frame<'_>, area: Rect, state: &TuiState) {
    let serial = state.serial.clone().unwrap_or_default();
    let rows = [
        format!(
            "Serial mode    {}",
            if state.serial.is_some() {
                "ON"
            } else {
                "OFF (Telnet)"
            }
        ),
        format!("Baud rate      {}", display_option(serial.baud)),
        format!("Data bits      {}", display_option(serial.data_bits)),
        format!(
            "Parity         {}",
            serial.parity.map(parity_label).unwrap_or("?")
        ),
        format!(
            "Stop bits      {}",
            serial.stop_bits.map(stop_label).unwrap_or("?")
        ),
        format!(
            "Flow control  {}",
            flow_label(serial.flow_out, serial.flow_in)
        ),
        format!("DTR            {}", on_off(serial.dtr)),
        format!("RTS            {}", on_off(serial.rts)),
    ];
    let summary = state
        .serial
        .as_ref()
        .map(serial_summary)
        .unwrap_or_else(|| "Telnet mode · Serial disabled".to_owned());
    let mut lines = vec![Line::from(format!("  {summary}")), Line::from("")];
    for (index, row) in rows.into_iter().enumerate() {
        let marker = if index == state.serial_selection {
            ">"
        } else {
            " "
        };
        lines.push(Line::from(format!(" {marker} {row}")));
    }
    lines.extend([
        Line::from(""),
        Line::from(format!(
            "  Modem  {}   Line  {}",
            modem_state_label(serial.modem_state),
            line_state_label(serial.line_state)
        )),
        Line::from("  Up/Down select · Left/Right change"),
        Line::from("  Enter/Space choose · F sends BREAK · Esc closes"),
    ]);

    let popup = centered_rect(76, 16, area);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Communication Parameters · serial "),
        ),
        popup,
    );
}

fn display_option<T: std::fmt::Display>(value: Option<T>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "?".to_owned())
}

fn on_off(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "on",
        Some(false) => "off",
        None => "?",
    }
}

fn modem_state_label(value: u8) -> String {
    let mut flags = Vec::new();
    if value & serial::modem_state::CTS != 0 {
        flags.push("CTS");
    }
    if value & serial::modem_state::DSR != 0 {
        flags.push("DSR");
    }
    if value & serial::modem_state::RING_INDICATOR != 0 {
        flags.push("RI");
    }
    if value & serial::modem_state::CARRIER_DETECT != 0 {
        flags.push("CD");
    }
    if flags.is_empty() {
        "none".to_owned()
    } else {
        flags.join(" ")
    }
}

fn line_state_label(value: u8) -> String {
    let mut flags = Vec::new();
    if value & serial::line_state::DATA_READY != 0 {
        flags.push("DR");
    }
    if value & serial::line_state::OVERRUN_ERROR != 0 {
        flags.push("OE");
    }
    if value & serial::line_state::PARITY_ERROR != 0 {
        flags.push("PE");
    }
    if value & serial::line_state::FRAMING_ERROR != 0 {
        flags.push("FE");
    }
    if value & serial::line_state::BREAK_DETECT != 0 {
        flags.push("BRK");
    }
    if value & serial::line_state::TIMEOUT_ERROR != 0 {
        flags.push("TO");
    }
    if flags.is_empty() {
        "ok".to_owned()
    } else {
        flags.join(" ")
    }
}

fn resize_remote_parser(terminal: &TuiTerminal, parser: &mut vt100::Parser) -> Result<(), String> {
    let size = terminal
        .size()
        .map_err(|error| format!("read terminal size: {error}"))?;
    let (rows, cols) = remote_parser_size(size);
    if parser.screen().size() != (rows, cols) {
        parser.set_size(rows, cols);
    }
    Ok(())
}

fn remote_parser_size(size: Size) -> (u16, u16) {
    let rows = size.height.saturating_sub(1).max(1);
    let cols = size.width.max(1);
    (rows, cols)
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_size_reserves_one_status_line() {
        assert_eq!(remote_parser_size(Size::new(80, 24)), (23, 80));
        assert_eq!(remote_parser_size(Size::new(1, 1)), (1, 1));
    }

    #[test]
    fn serial_steps_do_not_wrap() {
        assert_eq!(step_value(&[1, 2, 3], 1, -1), 1);
        assert_eq!(step_value(&[1, 2, 3], 2, 1), 3);
        assert_eq!(step_value(&[1, 2, 3], 3, 1), 3);
    }
}
