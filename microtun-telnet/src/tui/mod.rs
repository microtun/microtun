use std::{io, path::Path};

use crossterm::{
    cursor::Show,
    event::{Event, EventStream, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use embedded_io_async::{Read, Write};
use futures_util::StreamExt;
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
    telnet::TelnetClient,
    upload::{self, UploadEvent},
};

mod file_picker;

use file_picker::{FilePicker, PickerAction};

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
}

struct TuiState {
    target: String,
    port: u16,
    mode: TuiMode,
    file_picker: Option<FilePicker>,
    status: String,
    transfer: Option<TransferProgress>,
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
            network = client.read(&mut network_buf) => {
                match network {
                    Ok(0) => return Ok(TuiEnd::RemoteClosed),
                    Ok(len) => parser.process(&network_buf[..len]),
                    Err(error) if error.kind() == io::ErrorKind::TimedOut => {}
                    Err(error) => return Err(format!("read Telnet connection: {error}")),
                }
            }
        }
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
            let status = Line::from(vec![
                Span::styled(
                    " CTRL-A Z for help ",
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::raw("| "),
                Span::raw(&state.status),
                Span::raw(" | VT100 | "),
                Span::raw(format!("{}:{} ", state.target, state.port)),
            ]);
            frame.render_widget(
                Paragraph::new(status).style(Style::default().add_modifier(Modifier::REVERSED)),
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
                    TuiMode::CommandSummary => {
                        let popup = centered_rect(62, 12, area);
                        frame.render_widget(Clear, popup);
                        let summary = Paragraph::new(vec![
                            Line::from(""),
                            Line::from("  Commands can be called by CTRL-A <key>"),
                            Line::from(""),
                            Line::from("  Send files................S"),
                            Line::from("  Clear Screen..............C"),
                            Line::from("  Quit......................Q"),
                            Line::from("  Help screen...............Z"),
                            Line::from(""),
                            Line::from("  Select function or press Enter for none."),
                        ])
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title(" Command Summary "),
                        );
                        frame.render_widget(summary, popup);
                    }
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
}
