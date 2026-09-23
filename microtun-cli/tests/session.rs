//! End-to-end session tests over an in-memory transport.

use core::convert::Infallible;

use embedded_io_async::Write;
use futures_lite::future::block_on;
use microtun_cli::{
    Config, Console, Dispatch, Error, ErrorKind, Parser, Session,
    telnet::{DO, DONT, IAC, OPT_ECHO},
    write_fmt,
};

/// A transport that replays a fixed script and records everything written back.
struct Loopback {
    input: std::vec::Vec<u8>,
    read_at: usize,
    output: std::vec::Vec<u8>,
}

impl Loopback {
    fn new(input: &[u8]) -> Self {
        Self {
            input: input.to_vec(),
            read_at: 0,
            output: std::vec::Vec::new(),
        }
    }
}

impl embedded_io::ErrorType for Loopback {
    type Error = Infallible;
}

impl embedded_io_async::Read for Loopback {
    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Infallible> {
        let remaining = self.input.len() - self.read_at;
        if remaining == 0 {
            return Ok(0);
        }
        let count = remaining.min(buffer.len()).min(8);
        buffer[..count].copy_from_slice(&self.input[self.read_at..self.read_at + count]);
        self.read_at += count;
        Ok(count)
    }
}

impl embedded_io_async::Write for Loopback {
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, Infallible> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    async fn flush(&mut self) -> Result<(), Infallible> {
        Ok(())
    }
}

struct App {
    greetings: u32,
}

#[test]
fn console_uses_standard_write_and_escapes_iac() {
    let mut io = Loopback::new(&[]);
    {
        let mut out = Console::new(&mut io);
        block_on(out.write_all(&[b'a', IAC, b'b'])).unwrap();
    }
    assert_eq!(io.output, [b'a', IAC, IAC, b'b']);
}

impl App {
    async fn greet<W: Write<Error = ErrorKind> + ?Sized>(
        this: &mut Self,
        out: &mut W,
    ) -> Result<(), Error> {
        this.greetings += 1;
        out.write_all(b"hello\r\n").await?;
        Ok(())
    }

    /// Deliberately overflows the bounded format helper's scratch buffer.
    async fn flood<W: Write<Error = ErrorKind> + ?Sized>(
        _this: &mut Self,
        out: &mut W,
    ) -> Result<(), Error> {
        let long = "x".repeat(4096);
        write_fmt::<64, _>(out, format_args!("{long}")).await
    }

    async fn exit<W: Write<Error = ErrorKind> + ?Sized>(
        _this: &mut Self,
        out: &mut W,
    ) -> Result<(), Error> {
        out.write_all(b"bye\r\n").await?;
        out.flush().await?;
        Err(Error::Disconnected)
    }
}

#[derive(Parser, Dispatch)]
#[command(name = "test", version = "9.9.9")]
#[dispatch(context = App)]
enum Command {
    #[command(handler = App::greet)]
    Greet,
    #[command(handler = App::flood)]
    Flood,
    #[command(handler = App::exit)]
    Exit,
    /// No handler is attached, so dispatch reports `NoHandler`.
    Orphan,
}

/// Run a session against `script` and return everything the server wrote.
fn run(script: &[u8], negotiate: bool) -> (String, App) {
    let io = Loopback::new(script);
    let mut app = App { greetings: 0 };
    let mut session = Session::<_, 128, 4, 64>::new(
        io,
        Config::new("> ")
            .negotiate_telnet(negotiate)
            .help_hint(false),
    );
    let result = block_on(session.serve::<CommandParser, _>(&mut app));
    // The script always runs out, which the session reports as a disconnect.
    assert!(matches!(result, Err(Error::Disconnected)));
    let io = session.into_inner();
    (String::from_utf8_lossy(&io.output).into_owned(), app)
}

#[test]
fn a_handler_error_reports_without_dropping_the_session() {
    let (output, app) = run(b"flood\r\ngreet\r\n", false);
    assert!(output.contains("error: output did not fit the format buffer"));
    // The prompt came back and the next command still ran.
    assert!(output.contains("hello"));
    assert_eq!(app.greetings, 1);
}

#[test]
fn a_command_without_a_handler_is_reported() {
    let (output, _) = run(b"orphan\r\n", false);
    assert!(output.contains("error: command has no handler"));
}

#[test]
fn input_is_echoed_when_the_client_accepts_our_echo_offer() {
    let mut script = std::vec::Vec::new();
    script.extend_from_slice(&[IAC, DO, OPT_ECHO]);
    script.extend_from_slice(b"greet\r\n");
    let (output, _) = run(&script, true);
    // Each typed character came back before the command output did.
    let typed = output.find("greet").expect("echoed input");
    let replied = output.find("hello").expect("command output");
    assert!(typed < replied);
}

#[test]
fn input_is_not_echoed_when_the_client_refuses() {
    let mut script = std::vec::Vec::new();
    script.extend_from_slice(&[IAC, DONT, OPT_ECHO]);
    script.extend_from_slice(b"greet\r\n");
    let (output, app) = run(&script, true);
    assert_eq!(app.greetings, 1);
    assert!(output.contains("hello"));
    // The client is echoing locally, so the server must not send the characters back.
    assert!(!output.contains("greet"));
}

#[test]
fn version_is_answered_at_the_end_of_a_line_too() {
    let (output, _) = run(b"--version\r\ntest --version\r\n", false);
    assert_eq!(output.matches("test 9.9.9").count(), 2);
}

#[test]
fn disconnected_from_handler_ends_the_session_without_an_error_or_new_prompt() {
    let io = Loopback::new(b"exit\r\ngreet\r\n");
    let mut app = App { greetings: 0 };
    let mut session = Session::<_, 128, 4, 64>::new(
        io,
        Config::new("> ").negotiate_telnet(false).help_hint(false),
    );

    let result = block_on(session.serve::<CommandParser, _>(&mut app));
    assert_eq!(result, Err(Error::Disconnected));

    let io = session.into_inner();
    let output = String::from_utf8_lossy(&io.output);
    assert!(output.contains("bye"));
    assert!(!output.contains("error: disconnected"));
    assert_eq!(output.matches("> ").count(), 1);
    assert_eq!(app.greetings, 0);
}
