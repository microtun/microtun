use core::convert::Infallible;

use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};
use futures_lite::future::block_on;
use microtun_cli::{Config, Dispatch, Error, ErrorKind, Parser, ParserFamily, Session, ValueEnum};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Kind {
    /// Read digital input.
    Input,
    /// Inspect or control a relay.
    #[value(alias = "switch", visible_alias = "output")]
    Relay,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PlainKind {
    Alpha,
    Beta,
}

#[derive(Parser)]
#[command(name = "device", about = "test device")]
enum Command<'a> {
    /// Inspect I/O.
    #[command(alias = "hidden-io", visible_alias = "pins")]
    Io {
        input: &'a str,
        /// Select I/O kind.
        #[arg(long, value_enum, alias = "secret-kind", visible_alias = "kind")]
        mode: Option<Kind>,
    },
    /// Show an undocumented value enum.
    Plain {
        #[arg(value_enum, value_name = "KIND")]
        kind: PlainKind,
    },
    /// Require an enabled flag.
    Require {
        #[arg(long, required = true)]
        enabled: bool,
    },
}

impl<'a> Dispatch<()> for Command<'a> {
    async fn dispatch<W: Write<Error = ErrorKind> + ?Sized>(
        self,
        _context: &mut (),
        _out: &mut W,
    ) -> Result<(), Error> {
        match self {
            Self::Io { input, mode } => {
                let _ = (input, mode);
            }
            Self::Plain { kind } => {
                let _ = kind;
            }
            Self::Require { enabled } => {
                let _ = enabled;
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct TextOut(std::string::String);

impl ErrorType for TextOut {
    type Error = ErrorKind;
}

impl Write for TextOut {
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, ErrorKind> {
        self.0.push_str(core::str::from_utf8(bytes).unwrap());
        Ok(bytes.len())
    }

    async fn flush(&mut self) -> Result<(), ErrorKind> {
        Ok(())
    }
}

#[test]
fn help_uses_value_docs_visible_aliases_and_required_metadata() {
    let mut out = TextOut::default();
    block_on(microtun_cli::help::write_help(
        &mut out,
        &CommandParser::ROOT,
        &["io"],
    ))
    .unwrap();

    assert!(!out.0.contains("[possible values: input, relay]"));
    assert!(out.0.contains("Read digital input."));
    assert!(
        out.0
            .contains("relay [aliases: output]  Inspect or control a relay.")
    );
    assert!(out.0.contains("[aliases: --kind]"));
    assert!(!out.0.contains("secret-kind"));
    assert!(!out.0.contains("switch"));

    let option_description = out.0.find("Select I/O kind.").unwrap();
    let option_line_start = out.0[..option_description].rfind("\n").map_or(0, |i| i + 1);
    let help_description = out.0.find("Print help").unwrap();
    let help_line_start = out.0[..help_description].rfind("\n").map_or(0, |i| i + 1);
    assert_eq!(
        option_description - option_line_start,
        help_description - help_line_start
    );

    let input_description = out.0.find("Read digital input.").unwrap();
    let input_line_start = out.0[..input_description].rfind("\n").map_or(0, |i| i + 1);
    let relay_description = out.0.find("Inspect or control a relay.").unwrap();
    let relay_line_start = out.0[..relay_description].rfind("\n").map_or(0, |i| i + 1);
    assert_eq!(
        input_description - input_line_start,
        relay_description - relay_line_start
    );

    let mut out = TextOut::default();
    block_on(microtun_cli::help::write_help(
        &mut out,
        &CommandParser::ROOT,
        &["plain"],
    ))
    .unwrap();
    assert!(out.0.contains("<KIND> [possible values: alpha, beta]"));

    let mut out = TextOut::default();
    block_on(microtun_cli::help::write_help(
        &mut out,
        &CommandParser::ROOT,
        &["require"],
    ))
    .unwrap();
    assert!(out.0.contains("Usage: device require --enabled"));
    assert!(out.0.contains("--enabled [required]"));

    let mut out = TextOut::default();
    block_on(microtun_cli::help::write_help(
        &mut out,
        &CommandParser::ROOT,
        &[],
    ))
    .unwrap();
    assert!(out.0.contains("io [aliases: pins]"));
    assert!(!out.0.contains("hidden-io"));

    let io_description = out.0.find("Inspect I/O.").unwrap();
    let io_line_start = out.0[..io_description].rfind("\n").map_or(0, |i| i + 1);
    let require_description = out.0.find("Require an enabled flag.").unwrap();
    let require_line_start = out.0[..require_description]
        .rfind("\n")
        .map_or(0, |i| i + 1);
    assert_eq!(
        io_description - io_line_start,
        require_description - require_line_start
    );
}

struct MockIo {
    input: std::vec::Vec<u8>,
    read: bool,
    output: std::string::String,
}

impl MockIo {
    fn new(input: &str) -> Self {
        Self {
            input: input.as_bytes().to_vec(),
            read: false,
            output: std::string::String::new(),
        }
    }
}

impl ErrorType for MockIo {
    type Error = Infallible;
}

impl Read for MockIo {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if self.read {
            return Ok(0);
        }
        self.read = true;
        let count = self.input.len().min(buf.len());
        buf[..count].copy_from_slice(&self.input[..count]);
        Ok(count)
    }
}

impl Write for MockIo {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.output.push_str(core::str::from_utf8(buf).unwrap());
        Ok(buf.len())
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
fn trailing_help_ignores_positionals_when_building_command_path() {
    let io = MockIo::new("io input --help\r");
    let config = Config::new("").negotiate_telnet(false);
    let mut session = Session::<_, 128, 1, 256>::new(io, config);
    let mut context = ();

    let result = block_on(session.serve::<CommandParser, _>(&mut context));
    assert_eq!(result, Err(Error::Disconnected));

    let io = session.into_inner();
    assert!(io.output.contains("Usage: device io <INPUT>"));
    assert!(!io.output.contains("unknown command in help path"));
}
