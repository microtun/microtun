use embedded_io::ErrorType;
use embedded_io_async::Write;
use futures_lite::future::block_on;
use microtun_cli::{Dispatch, Error, ErrorKind, Parser, ParserFamily};

#[derive(Default)]
struct App {
    calls: u8,
}

impl App {
    async fn echo<W: Write<Error = ErrorKind> + ?Sized>(
        this: &mut Self,
        out: &mut W,
        text: &str,
        upper: bool,
    ) -> Result<(), Error> {
        this.calls = this.calls.saturating_add(1);
        if upper {
            out.write_all(b"UP:").await?;
        }
        out.write_all(text.as_bytes()).await?;
        Ok(())
    }
}

#[derive(Parser, Dispatch)]
#[command(name = "device")]
#[dispatch(context = App)]
enum Command<'a> {
    #[command(handler = App::echo)]
    Echo {
        text: &'a str,
        #[arg(short, long)]
        upper: bool,
    },
}

#[derive(Default)]
struct TestOut(std::string::String);

impl ErrorType for TestOut {
    type Error = ErrorKind;
}

impl Write for TestOut {
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, ErrorKind> {
        self.0.push_str(core::str::from_utf8(bytes).unwrap());
        Ok(bytes.len())
    }

    async fn flush(&mut self) -> Result<(), ErrorKind> {
        Ok(())
    }
}

#[test]
fn dispatches_borrowed_arguments_without_boxing() {
    let mut line = [0u8; 128];
    let text = "echo hello -u";
    line[..text.len()].copy_from_slice(text.as_bytes());
    let command = <CommandParser as ParserFamily>::parse(&mut line, text.len()).unwrap();

    let mut app = App::default();
    let mut out = TestOut::default();
    block_on(command.dispatch(&mut app, &mut out)).unwrap();

    assert_eq!(app.calls, 1);
    assert_eq!(out.0, "UP:hello");
}
