use embedded_io_async::{Read, Write};
use heapless::Vec;

#[cfg(feature = "completion")]
use crate::completion::complete;
#[cfg(feature = "help")]
use crate::help::write_help;
use crate::{
    Error, ParseErrorKind, RootSpec,
    editor::{Editor, EditorEvent},
    io::{Console, write_fmt, write_line, write_str},
    parse::{Dispatch, ParserFamily},
    telnet::{OPT_ECHO, Telnet, TelnetEvent},
};

/// Length of the longest shared prefix of `a` and `b`, on a character boundary.
#[cfg(feature = "completion")]
fn common_prefix_len(a: &str, b: &str) -> usize {
    let mut end = 0usize;
    let mut left = a.char_indices();
    let mut right = b.chars();
    loop {
        match (left.next(), right.next()) {
            (Some((index, x)), Some(y)) if x == y => end = index + x.len_utf8(),
            _ => return end,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub prompt: &'static str,
    pub banner: Option<&'static str>,
    pub negotiate_telnet: bool,
    pub help_hint: bool,
}

impl Config {
    pub const fn new(prompt: &'static str) -> Self {
        Self {
            prompt,
            banner: None,
            negotiate_telnet: true,
            help_hint: true,
        }
    }

    pub const fn banner(mut self, banner: &'static str) -> Self {
        self.banner = Some(banner);
        self
    }

    pub const fn negotiate_telnet(mut self, enabled: bool) -> Self {
        self.negotiate_telnet = enabled;
        self
    }

    pub const fn help_hint(mut self, enabled: bool) -> Self {
        self.help_hint = enabled;
        self
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new("> ")
    }
}

pub struct Session<
    T,
    const LINE: usize = 256,
    const HISTORY: usize = 8,
    const FMT: usize = 256,
    const COMPLETIONS: usize = 16,
> {
    io: T,
    config: Config,
    editor: Editor<LINE, HISTORY>,
    telnet: Telnet<64, 32>,
}

impl<T, const LINE: usize, const HISTORY: usize, const FMT: usize, const COMPLETIONS: usize>
    Session<T, LINE, HISTORY, FMT, COMPLETIONS>
{
    pub const fn new(io: T, config: Config) -> Self {
        Self {
            io,
            config,
            editor: Editor::new(),
            telnet: Telnet::new(),
        }
    }

    pub fn into_inner(self) -> T {
        self.io
    }

    pub fn terminal_type(&self) -> Option<&str> {
        self.telnet.terminal_type()
    }

    pub const fn window_size(&self) -> Option<(u16, u16)> {
        self.telnet.window_size()
    }
}

impl<T, const LINE: usize, const HISTORY: usize, const FMT: usize, const COMPLETIONS: usize>
    Session<T, LINE, HISTORY, FMT, COMPLETIONS>
where
    T: Read + Write,
    T::Error: embedded_io::Error,
{
    /// Whether the session is responsible for echoing input.
    ///
    /// The server offers `WILL ECHO` at startup; a client that answers `DONT ECHO` echoes
    /// locally, and echoing here as well would double every character. While negotiation is
    /// still outstanding, or when the Telnet layer is disabled entirely, the session echoes so
    /// that typing works against clients that never reply.
    fn echo_enabled(&self) -> bool {
        !self.config.negotiate_telnet
            || self.telnet.us_enabled(OPT_ECHO)
            || self.telnet.us_pending(OPT_ECHO)
    }

    async fn raw_write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.io.write_all(bytes).await.map_err(Error::io)?;
        self.io.flush().await.map_err(Error::io)?;
        Ok(())
    }

    async fn print_prompt(&mut self) -> Result<(), Error> {
        let mut out = Console::new(&mut self.io);
        write_str(&mut out, self.config.prompt).await?;
        out.flush().await?;
        Ok(())
    }

    async fn redraw(&mut self) -> Result<(), Error> {
        let cursor = self.editor.cursor();
        let line = self.editor.line();
        let tail_columns = core::str::from_utf8(&line[cursor..])
            .map(|tail| tail.chars().count())
            .unwrap_or(line.len().saturating_sub(cursor));

        let mut out = Console::new(&mut self.io);
        out.write_all(b"\r\x1b[2K").await?;
        write_str(&mut out, self.config.prompt).await?;
        out.write_all(line).await?;
        if tail_columns > 0 {
            write_fmt::<FMT, _>(&mut out, format_args!("\x1b[{tail_columns}D")).await?;
        }
        out.flush().await?;
        Ok(())
    }

    async fn render_parse_error(
        io: &mut T,
        help_hint: bool,
        error: crate::ParseError,
    ) -> Result<(), Error> {
        let mut out = Console::new(io);
        write_line(&mut out, "").await?;
        match error.kind {
            ParseErrorKind::Empty => {}
            ParseErrorKind::UnknownCommand => {
                write_line(&mut out, "error: unrecognized command").await?
            }
            ParseErrorKind::UnknownOption => {
                write_line(&mut out, "error: unrecognized option").await?
            }
            ParseErrorKind::UnexpectedArgument => {
                write_line(&mut out, "error: unexpected argument").await?
            }
            ParseErrorKind::MissingArgument => {
                write_str(&mut out, "error: required argument was not provided").await?;
                if let Some(argument) = error.argument {
                    write_str(&mut out, ": ").await?;
                    write_str(&mut out, argument).await?;
                }
                write_line(&mut out, "").await?;
            }
            ParseErrorKind::MissingValue => {
                write_str(&mut out, "error: option requires a value").await?;
                if let Some(argument) = error.argument {
                    write_str(&mut out, ": ").await?;
                    write_str(&mut out, argument).await?;
                }
                write_line(&mut out, "").await?;
            }
            ParseErrorKind::InvalidValue => {
                write_str(&mut out, "error: invalid value").await?;
                if let Some(argument) = error.argument {
                    write_str(&mut out, " for ").await?;
                    write_str(&mut out, argument).await?;
                }
                if let Some(expected) = error.expected {
                    write_str(&mut out, "; expected ").await?;
                    write_str(&mut out, expected).await?;
                }
                write_line(&mut out, "").await?;
            }
            ParseErrorKind::TooManyValues => {
                write_str(&mut out, "error: too many values").await?;
                if let Some(argument) = error.argument {
                    write_str(&mut out, " for ").await?;
                    write_str(&mut out, argument).await?;
                }
                write_line(&mut out, "").await?;
            }
            ParseErrorKind::TooManyTokens => {
                write_line(&mut out, "error: too many command-line tokens").await?
            }
            ParseErrorKind::LineTooLong => {
                write_line(&mut out, "error: command line is too long").await?
            }
            ParseErrorKind::InvalidUtf8 => {
                write_line(&mut out, "error: command line is not valid UTF-8").await?
            }
            ParseErrorKind::UnterminatedQuote => {
                write_line(&mut out, "error: unterminated quoted string").await?
            }
            ParseErrorKind::TrailingEscape => {
                write_line(&mut out, "error: trailing escape character").await?
            }
        }
        if help_hint {
            write_line(&mut out, "For more information, try 'help'.").await?;
        }
        Ok(())
    }

    /// Report an error raised by a command handler without tearing down the session.
    async fn render_runtime_error(io: &mut T, error: Error) -> Result<(), Error> {
        let mut out = Console::new(io);
        write_line(
            &mut out,
            match error {
                Error::FormatOverflow => "error: output did not fit the format buffer",
                Error::NoHandler => "error: command has no handler",
                Error::LineTooLong => "error: command line is too long",
                Error::Disconnected => "error: disconnected",
                Error::Parse(_) => "error: invalid command",
                Error::Io(_) => "error: transport failure",
            },
        )
        .await
        .map_err(Error::from)
    }

    async fn handle_completion(&mut self, root: &'static RootSpec) -> Result<(), Error> {
        #[cfg(not(feature = "completion"))]
        let _ = root;

        #[cfg(feature = "completion")]
        {
            let mut candidates = Vec::<crate::Candidate, COMPLETIONS>::new();
            complete(
                root,
                self.editor.line(),
                self.editor.cursor(),
                &mut candidates,
            );
            match candidates.len() {
                0 => {}
                1 => {
                    let candidate = candidates[0];
                    let _ = self.editor.replace_range(
                        candidate.replace_at,
                        candidate.prefix,
                        candidate.value,
                        candidate.quote,
                        true,
                    );
                    self.redraw().await?;
                }
                _ => {
                    // Insert the longest shared prefix first, the way readline does, so that
                    // repeated Tab presses make progress instead of reprinting the same list.
                    let first = candidates[0];
                    let uniform = candidates.iter().all(|candidate| {
                        candidate.replace_at == first.replace_at
                            && candidate.prefix == first.prefix
                            && !candidate.quote
                    });
                    if uniform {
                        let common = candidates.iter().fold(first.value.len(), |common, other| {
                            common.min(common_prefix_len(first.value, other.value))
                        });
                        if common > 0 {
                            let _ = self.editor.replace_range(
                                first.replace_at,
                                first.prefix,
                                &first.value[..common],
                                false,
                                false,
                            );
                        }
                    }
                    {
                        let mut out = Console::new(&mut self.io);
                        write_line(&mut out, "").await?;
                        for candidate in candidates {
                            write_str(&mut out, candidate.prefix).await?;
                            write_str(&mut out, candidate.value).await?;
                            write_str(&mut out, "  ").await?;
                        }
                        write_line(&mut out, "").await?;
                    }
                    self.redraw().await?;
                }
            }
        }
        Ok(())
    }

    async fn handle_builtin(
        &mut self,
        root: &'static RootSpec,
        line: &mut [u8],
    ) -> Result<bool, Error> {
        let Ok(text) = core::str::from_utf8(line) else {
            return Ok(false);
        };
        let trimmed = text.trim();

        let leading = trimmed.split_ascii_whitespace().next().unwrap_or("");
        let trailing = trimmed.split_ascii_whitespace().last().unwrap_or("");
        if matches!(leading, "--version" | "-V") || matches!(trailing, "--version" | "-V") {
            if let Some(version) = root.version {
                let mut out = Console::new(&mut self.io);
                write_str(&mut out, root.name).await?;
                write_str(&mut out, " ").await?;
                write_line(&mut out, version).await?;
                return Ok(true);
            }
        }

        #[cfg(feature = "help")]
        {
            use crate::lexer::{MAX_TOKENS, lex};

            let len = line.len();
            let lexed = match lex(line, len) {
                Ok(lexed) => lexed,
                Err(_) => return Ok(false),
            };
            if lexed.is_empty() {
                return Ok(false);
            }

            let mut path: Vec<&str, MAX_TOKENS> = Vec::new();
            let first = lexed.arg(0).unwrap_or("");
            let last = lexed.arg(lexed.len() - 1).unwrap_or("");
            let explicit_help = first == "help";
            let trailing_help = matches!(last, "--help" | "-h");

            if explicit_help {
                for index in 1..lexed.len() {
                    if path.push(lexed.arg(index).unwrap_or("")).is_err() {
                        return Ok(false);
                    }
                }
            } else if trailing_help {
                fn visit_args(
                    args: &'static [crate::ArgSpec],
                    f: &mut impl FnMut(&'static crate::ArgSpec),
                ) {
                    for arg in args {
                        if arg.kind == crate::ArgKind::Flatten {
                            visit_args(arg.children, f);
                        } else {
                            f(arg);
                        }
                    }
                }

                fn option_consumes_next(
                    args: &'static [crate::ArgSpec],
                    token: &str,
                    globals_only: bool,
                ) -> Option<bool> {
                    let mut answer = None;
                    visit_args(args, &mut |arg| {
                        if answer.is_some() || (globals_only && !arg.global) {
                            return;
                        }
                        if !matches!(arg.kind, crate::ArgKind::Option | crate::ArgKind::Flag) {
                            return;
                        }
                        if let Some(rest) = token.strip_prefix("--") {
                            let (name, attached) = rest
                                .split_once('=')
                                .map_or((rest, false), |(name, _)| (name, true));
                            let long_match = arg.long == Some(name)
                                || arg.aliases.iter().copied().any(|alias| alias == name)
                                || arg
                                    .visible_aliases
                                    .iter()
                                    .copied()
                                    .any(|alias| alias == name);
                            if long_match {
                                answer = Some(arg.kind == crate::ArgKind::Option && !attached);
                                return;
                            }
                        }
                        if let Some(short) = arg.short {
                            let mut chars = token.chars();
                            if chars.next() == Some('-') && chars.next() == Some(short) {
                                let rest = chars.as_str();
                                if rest.is_empty() {
                                    answer = Some(arg.kind == crate::ArgKind::Option);
                                } else if arg.kind == crate::ArgKind::Option
                                    && !token.starts_with("--")
                                {
                                    answer = Some(false);
                                }
                            }
                        }
                    });
                    answer
                }

                let mut commands = root.commands;
                let mut args = root.args;
                let mut skip_value = false;
                for index in 0..lexed.len() - 1 {
                    let word = lexed.arg(index).unwrap_or("");
                    if skip_value {
                        skip_value = false;
                        continue;
                    }
                    if word.starts_with('-') {
                        if let Some(consumes) = option_consumes_next(args, word, false)
                            .or_else(|| option_consumes_next(root.args, word, true))
                        {
                            skip_value = consumes;
                        }
                        continue;
                    }
                    if let Some(command) = crate::schema::find_command(commands, word) {
                        if path.push(command.name).is_err() {
                            return Ok(false);
                        }
                        commands = command.subcommands;
                        args = command.args;
                    }
                }
            } else if !matches!(first, "--help" | "-h") {
                return Ok(false);
            }

            let mut out = Console::new(&mut self.io);
            write_line(&mut out, "").await?;
            write_help(&mut out, root, path.as_slice()).await?;
            Ok(true)
        }

        #[cfg(not(feature = "help"))]
        {
            Ok(false)
        }
    }

    async fn submit<P, C>(&mut self, context: &mut C) -> Result<(), Error>
    where
        P: ParserFamily,
        for<'a> P::Parsed<'a>: Dispatch<C>,
    {
        {
            let mut out = Console::new(&mut self.io);
            write_line(&mut out, "").await?;
        }

        let len = self.editor.len();
        if len == 0 {
            self.print_prompt().await?;
            return Ok(());
        }

        // Built-ins inspect the original, un-compacted line before lexing.
        let mut builtin_copy = heapless::Vec::<u8, LINE>::new();
        let _ = builtin_copy.extend_from_slice(self.editor.line());
        if self
            .handle_builtin(&P::ROOT, builtin_copy.as_mut_slice())
            .await?
        {
            self.editor.remember();
            self.editor.clear();
            self.print_prompt().await?;
            return Ok(());
        }

        self.editor.remember();

        // A parsed command may borrow directly from the editor's line buffer. Keep
        // that borrow alive for dispatch, while borrowing the transport separately,
        // and make sure both borrows end before we clear/redraw the editor.
        let help_hint = self.config.help_hint;
        let mut runtime_error = None;
        {
            let editor = &mut self.editor;
            let io = &mut self.io;
            let line = editor.line_mut();

            match P::parse(line, len) {
                Ok(command) => {
                    let mut out = Console::new(io);
                    if let Err(error) = command.dispatch(context, &mut out).await {
                        match error {
                            // The transport is gone, so there is nothing left to report to.
                            Error::Io(error) => return Err(Error::Io(error)),
                            // A handler may explicitly end the interactive session.
                            Error::Disconnected => return Err(Error::Disconnected),
                            // Other handler failures are recoverable: report them and keep the
                            // prompt alive.
                            other => runtime_error = Some(other),
                        }
                    }
                }
                Err(error) => {
                    Self::render_parse_error(io, help_hint, error).await?;
                }
            }
        }
        if let Some(error) = runtime_error {
            Self::render_runtime_error(&mut self.io, error).await?;
        }

        self.editor.clear();
        self.print_prompt().await?;
        Ok(())
    }

    pub async fn serve<P, C>(&mut self, context: &mut C) -> Result<(), Error>
    where
        P: ParserFamily,
        for<'a> P::Parsed<'a>: Dispatch<C>,
    {
        if self.config.negotiate_telnet {
            let mut negotiation = Vec::<u8, 32>::new();
            self.telnet.initial_negotiation(&mut negotiation);
            self.raw_write(negotiation.as_slice()).await?;
        }

        if let Some(banner) = self.config.banner {
            let mut out = Console::new(&mut self.io);
            write_line(&mut out, banner).await?;
        }
        self.print_prompt().await?;

        let mut rx = [0u8; 64];
        loop {
            let count = self.io.read(&mut rx).await.map_err(Error::io)?;
            if count == 0 {
                return Err(Error::Disconnected);
            }

            for byte in rx[..count].iter().copied() {
                let mut reply = Vec::<u8, 32>::new();
                let event = self.telnet.feed(byte, &mut reply);
                if !reply.is_empty() {
                    self.raw_write(reply.as_slice()).await?;
                }

                let Some(event) = event else {
                    continue;
                };

                let editor_event = match event {
                    TelnetEvent::Data(byte) => self.editor.feed(byte),
                    TelnetEvent::Interrupt | TelnetEvent::Break => EditorEvent::Interrupt,
                    TelnetEvent::EraseCharacter => self.editor.feed(0x7f),
                    TelnetEvent::EraseLine => {
                        self.editor.clear();
                        EditorEvent::Redraw
                    }
                    TelnetEvent::AreYouThere => {
                        {
                            let mut out = Console::new(&mut self.io);
                            write_line(&mut out, "\r\n[yes]").await?;
                        }
                        EditorEvent::Redraw
                    }
                    TelnetEvent::WindowSizeChanged | TelnetEvent::TerminalTypeChanged => {
                        EditorEvent::None
                    }
                };

                let echo = self.echo_enabled();
                match editor_event {
                    EditorEvent::None => {}
                    EditorEvent::Echo(byte) => {
                        if echo {
                            let mut out = Console::new(&mut self.io);
                            out.write_all(&[byte]).await?;
                            out.flush().await?;
                        }
                    }
                    EditorEvent::Backspace => {
                        if echo {
                            let mut out = Console::new(&mut self.io);
                            out.write_all(b"\x08 \x08").await?;
                            out.flush().await?;
                        }
                    }
                    EditorEvent::Redraw => {
                        if echo {
                            self.redraw().await?;
                        }
                    }
                    EditorEvent::Submit => self.submit::<P, C>(context).await?,
                    EditorEvent::Complete => self.handle_completion(&P::ROOT).await?,
                    EditorEvent::Interrupt => {
                        self.editor.clear();
                        {
                            let mut out = Console::new(&mut self.io);
                            write_line(&mut out, "^C").await?;
                        }
                        self.print_prompt().await?;
                    }
                    EditorEvent::ClearScreen => {
                        {
                            let mut out = Console::new(&mut self.io);
                            out.write_all(b"\x1b[2J\x1b[H").await?;
                        }
                        self.redraw().await?;
                    }
                }
            }
        }
    }
}
