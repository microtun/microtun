use core::str::FromStr;

use heapless::{String, Vec};

use crate::{
    ArgKind, ArgSpec, Error, ParseError, ParseErrorKind, RootSpec, ValueError, ValueSpec,
    lexer::{Lexed, MAX_TOKENS, lex},
};

// `consumed` is a bitmask indexed by token position.
const _: () = assert!(
    MAX_TOKENS <= 64,
    "ArgCursor::consumed is a u64 bitmask indexed by token position"
);

/// The end-of-options marker. Every token after it is treated as a positional value.
pub const TERMINATOR: &str = "--";

fn short_mask(ch: char) -> Option<u128> {
    let code = ch as u32;
    (code < 128).then_some(1u128 << code)
}

/// Whether `token` is a negative number rather than an option (`-5`, `-.5`, `-1.2e3`).
fn is_negative_number(token: &str) -> bool {
    let Some(rest) = token.strip_prefix('-') else {
        return false;
    };
    let mut chars = rest.chars();
    match chars.next() {
        Some(ch) if ch.is_ascii_digit() => true,
        Some('.') => chars.next().is_some_and(|ch| ch.is_ascii_digit()),
        _ => false,
    }
}

/// Whether `token` should be rejected where a positional value is expected.
///
/// A bare `-` (conventionally stdin) and negative numbers are values, not options.
fn is_option_like(token: &str) -> bool {
    token.starts_with('-') && token != "-" && !is_negative_number(token)
}

/// The body of a short-option cluster (`-abc` -> `abc`), if `token` is one.
fn short_cluster(token: &str) -> Option<&str> {
    if !token.starts_with('-') || token.starts_with("--") || token == "-" {
        return None;
    }
    if is_negative_number(token) {
        return None;
    }
    Some(&token[1..])
}

#[derive(Clone, Copy, Debug)]
struct ShortUse {
    index: u8,
    /// Bitmask of ASCII short letters claimed within this cluster.
    used: u128,
    /// Whether the trailing value of this cluster has been claimed by an option.
    value_taken: bool,
}

pub struct ArgCursor<'c, 'a> {
    line: &'c Lexed<'a>,
    consumed: u64,
    short_use: Vec<ShortUse, MAX_TOKENS>,
    /// Bitmask of ASCII short letters that are known to take a value.
    value_shorts: u128,
    /// Position of the `--` end-of-options marker, if the line contains one.
    terminator: Option<usize>,
}

impl<'c, 'a> ArgCursor<'c, 'a> {
    pub fn new(line: &'c Lexed<'a>) -> Self {
        let mut terminator = None;
        for index in 0..line.len() {
            if line.arg(index).is_ok_and(|token| token == TERMINATOR) {
                terminator = Some(index);
                break;
            }
        }

        let mut cursor = Self {
            line,
            consumed: 0,
            short_use: Vec::new(),
            value_shorts: 0,
            terminator,
        };
        if let Some(index) = terminator {
            // The marker itself is not an argument.
            cursor.consume(index);
        }
        cursor
    }

    /// Register which short letters take a value, so that clustered shorts can be split correctly.
    ///
    /// Without this, `-ofoo` (an attached value for `-o`) is indistinguishable from a cluster of
    /// flags, and an unrelated `-f` flag would match the `f` inside the value. Derived
    /// implementations call this with their own `ARGS` before parsing any field; hand-written
    /// [`Args`] implementations should do the same.
    pub fn declare_value_shorts(&mut self, args: &'static [ArgSpec]) {
        fn walk(args: &'static [ArgSpec], mask: &mut u128) {
            for arg in args {
                match arg.kind {
                    ArgKind::Flatten => walk(arg.children, mask),
                    ArgKind::Option => {
                        if let Some(bit) = arg.short.and_then(short_mask) {
                            *mask |= bit;
                        }
                    }
                    _ => {}
                }
            }
        }
        walk(args, &mut self.value_shorts);
    }

    /// Register the value-taking shorts of whichever command in `commands` answers to `name`.
    ///
    /// See [`ArgCursor::declare_value_shorts`].
    pub fn declare_command_shorts(&mut self, commands: &'static [crate::CommandSpec], name: &str) {
        if let Some(command) = crate::schema::find_command(commands, name) {
            self.declare_value_shorts(command.args);
        }
    }

    pub fn is_empty(&self) -> bool {
        (0..self.line.len()).all(|index| self.is_consumed(index))
    }

    /// One past the last token that may be interpreted as an option.
    fn options_end(&self) -> usize {
        self.terminator.unwrap_or(self.line.len())
    }

    fn is_consumed(&self, index: usize) -> bool {
        self.consumed & (1u64 << index) != 0
    }

    fn consume(&mut self, index: usize) {
        self.consumed |= 1u64 << index;
    }

    fn is_value_short(&self, ch: char) -> bool {
        short_mask(ch).is_some_and(|mask| self.value_shorts & mask != 0)
    }

    fn slot_mut(&mut self, index: usize) -> Option<&mut ShortUse> {
        if let Some(position) = self
            .short_use
            .iter()
            .position(|entry| entry.index as usize == index)
        {
            return Some(&mut self.short_use[position]);
        }
        self.short_use
            .push(ShortUse {
                index: index as u8,
                used: 0,
                value_taken: false,
            })
            .ok()?;
        self.short_use.last_mut()
    }

    fn record_short_use(&mut self, index: usize, ch: char) {
        let Some(mask) = short_mask(ch) else {
            return;
        };
        if let Some(entry) = self.slot_mut(index) {
            entry.used |= mask;
        }
    }

    fn record_value_taken(&mut self, index: usize) {
        if let Some(entry) = self.slot_mut(index) {
            entry.value_taken = true;
        }
    }

    fn short_used(&self, index: usize, ch: char) -> bool {
        let Some(mask) = short_mask(ch) else {
            return false;
        };
        self.short_use
            .iter()
            .find(|entry| entry.index as usize == index)
            .is_some_and(|entry| entry.used & mask != 0)
    }

    fn value_taken(&self, index: usize) -> bool {
        self.short_use
            .iter()
            .find(|entry| entry.index as usize == index)
            .is_some_and(|entry| entry.value_taken)
    }

    /// Find `short` within a cluster body, returning the text that follows it.
    ///
    /// Scanning stops at the first letter that is itself a value-taking short, because everything
    /// after such a letter is that option's value rather than more flags.
    fn locate_short<'t>(&self, body: &'t str, short: char) -> Option<&'t str> {
        let mut rest = body;
        while let Some(ch) = rest.chars().next() {
            let after = &rest[ch.len_utf8()..];
            if ch == short {
                return Some(after);
            }
            if self.is_value_short(ch) {
                return None;
            }
            rest = after;
        }
        None
    }

    /// How many times `short` repeats in the flag portion of a cluster (`-vvv` -> 3).
    fn count_short(&self, body: &str, short: char) -> usize {
        let mut rest = body;
        let mut hits = 0usize;
        while let Some(ch) = rest.chars().next() {
            let after = &rest[ch.len_utf8()..];
            if ch == short {
                hits += 1;
            } else if self.is_value_short(ch) {
                break;
            }
            rest = after;
        }
        hits
    }

    /// Whether every letter of a short cluster (and its trailing value, if any) has been claimed.
    fn cluster_settled(&self, index: usize, token: &str) -> bool {
        let Some(body) = short_cluster(token) else {
            return false;
        };
        if body.is_empty() {
            return false;
        }
        let mut rest = body;
        while let Some(ch) = rest.chars().next() {
            if !self.short_used(index, ch) {
                return false;
            }
            if self.is_value_short(ch) {
                // Everything after `ch` is its value; the option must have claimed it.
                return self.value_taken(index);
            }
            rest = &rest[ch.len_utf8()..];
        }
        true
    }

    fn long_matches(token: &str, long: &str) -> bool {
        token.strip_prefix("--").is_some_and(|rest| rest == long)
    }

    pub fn take_flag(&mut self, long: Option<&str>, short: Option<char>) -> bool {
        for index in 0..self.options_end() {
            if self.is_consumed(index) {
                continue;
            }
            let Ok(token) = self.line.arg(index) else {
                continue;
            };

            if let Some(long) = long {
                if Self::long_matches(token, long) {
                    self.consume(index);
                    return true;
                }
            }

            if let Some(short) = short {
                if let Some(body) = short_cluster(token) {
                    if self.locate_short(body, short).is_some() && !self.short_used(index, short) {
                        self.record_short_use(index, short);
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn take_flag_aliases(
        &mut self,
        long: Option<&str>,
        short: Option<char>,
        aliases: &[&str],
    ) -> bool {
        if self.take_flag(long, short) {
            return true;
        }
        aliases
            .iter()
            .copied()
            .any(|alias| self.take_flag(Some(alias), None))
    }

    pub fn take_flag_aliases_with_visible(
        &mut self,
        long: Option<&str>,
        short: Option<char>,
        aliases: &[&str],
        visible_aliases: &[&str],
    ) -> bool {
        if self.take_flag_aliases(long, short, aliases) {
            return true;
        }
        visible_aliases
            .iter()
            .copied()
            .any(|alias| self.take_flag(Some(alias), None))
    }

    pub fn take_flag_count(&mut self, long: Option<&str>, short: Option<char>) -> u8 {
        let mut count = 0u8;
        for index in 0..self.options_end() {
            if self.is_consumed(index) {
                continue;
            }
            let Ok(token) = self.line.arg(index) else {
                continue;
            };

            if let Some(long) = long {
                if Self::long_matches(token, long) {
                    self.consume(index);
                    count = count.saturating_add(1);
                    continue;
                }
            }

            if let Some(short) = short {
                if let Some(body) = short_cluster(token) {
                    let hits = self.count_short(body, short);
                    if hits > 0 && !self.short_used(index, short) {
                        self.record_short_use(index, short);
                        count = count.saturating_add(hits.min(u8::MAX as usize) as u8);
                    }
                }
            }
        }
        count
    }

    pub fn take_flag_count_aliases(
        &mut self,
        long: Option<&str>,
        short: Option<char>,
        aliases: &[&str],
    ) -> u8 {
        let mut count = self.take_flag_count(long, short);
        for alias in aliases {
            count = count.saturating_add(self.take_flag_count(Some(alias), None));
        }
        count
    }

    pub fn take_flag_count_aliases_with_visible(
        &mut self,
        long: Option<&str>,
        short: Option<char>,
        aliases: &[&str],
        visible_aliases: &[&str],
    ) -> u8 {
        let mut count = self.take_flag_count_aliases(long, short, aliases);
        for alias in visible_aliases {
            count = count.saturating_add(self.take_flag_count(Some(alias), None));
        }
        count
    }

    /// Claim the token after `index` as a detached option value.
    fn take_detached_value(
        &mut self,
        index: usize,
        argument: &'static str,
        allow_hyphen: bool,
    ) -> Result<&'a str, ParseError> {
        let value_index = index + 1;
        if value_index >= self.line.len() || self.is_consumed(value_index) {
            return Err(ParseError::for_argument(
                ParseErrorKind::MissingValue,
                argument,
            ));
        }
        let token = self.line.arg(value_index)?;
        if !allow_hyphen && is_option_like(token) {
            // `--name --verbose` almost always means a forgotten value, not a value of "--verbose".
            return Err(ParseError::for_argument(
                ParseErrorKind::MissingValue,
                argument,
            ));
        }
        self.consume(value_index);
        Ok(token)
    }

    fn take_option_named(
        &mut self,
        long: Option<&str>,
        short: Option<char>,
        argument: &'static str,
        allow_hyphen: bool,
    ) -> Result<Option<&'a str>, ParseError> {
        for index in 0..self.options_end() {
            if self.is_consumed(index) {
                continue;
            }
            let token = self.line.arg(index)?;

            if let Some(long) = long {
                if let Some(rest) = token.strip_prefix("--") {
                    if rest == long {
                        self.consume(index);
                        return self
                            .take_detached_value(index, argument, allow_hyphen)
                            .map(Some);
                    }
                    if let Some(value) = rest.strip_prefix(long).and_then(|r| r.strip_prefix('=')) {
                        self.consume(index);
                        return Ok(Some(value));
                    }
                }
            }

            if let Some(short) = short {
                if self.short_used(index, short) {
                    continue;
                }
                let Some(body) = short_cluster(token) else {
                    continue;
                };
                let Some(after) = self.locate_short(body, short) else {
                    continue;
                };

                self.record_short_use(index, short);
                self.record_value_taken(index);

                if let Some(value) = after.strip_prefix('=') {
                    return Ok(Some(value));
                }
                if !after.is_empty() {
                    return Ok(Some(after));
                }
                return self
                    .take_detached_value(index, argument, allow_hyphen)
                    .map(Some);
            }
        }
        Ok(None)
    }

    pub fn take_option(
        &mut self,
        long: Option<&str>,
        short: Option<char>,
    ) -> Result<Option<&'a str>, ParseError> {
        self.take_option_named(long, short, "option", false)
    }

    pub fn take_option_aliases(
        &mut self,
        long: Option<&str>,
        short: Option<char>,
        aliases: &[&str],
    ) -> Result<Option<&'a str>, ParseError> {
        if let Some(value) = self.take_option(long, short)? {
            return Ok(Some(value));
        }
        for alias in aliases {
            if let Some(value) = self.take_option(Some(alias), None)? {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    pub fn take_option_aliases_with_visible(
        &mut self,
        long: Option<&str>,
        short: Option<char>,
        aliases: &[&str],
        visible_aliases: &[&str],
        argument: &'static str,
        allow_hyphen: bool,
    ) -> Result<Option<&'a str>, ParseError> {
        if let Some(value) = self.take_option_named(long, short, argument, allow_hyphen)? {
            return Ok(Some(value));
        }
        for alias in aliases.iter().chain(visible_aliases.iter()) {
            if let Some(value) =
                self.take_option_named(Some(alias), None, argument, allow_hyphen)?
            {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    pub fn take_positional(&mut self) -> Result<Option<&'a str>, ParseError> {
        for index in 0..self.line.len() {
            if self.is_consumed(index) {
                continue;
            }
            let token = self.line.arg(index)?;
            if !self.after_terminator(index) {
                if self.cluster_settled(index, token) {
                    self.consume(index);
                    continue;
                }
                if is_option_like(token) {
                    return Err(ParseError::new(ParseErrorKind::UnknownOption));
                }
            }
            self.consume(index);
            return Ok(Some(token));
        }
        Ok(None)
    }

    fn after_terminator(&self, index: usize) -> bool {
        self.terminator.is_some_and(|position| index > position)
    }

    pub fn finish(&mut self) -> Result<(), ParseError> {
        for index in 0..self.line.len() {
            if self.is_consumed(index) {
                continue;
            }
            let token = self.line.arg(index)?;
            if !self.after_terminator(index) {
                if self.cluster_settled(index, token) {
                    self.consume(index);
                    continue;
                }
                if is_option_like(token) {
                    return Err(ParseError::new(ParseErrorKind::UnknownOption));
                }
            }
            return Err(ParseError::new(ParseErrorKind::UnexpectedArgument));
        }
        Ok(())
    }
}

/// Internal abstraction used by the derive macros for repeated arguments.
///
/// This keeps fixed-capacity `heapless::Vec<T, N>` support allocation-free while allowing
/// `alloc::vec::Vec<T>` when the crate's `alloc` feature is enabled.
#[doc(hidden)]
pub trait RepeatedArg<T>: Sized {
    fn new() -> Self;
    fn push_value(&mut self, value: T) -> bool;
}

impl<T, const N: usize> RepeatedArg<T> for Vec<T, N> {
    fn new() -> Self {
        Vec::new()
    }

    fn push_value(&mut self, value: T) -> bool {
        self.push(value).is_ok()
    }
}

#[cfg(feature = "alloc")]
impl<T> RepeatedArg<T> for alloc::vec::Vec<T> {
    fn new() -> Self {
        alloc::vec::Vec::new()
    }

    fn push_value(&mut self, value: T) -> bool {
        self.push(value);
        true
    }
}

pub trait FromArg<'a>: Sized {
    fn from_arg(value: &'a str) -> Result<Self, ValueError>;
}

impl<'a> FromArg<'a> for &'a str {
    fn from_arg(value: &'a str) -> Result<Self, ValueError> {
        Ok(value)
    }
}

impl<const N: usize> FromArg<'_> for String<N> {
    fn from_arg(value: &str) -> Result<Self, ValueError> {
        let mut out = String::new();
        out.push_str(value)
            .map_err(|_| ValueError::new("string within configured capacity"))?;
        Ok(out)
    }
}

#[cfg(feature = "alloc")]
impl FromArg<'_> for alloc::string::String {
    fn from_arg(value: &str) -> Result<Self, ValueError> {
        Ok(alloc::string::String::from(value))
    }
}

macro_rules! from_str_arg {
    ($($ty:ty => $expected:literal),* $(,)?) => {$ (
        impl FromArg<'_> for $ty {
            fn from_arg(value: &str) -> Result<Self, ValueError> {
                <$ty>::from_str(value).map_err(|_| ValueError::new($expected))
            }
        }
    )* };
}

from_str_arg! {
    bool => "boolean",
    char => "character",
    u8 => "u8",
    u16 => "u16",
    u32 => "u32",
    u64 => "u64",
    u128 => "u128",
    usize => "usize",
    i8 => "i8",
    i16 => "i16",
    i32 => "i32",
    i64 => "i64",
    i128 => "i128",
    isize => "isize",
    f32 => "f32",
    f64 => "f64",
    core::net::IpAddr => "IP address",
    core::net::Ipv4Addr => "IPv4 address",
    core::net::Ipv6Addr => "IPv6 address",
}

pub trait ValueEnum: Sized {
    const VALUES: &'static [ValueSpec];
}

pub trait Args<'a>: Sized {
    const ARGS: &'static [crate::ArgSpec];
    fn parse_args(cursor: &mut ArgCursor<'_, 'a>) -> Result<Self, ParseError>;
}

pub trait Subcommand<'a>: Sized {
    const COMMANDS: &'static [crate::CommandSpec];

    /// Parse the remainder of a subcommand whose leading name token is already consumed.
    ///
    /// Returns `Ok(None)` when `command` names none of this enum's variants, which is what
    /// lets a `#[command(flatten)]` group be tried and fall through to the next candidate
    /// rather than committing the whole parse to an `UnknownCommand` error.
    fn parse_named(
        cursor: &mut ArgCursor<'_, 'a>,
        command: &'a str,
    ) -> Result<Option<Self>, ParseError>;

    fn parse_subcommand(cursor: &mut ArgCursor<'_, 'a>) -> Result<Self, ParseError> {
        let command = cursor
            .take_positional()?
            .ok_or_else(|| ParseError::new(ParseErrorKind::MissingArgument))?;
        cursor.declare_command_shorts(Self::COMMANDS, command);
        Self::parse_named(cursor, command)?
            .ok_or_else(|| ParseError::new(ParseErrorKind::UnknownCommand))
    }
}

pub trait ParserFamily {
    type Parsed<'a>;
    const ROOT: RootSpec;

    fn parse<'a>(line: &'a mut [u8], len: usize) -> Result<Self::Parsed<'a>, ParseError>;
}

pub trait Dispatch<C> {
    async fn dispatch<W: embedded_io_async::Write<Error = crate::ErrorKind> + ?Sized>(
        self,
        context: &mut C,
        out: &mut W,
    ) -> Result<(), Error>;
}

pub fn parse_with<'a, T: Args<'a>>(line: &'a mut [u8], len: usize) -> Result<T, ParseError> {
    let lexed = lex(line, len)?;
    if lexed.is_empty() {
        return Err(ParseError::new(ParseErrorKind::Empty));
    }
    let mut cursor = ArgCursor::new(&lexed);
    cursor.declare_value_shorts(T::ARGS);
    let parsed = T::parse_args(&mut cursor)?;
    cursor.finish()?;
    Ok(parsed)
}
