pub use embedded_io::ErrorKind;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ParseErrorKind {
    Empty,
    TooManyTokens,
    LineTooLong,
    InvalidUtf8,
    UnterminatedQuote,
    TrailingEscape,
    UnknownCommand,
    UnknownOption,
    UnexpectedArgument,
    MissingArgument,
    MissingValue,
    InvalidValue,
    TooManyValues,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ParseError {
    pub kind: ParseErrorKind,
    pub argument: Option<&'static str>,
    pub expected: Option<&'static str>,
}

impl ParseError {
    pub const fn new(kind: ParseErrorKind) -> Self {
        Self {
            kind,
            argument: None,
            expected: None,
        }
    }

    pub const fn for_argument(kind: ParseErrorKind, argument: &'static str) -> Self {
        Self {
            kind,
            argument: Some(argument),
            expected: None,
        }
    }

    pub const fn invalid_value(argument: &'static str, expected: &'static str) -> Self {
        Self {
            kind: ParseErrorKind::InvalidValue,
            argument: Some(argument),
            expected: Some(expected),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ValueError {
    pub expected: &'static str,
}

impl ValueError {
    pub const fn new(expected: &'static str) -> Self {
        Self { expected }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    Io(ErrorKind),
    Parse(ParseError),
    LineTooLong,
    FormatOverflow,
    Disconnected,
    NoHandler,
}

impl Error {
    pub fn io<E: embedded_io::Error>(error: E) -> Self {
        Self::Io(error.kind())
    }
}

impl From<ErrorKind> for Error {
    fn from(value: ErrorKind) -> Self {
        Self::Io(value)
    }
}

impl From<ParseError> for Error {
    fn from(value: ParseError) -> Self {
        Self::Parse(value)
    }
}
