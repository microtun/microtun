use core::fmt;

/// A category of parse or deserialization failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// A section header is malformed.
    #[error("invalid section header")]
    InvalidSection,
    /// A section header has no name.
    #[error("empty section name")]
    EmptySectionName,
    /// An explicit section used the reserved [`crate::ROOT_SECTION`] name.
    #[error("reserved section name")]
    ReservedSectionName,
    /// A property has neither `=` nor `:` as a delimiter.
    #[error("missing property delimiter")]
    MissingDelimiter,
    /// A property name is empty.
    #[error("empty property name")]
    EmptyKey,
    /// More than one matching section was deserialized into a scalar struct.
    #[error("repeated section requires a sequence")]
    DuplicateSection,
    /// More than one matching property was deserialized into a scalar value.
    #[error("repeated property requires a sequence")]
    DuplicateKey,
    /// A boolean value was not recognized.
    #[error("invalid boolean")]
    InvalidBoolean,
    /// A signed integer could not be parsed.
    #[error("invalid signed integer")]
    InvalidInteger,
    /// An unsigned integer could not be parsed.
    #[error("invalid unsigned integer")]
    InvalidUnsignedInteger,
    /// A floating-point value could not be parsed.
    #[error("invalid floating-point number")]
    InvalidFloat,
    /// A value did not contain exactly one character.
    #[error("expected exactly one character")]
    InvalidChar,
    /// Serde requested a shape that INI cannot represent here.
    #[error("unsupported INI data shape")]
    UnsupportedType,
    /// A Serde visitor rejected a value.
    #[error("value rejected by Serde")]
    Serde,
}

/// An error with an optional one-based source location.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    kind: ErrorKind,
    line: usize,
    column: usize,
}

impl Error {
    pub(crate) const fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            line: 0,
            column: 0,
        }
    }

    pub(crate) const fn at(kind: ErrorKind, line: usize, column: usize) -> Self {
        Self { kind, line, column }
    }

    pub(crate) fn locate(mut self, line: usize, column: usize) -> Self {
        if self.line == 0 {
            self.line = line;
            self.column = column;
        }
        self
    }

    /// Returns the error category.
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns the one-based line number, if the failure has a source location.
    pub const fn line(&self) -> Option<usize> {
        if self.line == 0 {
            None
        } else {
            Some(self.line)
        }
    }

    /// Returns the one-based UTF-8 byte column, if the failure has a source location.
    pub const fn column(&self) -> Option<usize> {
        if self.column == 0 {
            None
        } else {
            Some(self.column)
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.line(), self.column()) {
            (Some(line), Some(column)) => {
                write!(formatter, "{} at line {line}, column {column}", self.kind)
            }
            _ => self.kind.fmt(formatter),
        }
    }
}

impl core::error::Error for Error {}

impl serde::de::Error for Error {
    fn custom<T>(_message: T) -> Self
    where
        T: fmt::Display,
    {
        Self::new(ErrorKind::Serde)
    }
}
