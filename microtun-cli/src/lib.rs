#![no_std]
#![forbid(unsafe_code)]
#![allow(async_fn_in_trait)]

#[cfg(feature = "alloc")]
extern crate alloc;

extern crate self as microtun_cli;

#[cfg(feature = "completion")]
pub mod completion;
pub mod editor;
pub mod error;
#[cfg(feature = "help")]
pub mod help;
pub mod io;
pub mod lexer;
pub mod parse;
pub mod schema;
pub mod session;
mod table;
pub mod telnet;

#[cfg(feature = "completion")]
pub use completion::{Candidate, CandidateKind};
pub use error::{Error, ErrorKind, ParseError, ParseErrorKind, ValueError};
pub use io::{Console, write_fmt};
#[cfg(feature = "derive")]
pub use microtun_cli_macros::{Args, Dispatch, Parser, Subcommand, ValueEnum};
pub use parse::{
    ArgCursor, Args, Dispatch, FromArg, ParserFamily, Subcommand, TERMINATOR, ValueEnum,
};
pub use schema::{
    ArgAction, ArgKind, ArgSpec, CommandIter, CommandSpec, MAX_COMMAND_FLATTEN_DEPTH, RootSpec,
    ValueSpec, find_command,
};
pub use session::{Config, Session};
pub use table::Table;
