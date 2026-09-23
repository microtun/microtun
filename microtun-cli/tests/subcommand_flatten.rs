//! `#[command(flatten)]` on enum variants: splicing a shared command set into a container.
//!
//! This is the mechanism that lets several boards share one dispatch implementation while
//! each still contributes its own hardware-specific commands.

use microtun_cli::{
    CommandIter, CommandSpec, Parser, ParserFamily, RootSpec, Subcommand, find_command,
};

/// A command set shared by every container below.
#[derive(Debug, Eq, PartialEq, Subcommand)]
enum Common {
    /// Show system information.
    Sys,
    /// Ping an address.
    Ping { host: u32, count: u8 },
    /// Close this session.
    #[command(alias = "exit")]
    Quit,
}

/// A second shared group, to prove more than one flattened variant can coexist.
#[derive(Debug, Eq, PartialEq, Subcommand)]
enum Diagnostics {
    /// Dump counters.
    Counters,
}

#[derive(Debug, Eq, PartialEq, Parser)]
#[command(name = "board", about = "board console")]
enum Command {
    #[command(flatten)]
    Common(Common),

    #[command(flatten)]
    Diagnostics(Diagnostics),

    /// Inspect or control hardware I/O.
    Io { channel: u8 },
}

fn parse(buffer: &mut [u8], text: &str) -> Command {
    buffer[..text.len()].copy_from_slice(text.as_bytes());
    <CommandParser as ParserFamily>::parse(buffer, text.len()).unwrap()
}

fn root() -> &'static RootSpec {
    &<CommandParser as ParserFamily>::ROOT
}

#[test]
fn parses_a_flattened_command() {
    let mut line = [0u8; 128];
    assert_eq!(parse(&mut line, "sys"), Command::Common(Common::Sys));
}

#[test]
fn parses_a_flattened_command_with_arguments() {
    let mut line = [0u8; 128];
    assert_eq!(
        parse(&mut line, "ping 7 3"),
        Command::Common(Common::Ping { host: 7, count: 3 })
    );
}

#[test]
fn parses_the_containers_own_command() {
    let mut line = [0u8; 128];
    assert_eq!(parse(&mut line, "io 2"), Command::Io { channel: 2 });
}

#[test]
fn parses_a_second_flattened_group() {
    let mut line = [0u8; 128];
    assert_eq!(
        parse(&mut line, "counters"),
        Command::Diagnostics(Diagnostics::Counters)
    );
}

#[test]
fn aliases_survive_flattening() {
    let mut line = [0u8; 128];
    assert_eq!(parse(&mut line, "exit"), Command::Common(Common::Quit));
}

#[test]
fn unknown_commands_still_fail() {
    let mut line = [0u8; 128];
    let text = "nope";
    line[..text.len()].copy_from_slice(text.as_bytes());
    assert!(<CommandParser as ParserFamily>::parse(&mut line, text.len()).is_err());
}

#[test]
fn command_iter_yields_real_commands_only() {
    let names: heapless::Vec<&str, 16> = CommandIter::new(root().commands)
        .map(|command| command.name)
        .collect();
    assert_eq!(names.as_slice(), &["sys", "ping", "quit", "counters", "io"]);
}

#[test]
fn flattened_entries_are_not_addressable_by_name() {
    // A flattened group has an empty name; looking one up must not match it.
    assert!(find_command(root().commands, "").is_none());
    assert!(find_command(root().commands, "common").is_none());
}

#[test]
fn find_command_descends_into_groups() {
    let found = find_command(root().commands, "ping").expect("flattened command is findable");
    assert_eq!(found.name, "ping");
    assert!(!found.flatten);
}

#[test]
fn the_raw_command_table_still_holds_the_group_marker() {
    // CommandIter hides flattened entries; the underlying const still records them so help and
    // completion can splice lazily rather than concatenating at compile time.
    let markers = root()
        .commands
        .iter()
        .filter(|command: &&CommandSpec| command.flatten)
        .count();
    assert_eq!(markers, 2);
}
