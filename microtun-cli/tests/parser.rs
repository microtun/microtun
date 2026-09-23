use core::net::Ipv4Addr;

use heapless::Vec;
use microtun_cli::{Args, Parser, ParserFamily, Subcommand, ValueEnum};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Level {
    Error,
    Warn,
    Info,
    #[value(name = "dbg", alias = "debug")]
    Debug,
}

#[derive(Debug, Eq, PartialEq, Args)]
struct PingArgs {
    host: Ipv4Addr,

    #[arg(short = 'c', long, default_value_t = 4)]
    count: u8,
}

#[derive(Debug, Eq, PartialEq, Subcommand)]
enum Net<'a> {
    Static {
        address: Ipv4Addr,

        #[arg(short, long, default_value_t = 24)]
        prefix: u8,

        #[arg(long)]
        label: Option<&'a str>,
    },
    Dhcp,
}

#[derive(Debug, Eq, PartialEq, Parser)]
#[command(name = "device", about = "test console", version = "0.1.0")]
enum Command<'a> {
    Status {
        #[arg(short, long)]
        verbose: bool,
    },
    Echo {
        text: &'a str,
    },
    Ping(PingArgs),
    Net {
        #[command(subcommand)]
        command: Net<'a>,
    },
    Log {
        #[arg(value_enum)]
        level: Level,
    },
    Dns {
        #[arg(long)]
        server: Vec<Ipv4Addr, 3>,
    },
    Verbose {
        #[arg(short, long, action = ArgAction::Count)]
        verbose: u8,
    },
}

fn parse<'a>(buffer: &'a mut [u8], text: &str) -> Command<'a> {
    buffer[..text.len()].copy_from_slice(text.as_bytes());
    <CommandParser as ParserFamily>::parse(buffer, text.len()).unwrap()
}

#[test]
fn parses_flags_and_defaults() {
    let mut line = [0u8; 128];
    assert_eq!(
        parse(&mut line, "status -v"),
        Command::Status { verbose: true }
    );
}

#[test]
fn parses_zero_copy_quoted_string() {
    let mut line = [0u8; 128];
    assert_eq!(
        parse(&mut line, "echo \"hello world\""),
        Command::Echo {
            text: "hello world"
        }
    );
}

#[test]
fn parses_nested_subcommands_and_options_anywhere() {
    let mut line = [0u8; 128];
    assert_eq!(
        parse(
            &mut line,
            "net static --label office 192.168.4.20 --prefix 25"
        ),
        Command::Net {
            command: Net::Static {
                address: Ipv4Addr::new(192, 168, 4, 20),
                prefix: 25,
                label: Some("office"),
            }
        }
    );
}

#[test]
fn parses_tuple_args() {
    let mut line = [0u8; 128];
    assert_eq!(
        parse(&mut line, "ping 10.0.0.1 -c 7"),
        Command::Ping(PingArgs {
            host: Ipv4Addr::new(10, 0, 0, 1),
            count: 7,
        })
    );
}

#[test]
fn parses_value_enum_alias() {
    let mut line = [0u8; 128];
    assert_eq!(
        parse(&mut line, "log debug"),
        Command::Log {
            level: Level::Debug
        }
    );
}

#[test]
fn parses_repeated_bounded_values() {
    let mut line = [0u8; 160];
    let command = parse(
        &mut line,
        "dns --server 1.1.1.1 --server 8.8.8.8 --server 9.9.9.9",
    );
    let Command::Dns { server } = command else {
        panic!("wrong command");
    };
    assert_eq!(server.len(), 3);
    assert_eq!(server[0], Ipv4Addr::new(1, 1, 1, 1));
}

#[test]
fn counts_clustered_flags() {
    let mut line = [0u8; 128];
    assert_eq!(
        parse(&mut line, "verbose -vvv"),
        Command::Verbose { verbose: 3 }
    );
}

#[derive(Debug, Eq, PartialEq, Args)]
struct CommonArgs {
    #[arg(long, alias = "wait", visible_alias = "delay")]
    timeout: Option<u32>,
}

#[derive(Debug, Eq, PartialEq, Subcommand)]
enum RootCommand<'a> {
    Echo {
        text: &'a str,

        #[command(flatten)]
        common: CommonArgs,
    },
    Feature {
        #[arg(long, action = ArgAction::SetFalse)]
        enabled: bool,
    },
    Required {
        #[arg(long, required = true)]
        label: Option<&'a str>,
    },
    RequiredFlag {
        #[arg(long, required = true)]
        enabled: bool,
    },
    RequiredCount {
        #[arg(short = 'c', long, required = true, action = ArgAction::Count)]
        verbose: u8,
    },
    RequiredDisable {
        #[arg(long, required = true, action = ArgAction::SetFalse)]
        enabled: bool,
    },
}

#[derive(Debug, Eq, PartialEq, Parser)]
#[command(name = "root")]
struct Root<'a> {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: RootCommand<'a>,
}

fn parse_root<'a>(buffer: &'a mut [u8], text: &str) -> Root<'a> {
    buffer[..text.len()].copy_from_slice(text.as_bytes());
    <RootParser as ParserFamily>::parse(buffer, text.len()).unwrap()
}

#[test]
fn parser_struct_supports_global_flags_and_flatten() {
    let mut line = [0u8; 160];
    assert_eq!(
        parse_root(&mut line, "echo hello --wait 50 --verbose"),
        Root {
            verbose: true,
            command: RootCommand::Echo {
                text: "hello",
                common: CommonArgs { timeout: Some(50) },
            },
        }
    );
}

#[test]
fn set_false_defaults_true_and_flips_when_present() {
    let mut line = [0u8; 128];
    assert_eq!(
        parse_root(&mut line, "feature"),
        Root {
            verbose: false,
            command: RootCommand::Feature { enabled: true },
        }
    );
    assert_eq!(
        parse_root(&mut line, "feature --enabled"),
        Root {
            verbose: false,
            command: RootCommand::Feature { enabled: false },
        }
    );
}

#[test]
fn required_optional_field_is_enforced() {
    let mut line = [0u8; 128];
    line[..8].copy_from_slice(b"required");
    let err = <RootParser as ParserFamily>::parse(&mut line, 8).unwrap_err();
    assert_eq!(err.kind, microtun_cli::ParseErrorKind::MissingArgument);
}

#[test]
fn hidden_and_visible_option_aliases_both_parse() {
    let mut line = [0u8; 160];
    assert_eq!(
        parse_root(&mut line, "echo hello --delay 25"),
        Root {
            verbose: false,
            command: RootCommand::Echo {
                text: "hello",
                common: CommonArgs { timeout: Some(25) },
            },
        }
    );
}

#[test]
fn required_flag_actions_are_enforced() {
    let mut line = [0u8; 128];
    for text in ["required-flag", "required-count", "required-disable"] {
        line[..text.len()].copy_from_slice(text.as_bytes());
        let err = <RootParser as ParserFamily>::parse(&mut line, text.len()).unwrap_err();
        assert_eq!(err.kind, microtun_cli::ParseErrorKind::MissingArgument);
    }

    assert_eq!(
        parse_root(&mut line, "required-flag --enabled"),
        Root {
            verbose: false,
            command: RootCommand::RequiredFlag { enabled: true },
        }
    );
    assert_eq!(
        parse_root(&mut line, "required-count -cc"),
        Root {
            verbose: false,
            command: RootCommand::RequiredCount { verbose: 2 },
        }
    );
    assert_eq!(
        parse_root(&mut line, "required-disable --enabled"),
        Root {
            verbose: false,
            command: RootCommand::RequiredDisable { enabled: false },
        }
    );
}

#[test]
fn invalid_values_preserve_expected_metadata() {
    let mut line = [0u8; 128];
    let text = "log nope";
    line[..text.len()].copy_from_slice(text.as_bytes());
    let err = <CommandParser as ParserFamily>::parse(&mut line, text.len()).unwrap_err();
    assert_eq!(err.kind, microtun_cli::ParseErrorKind::InvalidValue);
    assert_eq!(err.argument, Some("level"));
    assert_eq!(err.expected, Some("one of: error, warn, info, dbg"));
}

#[test]
fn missing_and_too_many_value_errors_preserve_argument_metadata() {
    let mut line = [0u8; 192];
    let text = "dns --server";
    line[..text.len()].copy_from_slice(text.as_bytes());
    let err = <CommandParser as ParserFamily>::parse(&mut line, text.len()).unwrap_err();
    assert_eq!(err.kind, microtun_cli::ParseErrorKind::MissingValue);
    assert_eq!(err.argument, Some("server"));

    let text = "dns --server 1.1.1.1 --server 8.8.8.8 --server 9.9.9.9 --server 4.4.4.4";
    line[..text.len()].copy_from_slice(text.as_bytes());
    let err = <CommandParser as ParserFamily>::parse(&mut line, text.len()).unwrap_err();
    assert_eq!(err.kind, microtun_cli::ParseErrorKind::TooManyValues);
    assert_eq!(err.argument, Some("server"));
}

#[test]
fn unknown_options_are_not_consumed_as_positionals() {
    let mut line = [0u8; 128];
    let text = "echo --bogus";
    line[..text.len()].copy_from_slice(text.as_bytes());
    let err = <CommandParser as ParserFamily>::parse(&mut line, text.len()).unwrap_err();
    assert_eq!(err.kind, microtun_cli::ParseErrorKind::UnknownOption);
}

#[derive(Debug, Eq, PartialEq, Args)]
struct FlattenedPositionals<'a> {
    flattened: &'a str,
}

#[derive(Debug, Eq, PartialEq, Parser)]
#[command(name = "ordering")]
enum Ordering<'a> {
    Mixed {
        local: &'a str,
        #[command(flatten)]
        flattened: FlattenedPositionals<'a>,
    },
}

#[test]
fn flattened_positional_schema_matches_parser_order() {
    let mut line = [0u8; 128];
    let text = "mixed flattened local";
    line[..text.len()].copy_from_slice(text.as_bytes());
    let parsed = <OrderingParser as ParserFamily>::parse(&mut line, text.len()).unwrap();
    assert_eq!(
        parsed,
        Ordering::Mixed {
            local: "local",
            flattened: FlattenedPositionals {
                flattened: "flattened",
            },
        }
    );

    let args = OrderingParser::ROOT.commands[0].args;
    assert_eq!(args[0].kind, microtun_cli::ArgKind::Flatten);
    assert_eq!(args[1].name, "local");
}

#[derive(Debug, Eq, PartialEq, Parser)]
#[command(name = "defaults")]
struct Defaults {
    #[arg(long, default_value_t = 1 + 2)]
    computed: u8,
    #[arg(long, default_value_t = 3)]
    literal: u8,
    #[arg(long, default_value_t)]
    implicit: u8,
}

#[test]
fn help_schema_only_renders_truthful_static_defaults() {
    let args = DefaultsParser::ROOT.args;
    assert_eq!(args[0].name, "computed");
    assert_eq!(args[0].default, None);
    assert_eq!(args[1].default, Some("3"));
    assert_eq!(args[2].default, None);
}

// ---------------------------------------------------------------------------
// Regression tests for parser fixes
// ---------------------------------------------------------------------------

/// A flag declared *before* an option whose short takes an attached value.
///
/// Field order matters here: `force` is checked first, and used to match the `f` inside the
/// value of `-o`.
#[derive(Debug, Eq, PartialEq, Parser)]
#[command(name = "cluster")]
struct ClusterCli<'a> {
    #[arg(short, long)]
    force: bool,

    #[arg(short, long)]
    output: Option<&'a str>,

    #[arg(short, long)]
    all: bool,
}

fn parse_cluster<'a>(buffer: &'a mut [u8], text: &str) -> ClusterCli<'a> {
    buffer[..text.len()].copy_from_slice(text.as_bytes());
    <ClusterCliParser as ParserFamily>::parse(buffer, text.len()).unwrap()
}

#[test]
fn attached_short_value_is_not_scanned_for_flag_letters() {
    let mut line = [0u8; 128];
    assert_eq!(
        parse_cluster(&mut line, "-ofoo"),
        ClusterCli {
            force: false,
            output: Some("foo"),
            all: false,
        }
    );

    let mut line = [0u8; 128];
    assert_eq!(
        parse_cluster(&mut line, "-o=fall"),
        ClusterCli {
            force: false,
            output: Some("fall"),
            all: false,
        }
    );
}

#[test]
fn cluster_may_end_in_a_value_taking_short() {
    let mut line = [0u8; 128];
    assert_eq!(
        parse_cluster(&mut line, "-fao bar"),
        ClusterCli {
            force: true,
            output: Some("bar"),
            all: true,
        }
    );

    let mut line = [0u8; 128];
    assert_eq!(
        parse_cluster(&mut line, "-faobar"),
        ClusterCli {
            force: true,
            output: Some("bar"),
            all: true,
        }
    );
}

#[test]
fn cluster_flags_are_claimed_regardless_of_field_order() {
    // `output` is declared between the two flags; claiming its value must not orphan `all`.
    let mut line = [0u8; 128];
    assert_eq!(
        parse_cluster(&mut line, "-af"),
        ClusterCli {
            force: true,
            output: None,
            all: true,
        }
    );
}

#[derive(Debug, Eq, PartialEq, Parser)]
#[command(name = "vals")]
struct ValueCli<'a> {
    #[arg(long)]
    name: Option<&'a str>,

    #[arg(long, allow_hyphen_values)]
    raw: Option<&'a str>,

    offset: Option<i32>,

    trailing: Vec<&'a str, 4>,
}

fn try_parse_values<'a>(
    buffer: &'a mut [u8],
    text: &str,
) -> Result<ValueCli<'a>, microtun_cli::ParseError> {
    buffer[..text.len()].copy_from_slice(text.as_bytes());
    <ValueCliParser as ParserFamily>::parse(buffer, text.len())
}

#[test]
fn option_values_do_not_swallow_the_following_option() {
    let mut line = [0u8; 128];
    let error = try_parse_values(&mut line, "--name --raw x").unwrap_err();
    assert_eq!(error.kind, microtun_cli::ParseErrorKind::MissingValue);
    assert_eq!(error.argument, Some("name"));
}

#[test]
fn allow_hyphen_values_opts_back_in() {
    let mut line = [0u8; 128];
    let parsed = try_parse_values(&mut line, "--raw --weird").unwrap();
    assert_eq!(parsed.raw, Some("--weird"));
}

#[test]
fn negative_numbers_parse_as_positionals() {
    let mut line = [0u8; 128];
    let parsed = try_parse_values(&mut line, "-42").unwrap();
    assert_eq!(parsed.offset, Some(-42));
}

#[test]
fn double_dash_terminates_option_parsing() {
    let mut line = [0u8; 128];
    let parsed = try_parse_values(&mut line, "--name bob -- 7 --not-an-option -x").unwrap();
    assert_eq!(parsed.name, Some("bob"));
    assert_eq!(parsed.offset, Some(7));
    assert_eq!(parsed.trailing.as_slice(), &["--not-an-option", "-x"]);
}

#[derive(Debug, Eq, PartialEq, Parser)]
#[command(name = "dash")]
struct DashCli<'a> {
    path: Option<&'a str>,
}

#[test]
fn bare_dash_is_still_a_positional() {
    let mut line = [0u8; 128];
    let text = "-";
    line[..text.len()].copy_from_slice(text.as_bytes());
    let parsed = <DashCliParser as ParserFamily>::parse(&mut line, text.len()).unwrap();
    assert_eq!(parsed.path, Some("-"));
}

#[cfg(feature = "alloc")]
#[derive(Debug, Eq, PartialEq, Parser)]
#[command(name = "alloc")]
struct AllocCli {
    name: std::string::String,

    #[arg(long)]
    tag: std::vec::Vec<std::string::String>,

    trailing: std::vec::Vec<u16>,
}

#[cfg(feature = "alloc")]
#[test]
fn parses_alloc_string_and_vec_arguments() {
    let text = "--tag alpha --tag beta device 7 11";
    let mut line = [0u8; 128];
    line[..text.len()].copy_from_slice(text.as_bytes());

    let parsed = <AllocCliParser as ParserFamily>::parse(&mut line, text.len()).unwrap();
    assert_eq!(
        parsed,
        AllocCli {
            name: std::string::String::from("device"),
            tag: std::vec![
                std::string::String::from("alpha"),
                std::string::String::from("beta"),
            ],
            trailing: std::vec![7, 11],
        }
    );
}
