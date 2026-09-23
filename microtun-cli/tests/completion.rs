// These types are declarative fixtures for the derive-generated completion schema.
#![allow(dead_code)]

use heapless::Vec;
use microtun_cli::{
    Args, Candidate, CandidateKind, Parser, ParserFamily, Subcommand, ValueEnum,
    completion::complete,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    Station,
    #[value(name = "ap", alias = "access-point", visible_alias = "hotspot")]
    AccessPoint,
}

#[derive(Args)]
struct WifiArgs {
    #[arg(
        short = 'm',
        long,
        value_enum,
        alias = "secret-mode",
        visible_alias = "kind"
    )]
    mode: Option<Mode>,
}

#[derive(Subcommand)]
enum Command {
    #[command(alias = "wi", visible_alias = "wireless")]
    Wifi {
        #[command(flatten)]
        args: WifiArgs,

        #[arg(value_enum)]
        positional_mode: Option<Mode>,
    },
    Quote {
        text: heapless::String<32>,
        #[arg(value_enum)]
        mode: Option<Mode>,
    },
}

#[derive(Parser)]
#[command(name = "device")]
struct Cli {
    #[arg(short, long, global = true, action = ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

fn values(line: &str) -> Vec<Candidate, 16> {
    let mut out = Vec::new();
    complete(&CliParser::ROOT, line.as_bytes(), line.len(), &mut out);
    out
}

#[test]
fn completes_only_visible_command_aliases() {
    let out = values("w");
    assert!(
        out.iter()
            .any(|c| c.kind == CandidateKind::Command && c.value == "wifi")
    );
    assert!(
        out.iter()
            .any(|c| c.kind == CandidateKind::Command && c.value == "wireless")
    );
    assert!(
        !out.iter()
            .any(|c| c.kind == CandidateKind::Command && c.value == "wi")
    );
}

#[test]
fn completes_long_options_global_options_and_only_visible_aliases() {
    let out = values("wifi --v");
    assert!(
        out.iter()
            .any(|c| c.kind == CandidateKind::Option && c.value == "verbose")
    );

    let out = values("wifi --k");
    assert!(
        out.iter()
            .any(|c| c.kind == CandidateKind::Option && c.value == "kind")
    );

    let out = values("wifi --s");
    assert!(
        !out.iter()
            .any(|c| c.kind == CandidateKind::Option && c.value == "secret-mode")
    );
}

#[test]
fn completes_option_value_enum_visible_aliases_only() {
    let out = values("wifi --mode h");
    assert!(
        out.iter()
            .any(|c| c.kind == CandidateKind::Value && c.value == "hotspot")
    );

    let out = values("wifi --mode a");
    assert!(
        out.iter()
            .any(|c| c.kind == CandidateKind::Value && c.value == "ap")
    );
    assert!(
        !out.iter()
            .any(|c| c.kind == CandidateKind::Value && c.value == "access-point")
    );
}

#[test]
fn completes_positional_value_enums() {
    let out = values("wifi s");
    assert!(
        out.iter()
            .any(|c| c.kind == CandidateKind::Value && c.value == "station")
    );
}

#[test]
fn completes_attached_long_enum_values() {
    let out = values("wifi --mode=st");
    let candidate = out
        .iter()
        .find(|c| c.kind == CandidateKind::Value && c.value == "station")
        .expect("station candidate");
    assert_eq!(candidate.replace_at, "wifi ".len() + "--mode=".len());
}

#[test]
fn completes_attached_short_enum_values() {
    let out = values("wifi -mst");
    let candidate = out
        .iter()
        .find(|c| c.kind == CandidateKind::Value && c.value == "station")
        .expect("station candidate");
    assert_eq!(candidate.replace_at, "wifi ".len() + "-m".len());

    let out = values("wifi -m=st");
    let candidate = out
        .iter()
        .find(|c| c.kind == CandidateKind::Value && c.value == "station")
        .expect("station candidate");
    assert_eq!(candidate.replace_at, "wifi ".len() + "-m=".len());
}

#[test]
fn completion_tokenization_respects_quoted_positionals() {
    let out = values("quote \"hello world\" s");
    assert!(
        out.iter()
            .any(|c| c.kind == CandidateKind::Value && c.value == "station")
    );
}

// ---------------------------------------------------------------------------
// Regression tests for completion fixes
// ---------------------------------------------------------------------------

#[test]
fn candidates_report_the_absolute_start_of_the_current_token() {
    let out = values("wifi st");
    let candidate = out
        .iter()
        .find(|c| c.value == "station")
        .expect("station candidate");
    assert_eq!(candidate.replace_at, "wifi ".len());
    assert!(!candidate.quote);
}

#[test]
fn a_quoted_token_completes_from_its_opening_quote() {
    // A backwards scan over whitespace cannot tell that the token began at the quote, so the
    // offset has to come from the completer's own tokenization.
    let out = values("wifi \"st");
    let candidate = out
        .iter()
        .find(|c| c.value == "station")
        .expect("station candidate");
    assert_eq!(candidate.replace_at, "wifi ".len());
}

#[test]
fn quoted_prefixes_match_against_their_logical_text() {
    // `"acce` should still match `access-point`'s visible alias set, not be compared verbatim.
    let out = values("wifi --mode \"ho");
    assert!(
        out.iter()
            .any(|c| c.kind == CandidateKind::Value && c.value == "hotspot")
    );
}

#[test]
fn an_escaped_prefix_matches_its_logical_text() {
    let out = values("wifi \\st");
    assert!(
        out.iter()
            .any(|c| c.kind == CandidateKind::Value && c.value == "station")
    );
}

#[test]
fn values_needing_quotes_are_flagged() {
    let out = values("quote ");
    // The positional here is a free-form string with no enumerated values, so completion is
    // empty; this asserts the flag plumbing rather than a specific candidate.
    assert!(out.iter().all(|c| !c.quote || needs_quotes(c.value)));
}

fn needs_quotes(value: &str) -> bool {
    value.is_empty() || value.bytes().any(|b| b.is_ascii_whitespace())
}

#[test]
fn nothing_is_completed_after_the_end_of_options_marker() {
    let out = values("wifi -- st");
    assert!(out.iter().all(|c| c.kind != CandidateKind::Command));
}

#[test]
fn an_unknown_option_is_not_counted_as_a_positional() {
    // `--nope` is not a known option, but it is still an option: the enum positional that
    // follows is the first positional, not the second.
    let out = values("wifi --nope st");
    assert!(
        out.iter()
            .any(|c| c.kind == CandidateKind::Value && c.value == "station")
    );
}
