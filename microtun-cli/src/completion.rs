use heapless::Vec;

use crate::{ArgAction, ArgKind, ArgSpec, CommandSpec, RootSpec, lexer::MAX_TOKENS};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateKind {
    Command,
    Option,
    Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Candidate {
    pub prefix: &'static str,
    pub value: &'static str,
    pub kind: CandidateKind,
    /// Absolute byte offset in the line at which replacement should begin.
    ///
    /// This is resolved against the tokenization the completer performed, so it is correct for
    /// quoted and escaped tokens, which cannot be recovered by scanning back over whitespace.
    pub replace_at: usize,
    /// Whether the inserted value has to be wrapped in double quotes to survive re-lexing.
    pub quote: bool,
}

/// Whether `value` must be quoted to lex back as a single token.
fn needs_quoting(value: &str) -> bool {
    value.is_empty()
        || value
            .bytes()
            .any(|byte| is_space(byte) || matches!(byte, b'\'' | b'"' | b'\\'))
}

fn push_unique<const N: usize>(out: &mut Vec<Candidate, N>, candidate: Candidate) {
    if out.iter().any(|item| {
        item.prefix == candidate.prefix
            && item.value == candidate.value
            && item.replace_at == candidate.replace_at
    }) {
        return;
    }
    let _ = out.push(candidate);
}

/// Iterates the logical characters of a raw token, resolving quotes and escapes.
///
/// `"my fi` yields `my fi`, so a partially quoted token still matches candidates correctly.
struct Logical<'a> {
    bytes: &'a [u8],
    read: usize,
    quote: Option<u8>,
}

impl<'a> Logical<'a> {
    fn new(raw: &'a str) -> Self {
        Self {
            bytes: raw.as_bytes(),
            read: 0,
            quote: None,
        }
    }
}

impl Iterator for Logical<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        loop {
            let byte = *self.bytes.get(self.read)?;
            match self.quote {
                Some(quote) if byte == quote => {
                    self.quote = None;
                    self.read += 1;
                }
                _ if byte == b'\\' => {
                    self.read += 1;
                    let escaped = *self.bytes.get(self.read)?;
                    self.read += 1;
                    return Some(escaped);
                }
                None if matches!(byte, b'\'' | b'"') => {
                    self.quote = Some(byte);
                    self.read += 1;
                }
                _ => {
                    self.read += 1;
                    return Some(byte);
                }
            }
        }
    }
}

/// Whether the logical text of `raw` is a prefix of `candidate`.
fn logical_is_prefix_of(raw: &str, candidate: &str) -> bool {
    let mut expected = candidate.bytes();
    for byte in Logical::new(raw) {
        if expected.next() != Some(byte) {
            return false;
        }
    }
    true
}

/// Whether `raw` contains no quoting, so byte offsets within it are meaningful.
fn is_plain(raw: &str) -> bool {
    !raw.bytes().any(|byte| matches!(byte, b'\'' | b'"' | b'\\'))
}

fn find_command(commands: &'static [CommandSpec], name: &str) -> Option<&'static CommandSpec> {
    crate::schema::find_command(commands, name)
}

fn visit_args(args: &'static [ArgSpec], f: &mut impl FnMut(&'static ArgSpec)) {
    for arg in args {
        if arg.kind == ArgKind::Flatten {
            visit_args(arg.children, f);
        } else {
            f(arg);
        }
    }
}

fn arg_long_matches(arg: &ArgSpec, name: &str) -> bool {
    arg.long == Some(name)
        || arg.aliases.iter().copied().any(|alias| alias == name)
        || arg
            .visible_aliases
            .iter()
            .copied()
            .any(|alias| alias == name)
}

fn short_token(token: &str, short: char) -> bool {
    let mut chars = token.chars();
    chars.next() == Some('-') && chars.next() == Some(short) && chars.next().is_none()
}

fn add_value_candidates<const N: usize>(
    arg: &ArgSpec,
    current: &str,
    replace_at: usize,
    out: &mut Vec<Candidate, N>,
) {
    let mut add = |value: &'static str| {
        if logical_is_prefix_of(current, value) {
            push_unique(
                out,
                Candidate {
                    prefix: "",
                    value,
                    kind: CandidateKind::Value,
                    replace_at,
                    quote: needs_quoting(value),
                },
            );
        }
    };
    for value in arg.values {
        add(value.name);
        for alias in value.visible_aliases {
            add(alias);
        }
    }
}

fn option_value_candidates<const N: usize>(
    args: &'static [ArgSpec],
    previous: &str,
    current: &str,
    replace_at: usize,
    globals_only: bool,
    out: &mut Vec<Candidate, N>,
) -> bool {
    let mut found = false;
    visit_args(args, &mut |arg| {
        if globals_only && !arg.global {
            return;
        }
        if arg.kind != ArgKind::Option {
            return;
        }
        let previous_long = previous.strip_prefix("--").unwrap_or(previous);
        let is_match = arg_long_matches(arg, previous_long)
            || arg.short.is_some_and(|short| short_token(previous, short));
        if !is_match || arg.values.is_empty() {
            return;
        }
        found = true;
        add_value_candidates(arg, current, replace_at, out);
    });
    found
}

fn attached_option_value_candidates<const N: usize>(
    args: &'static [ArgSpec],
    current: &str,
    token_at: usize,
    globals_only: bool,
    out: &mut Vec<Candidate, N>,
) -> bool {
    if !is_plain(current) {
        // Byte offsets into a quoted token are not meaningful; fall through to whole-token
        // completion instead of splicing into the middle of a quoted region.
        return false;
    }
    let mut found = false;
    visit_args(args, &mut |arg| {
        if found
            || (globals_only && !arg.global)
            || arg.kind != ArgKind::Option
            || arg.values.is_empty()
        {
            return;
        }

        if let Some(rest) = current.strip_prefix("--") {
            if let Some((name, value)) = rest.split_once('=') {
                if arg_long_matches(arg, name) {
                    let offset = current.len().saturating_sub(value.len());
                    add_value_candidates(arg, value, token_at + offset, out);
                    found = true;
                    return;
                }
            }
        }

        if current.starts_with('-') && !current.starts_with("--") {
            let mut chars = current[1..].chars();
            let Some(token_short) = chars.next() else {
                return;
            };
            if arg.short != Some(token_short) {
                return;
            }
            let mut value = chars.as_str();
            if value.is_empty() {
                return;
            }
            let base = 1 + token_short.len_utf8();
            let offset = if let Some(rest) = value.strip_prefix('=') {
                value = rest;
                base + 1
            } else {
                base
            };
            add_value_candidates(arg, value, token_at + offset, out);
            found = true;
        }
    });
    found
}

/// Return whether `token` is a known option and, if so, whether it consumes the next token.
fn option_consumes_next(args: &'static [ArgSpec], token: &str, globals_only: bool) -> Option<bool> {
    let mut answer = None;
    visit_args(args, &mut |arg| {
        if answer.is_some() || (globals_only && !arg.global) {
            return;
        }
        if !matches!(arg.kind, ArgKind::Option | ArgKind::Flag) {
            return;
        }

        if let Some(rest) = token.strip_prefix("--") {
            let (name, attached) = rest
                .split_once('=')
                .map_or((rest, false), |(name, _)| (name, true));
            if arg_long_matches(arg, name) {
                answer = Some(arg.kind == ArgKind::Option && !attached);
                return;
            }
        }

        if let Some(short) = arg.short {
            if short_token(token, short) {
                answer = Some(arg.kind == ArgKind::Option);
            } else if arg.kind == ArgKind::Option
                && token.starts_with('-')
                && !token.starts_with("--")
            {
                let mut chars = token.chars();
                let _ = chars.next();
                if chars.next() == Some(short) && !chars.as_str().is_empty() {
                    answer = Some(false);
                }
            }
        }
    });
    answer
}

fn positional_at(args: &'static [ArgSpec], index: usize) -> Option<&'static ArgSpec> {
    let mut position = 0usize;
    let mut last_repeated = None;
    let mut answer = None;
    visit_args(args, &mut |arg| {
        if answer.is_some() || arg.kind != ArgKind::Positional {
            return;
        }
        if position == index {
            answer = Some(arg);
            return;
        }
        if arg.action == ArgAction::Append {
            last_repeated = Some(arg);
        }
        position += 1;
    });
    answer.or(last_repeated.filter(|_| index >= position))
}

fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

/// A token of the line under completion, with its byte offset.
#[derive(Clone, Copy, Debug)]
struct Word<'a> {
    raw: &'a str,
    start: usize,
}

/// Tokenize for completion without modifying the editor buffer. Unlike
/// `split_ascii_whitespace`, this keeps quoted/escaped text within one token.
fn completion_words(text: &str) -> (Vec<Word<'_>, MAX_TOKENS>, bool) {
    let bytes = text.as_bytes();
    let mut words = Vec::new();
    let mut read = 0usize;
    let mut trailing_space = false;

    while read < bytes.len() {
        while read < bytes.len() && is_space(bytes[read]) {
            read += 1;
            trailing_space = true;
        }
        if read == bytes.len() {
            break;
        }

        trailing_space = false;
        let start = read;
        let mut quote = None;
        while read < bytes.len() {
            let byte = bytes[read];
            match quote {
                Some(q) if byte == q => {
                    quote = None;
                    read += 1;
                }
                Some(_) if byte == b'\\' => {
                    read += 1;
                    if read < bytes.len() {
                        read += 1;
                    }
                }
                Some(_) => read += 1,
                None if matches!(byte, b'\'' | b'"') => {
                    quote = Some(byte);
                    read += 1;
                }
                None if byte == b'\\' => {
                    read += 1;
                    if read < bytes.len() {
                        read += 1;
                    }
                }
                None if is_space(byte) => break,
                None => read += 1,
            }
        }

        let word = Word {
            raw: &text[start..read],
            start,
        };
        if words.push(word).is_err() {
            return (words, trailing_space);
        }
    }

    (words, trailing_space)
}

pub fn complete<const N: usize>(
    root: &'static RootSpec,
    line: &[u8],
    cursor: usize,
    out: &mut Vec<Candidate, N>,
) {
    out.clear();
    let cursor = cursor.min(line.len());
    let Ok(text) = core::str::from_utf8(&line[..cursor]) else {
        return;
    };
    let (mut words, trailing_space) = completion_words(text);

    let current = if trailing_space {
        Word {
            raw: "",
            start: cursor,
        }
    } else {
        words.pop().unwrap_or(Word {
            raw: "",
            start: cursor,
        })
    };
    let previous = words.last().map(|word| word.raw).unwrap_or("");
    let replace_at = current.start;

    let mut commands = root.commands;
    let mut args = root.args;
    let mut positional_seen = 0usize;
    let mut skip_value = false;
    let mut terminated = false;

    for word in words.iter().map(|word| word.raw) {
        if skip_value {
            skip_value = false;
            continue;
        }

        if terminated {
            positional_seen = positional_seen.saturating_add(1);
            continue;
        }

        if word == crate::parse::TERMINATOR {
            terminated = true;
            continue;
        }

        if word.starts_with('-') && word != "-" {
            if let Some(consumes) = option_consumes_next(args, word, false)
                .or_else(|| option_consumes_next(root.args, word, true))
            {
                skip_value = consumes;
            }
            // An unrecognized option is still an option, not a positional value.
            continue;
        }

        if let Some(command) = find_command(commands, word) {
            commands = command.subcommands;
            args = command.args;
            positional_seen = 0;
            continue;
        }

        positional_seen = positional_seen.saturating_add(1);
    }

    if !terminated {
        let local_attached =
            attached_option_value_candidates(args, current.raw, replace_at, false, out);
        let global_attached = if core::ptr::eq(args, root.args) {
            false
        } else {
            attached_option_value_candidates(root.args, current.raw, replace_at, true, out)
        };
        if local_attached || global_attached {
            return;
        }

        let local_value =
            option_value_candidates(args, previous, current.raw, replace_at, false, out);
        let global_value = if core::ptr::eq(args, root.args) {
            false
        } else {
            option_value_candidates(root.args, previous, current.raw, replace_at, true, out)
        };
        if local_value || global_value {
            return;
        }

        if current.raw.starts_with('-') && current.raw != "-" {
            let needle = current.raw.trim_start_matches('-');
            let mut add_arg = |arg: &'static ArgSpec| {
                let mut add = |value: &'static str| {
                    if value.starts_with(needle) {
                        push_unique(
                            out,
                            Candidate {
                                prefix: "--",
                                value,
                                kind: CandidateKind::Option,
                                replace_at,
                                quote: false,
                            },
                        );
                    }
                };
                if let Some(long) = arg.long {
                    add(long);
                }
                for alias in arg.visible_aliases {
                    add(alias);
                }
            };
            visit_args(args, &mut add_arg);
            if !core::ptr::eq(args, root.args) {
                visit_args(root.args, &mut |arg| {
                    if arg.global {
                        add_arg(arg);
                    }
                });
            }
            return;
        }
    }

    if let Some(arg) = positional_at(args, positional_seen) {
        add_value_candidates(arg, current.raw, replace_at, out);
    }

    if terminated {
        return;
    }

    for command in crate::schema::CommandIter::new(commands) {
        let mut add = |value: &'static str| {
            if logical_is_prefix_of(current.raw, value) {
                push_unique(
                    out,
                    Candidate {
                        prefix: "",
                        value,
                        kind: CandidateKind::Command,
                        replace_at,
                        quote: false,
                    },
                );
            }
        };
        add(command.name);
        for alias in command.visible_aliases {
            add(alias);
        }
    }
}
