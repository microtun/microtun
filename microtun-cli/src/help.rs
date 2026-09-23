use embedded_io_async::Write;

use crate::{
    ArgKind, ArgSpec, CommandSpec, Error, ErrorKind, RootSpec,
    io::{write_line, write_str},
    schema::{CommandIter, find_command},
};

fn visible_aliases_width(aliases: &'static [&'static str], prefix: &str) -> usize {
    if aliases.is_empty() {
        return 0;
    }

    let mut width = " [aliases: ".len() + "]".len();
    for (index, alias) in aliases.iter().enumerate() {
        if index != 0 {
            width += ", ".len();
        }
        width += prefix.len() + alias.len();
    }
    width
}

fn command_label_width(command: &CommandSpec) -> usize {
    command.name.len() + visible_aliases_width(command.visible_aliases, "")
}

fn arg_label_width(arg: &ArgSpec) -> usize {
    let mut width = if arg.short.is_some() {
        let mut width = 2usize; // -x
        if let Some(long) = arg.long {
            width += ", ".len() + "--".len() + long.len();
        }
        width
    } else if let Some(long) = arg.long {
        "    --".len() + long.len()
    } else if arg.kind == ArgKind::Positional {
        "<>".len() + arg.value_name.len()
    } else {
        0
    };

    if arg.kind == ArgKind::Option {
        width += " <>".len() + arg.value_name.len();
    }
    width
}

fn value_label_width(value: &crate::ValueSpec) -> usize {
    value.name.len() + visible_aliases_width(value.visible_aliases, "")
}

async fn write_column_gap<W: Write<Error = ErrorKind> + ?Sized>(
    out: &mut W,
    current_width: usize,
    column_width: usize,
) -> Result<(), Error> {
    let mut spaces = column_width.saturating_sub(current_width) + 2;
    while spaces != 0 {
        write_str(out, " ").await?;
        spaces -= 1;
    }
    Ok(())
}

fn descend(root: &'static RootSpec, path: &[&str]) -> Option<&'static CommandSpec> {
    let mut commands = root.commands;
    let mut current = None;
    for segment in path {
        let next = find_command(commands, segment)?;
        commands = next.subcommands;
        current = Some(next);
    }
    current
}

/// Maximum depth of nested `#[command(flatten)]` groups that help rendering will descend into.
const MAX_FLATTEN_DEPTH: usize = 8;

/// Flattens `#[command(flatten)]` groups into a single left-to-right pass.
///
/// Help renders the argument list several times over (to measure columns, then to print), so
/// this keeps each pass linear rather than restarting the walk for every item.
struct ArgIter {
    stack: heapless::Vec<(&'static [ArgSpec], usize), MAX_FLATTEN_DEPTH>,
}

impl ArgIter {
    fn new(args: &'static [ArgSpec]) -> Self {
        let mut stack = heapless::Vec::new();
        let _ = stack.push((args, 0));
        Self { stack }
    }
}

impl Iterator for ArgIter {
    type Item = &'static ArgSpec;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (args, index) = *self.stack.last()?;
            if index >= args.len() {
                self.stack.pop();
                continue;
            }
            if let Some(top) = self.stack.last_mut() {
                top.1 = index + 1;
            }
            let arg = &args[index];
            if arg.kind == ArgKind::Flatten {
                // Deeper nesting than the fixed stack allows is skipped rather than truncating
                // the rest of the list.
                let _ = self.stack.push((arg.children, 0));
                continue;
            }
            return Some(arg);
        }
    }
}

fn has_optional_options(args: &'static [ArgSpec]) -> bool {
    ArgIter::new(args)
        .any(|arg| !arg.required && matches!(arg.kind, ArgKind::Option | ArgKind::Flag))
}

fn has_global_options(root: &'static RootSpec) -> bool {
    ArgIter::new(root.args)
        .any(|arg| arg.global && matches!(arg.kind, ArgKind::Option | ArgKind::Flag))
}

fn has_optional_global_options(root: &'static RootSpec) -> bool {
    ArgIter::new(root.args).any(|arg| {
        arg.global && !arg.required && matches!(arg.kind, ArgKind::Option | ArgKind::Flag)
    })
}

async fn write_required_usage<W: Write<Error = ErrorKind> + ?Sized>(
    out: &mut W,
    arg: &'static ArgSpec,
) -> Result<(), Error> {
    if !arg.required || !matches!(arg.kind, ArgKind::Option | ArgKind::Flag) {
        return Ok(());
    }
    write_str(out, " ").await?;
    if let Some(long) = arg.long {
        write_str(out, "--").await?;
        write_str(out, long).await?;
    } else if let Some(short) = arg.short {
        write_str(out, "-").await?;
        let mut encoded = [0u8; 4];
        out.write_all(short.encode_utf8(&mut encoded).as_bytes())
            .await?;
    }
    if arg.kind == ArgKind::Option {
        write_str(out, " <").await?;
        write_str(out, arg.value_name).await?;
        write_str(out, ">").await?;
    }
    Ok(())
}

async fn usage<W: Write<Error = ErrorKind> + ?Sized>(
    out: &mut W,
    root: &'static RootSpec,
    path: &[&str],
    args: &'static [ArgSpec],
    commands: &'static [CommandSpec],
) -> Result<(), Error> {
    write_str(out, "Usage: ").await?;
    write_str(out, root.name).await?;
    for segment in path {
        write_str(out, " ").await?;
        write_str(out, segment).await?;
    }

    for arg in ArgIter::new(args) {
        match arg.kind {
            ArgKind::Positional if arg.required => {
                write_str(out, " <").await?;
                write_str(out, arg.value_name).await?;
                write_str(out, ">").await?;
            }
            ArgKind::Positional => {
                write_str(out, " [<").await?;
                write_str(out, arg.value_name).await?;
                write_str(out, ">]").await?;
            }
            ArgKind::Option | ArgKind::Flag if arg.required => {
                write_required_usage(out, arg).await?;
            }
            ArgKind::Option | ArgKind::Flag | ArgKind::Flatten => {}
        }
    }

    if !path.is_empty() {
        for arg in ArgIter::new(root.args).filter(|arg| arg.global && arg.required) {
            write_required_usage(out, arg).await?;
        }
    }

    if has_optional_options(args) || (!path.is_empty() && has_optional_global_options(root)) {
        write_str(out, " [OPTIONS]").await?;
    }
    if CommandIter::new(commands).next().is_some() {
        write_str(out, " <COMMAND>").await?;
    }
    write_line(out, "").await?;
    Ok(())
}

async fn write_visible_aliases<W: Write<Error = ErrorKind> + ?Sized>(
    out: &mut W,
    aliases: &'static [&'static str],
    prefix: &str,
) -> Result<(), Error> {
    if aliases.is_empty() {
        return Ok(());
    }
    write_str(out, " [aliases: ").await?;
    for (index, alias) in aliases.iter().enumerate() {
        if index != 0 {
            write_str(out, ", ").await?;
        }
        write_str(out, prefix).await?;
        write_str(out, alias).await?;
    }
    write_str(out, "]").await?;
    Ok(())
}

async fn write_arg<W: Write<Error = ErrorKind> + ?Sized>(
    out: &mut W,
    arg: &'static ArgSpec,
    column_width: usize,
) -> Result<(), Error> {
    write_str(out, "  ").await?;
    if let Some(short) = arg.short {
        write_str(out, "-").await?;
        let mut encoded = [0u8; 4];
        out.write_all(short.encode_utf8(&mut encoded).as_bytes())
            .await?;
        if arg.long.is_some() {
            write_str(out, ", ").await?;
        }
    } else if arg.long.is_some() {
        write_str(out, "    ").await?;
    }

    if let Some(long) = arg.long {
        write_str(out, "--").await?;
        write_str(out, long).await?;
    } else if arg.kind == ArgKind::Positional {
        write_str(out, "<").await?;
        write_str(out, arg.value_name).await?;
        write_str(out, ">").await?;
    }

    if arg.kind == ArgKind::Option {
        write_str(out, " <").await?;
        write_str(out, arg.value_name).await?;
        write_str(out, ">").await?;
    }

    if !arg.help.is_empty() {
        write_column_gap(out, arg_label_width(arg), column_width).await?;
        write_str(out, arg.help).await?;
    }
    if arg.required && matches!(arg.kind, ArgKind::Option | ArgKind::Flag) {
        write_str(out, " [required]").await?;
    }
    if let Some(default) = arg.default {
        write_str(out, " [default: ").await?;
        write_str(out, default).await?;
        write_str(out, "]").await?;
    }
    // Aliases are always long-form, so they are worth showing even for an option that only has
    // a short flag of its own.
    write_visible_aliases(out, arg.visible_aliases, "--").await?;

    let has_value_details = arg
        .values
        .iter()
        .any(|value| !value.help.is_empty() || !value.visible_aliases.is_empty());

    if !arg.values.is_empty() && !has_value_details {
        write_str(out, " [possible values: ").await?;
        for (index, value) in arg.values.iter().enumerate() {
            if index != 0 {
                write_str(out, ", ").await?;
            }
            write_str(out, value.name).await?;
        }
        write_str(out, "]").await?;
    }

    write_line(out, "").await?;

    if has_value_details {
        let value_column_width = arg.values.iter().map(value_label_width).max().unwrap_or(0);
        for value in arg.values {
            write_str(out, "      ").await?;
            write_str(out, value.name).await?;
            write_visible_aliases(out, value.visible_aliases, "").await?;
            if !value.help.is_empty() {
                write_column_gap(out, value_label_width(value), value_column_width).await?;
                write_str(out, value.help).await?;
            }
            write_line(out, "").await?;
        }
    }
    Ok(())
}

pub async fn write_help<W: Write<Error = ErrorKind> + ?Sized>(
    out: &mut W,
    root: &'static RootSpec,
    path: &[&str],
) -> Result<(), Error> {
    let (about, args, commands) = if path.is_empty() {
        (root.about, root.args, root.commands)
    } else if let Some(command) = descend(root, path) {
        (command.about, command.args, command.subcommands)
    } else {
        write_line(out, "error: unknown command in help path").await?;
        return Ok(());
    };

    if !about.is_empty() {
        write_line(out, about).await?;
        write_line(out, "").await?;
    }

    usage(out, root, path, args, commands).await?;

    if CommandIter::new(commands).next().is_some() {
        write_line(out, "").await?;
        write_line(out, "Commands:").await?;
        let command_column_width = CommandIter::new(commands)
            .map(command_label_width)
            .max()
            .unwrap_or(0)
            .max("help".len());
        for command in CommandIter::new(commands) {
            write_str(out, "  ").await?;
            write_str(out, command.name).await?;
            write_visible_aliases(out, command.visible_aliases, "").await?;
            if !command.about.is_empty() {
                write_column_gap(out, command_label_width(command), command_column_width).await?;
                write_str(out, command.about).await?;
            }
            write_line(out, "").await?;
        }
        write_str(out, "  help").await?;
        write_column_gap(out, "help".len(), command_column_width).await?;
        write_line(out, "Print this message").await?;
    }

    let has_positionals = ArgIter::new(args).any(|arg| arg.kind == ArgKind::Positional);
    if has_positionals {
        write_line(out, "").await?;
        write_line(out, "Arguments:").await?;
        let argument_column_width = ArgIter::new(args)
            .filter(|arg| arg.kind == ArgKind::Positional)
            .map(arg_label_width)
            .max()
            .unwrap_or(0);
        for arg in ArgIter::new(args).filter(|arg| arg.kind == ArgKind::Positional) {
            write_arg(out, arg, argument_column_width).await?;
        }
    }

    let include_globals = !path.is_empty() && has_global_options(root);
    // Always rendered: even a command with no options of its own accepts `-h`/`--help`, and
    // omitting the section made help look like it did not.
    {
        write_line(out, "").await?;
        write_line(out, "Options:").await?;
        let mut option_column_width = "-h, --help".len();
        if path.is_empty() && root.version.is_some() {
            option_column_width = option_column_width.max("-V, --version".len());
        }
        for arg in
            ArgIter::new(args).filter(|arg| matches!(arg.kind, ArgKind::Option | ArgKind::Flag))
        {
            option_column_width = option_column_width.max(arg_label_width(arg));
        }
        if include_globals {
            for arg in ArgIter::new(root.args)
                .filter(|arg| arg.global && matches!(arg.kind, ArgKind::Option | ArgKind::Flag))
            {
                option_column_width = option_column_width.max(arg_label_width(arg));
            }
        }

        for arg in
            ArgIter::new(args).filter(|arg| matches!(arg.kind, ArgKind::Option | ArgKind::Flag))
        {
            write_arg(out, arg, option_column_width).await?;
        }
        if include_globals {
            for arg in ArgIter::new(root.args)
                .filter(|arg| arg.global && matches!(arg.kind, ArgKind::Option | ArgKind::Flag))
            {
                write_arg(out, arg, option_column_width).await?;
            }
        }
        write_str(out, "  -h, --help").await?;
        write_column_gap(out, "-h, --help".len(), option_column_width).await?;
        write_line(out, "Print help").await?;
        if path.is_empty() && root.version.is_some() {
            write_str(out, "  -V, --version").await?;
            write_column_gap(out, "-V, --version".len(), option_column_width).await?;
            write_line(out, "Print version").await?;
        }
    }
    Ok(())
}
