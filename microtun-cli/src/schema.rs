#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueSpec {
    pub name: &'static str,
    pub help: &'static str,
    /// Hidden aliases accepted by parsing but not shown in help/completion.
    pub aliases: &'static [&'static str],
    /// Aliases accepted by parsing and exposed in help/completion.
    pub visible_aliases: &'static [&'static str],
}

impl ValueSpec {
    /// Field defaults for struct-update syntax.
    ///
    /// Generated code builds every spec as `ValueSpec { name, .. ValueSpec::DEFAULT }` so that
    /// adding a field to this struct is not a breaking change for downstream crates.
    pub const DEFAULT: Self = Self {
        name: "",
        help: "",
        aliases: &[],
        visible_aliases: &[],
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgAction {
    Set,
    SetTrue,
    SetFalse,
    Count,
    Append,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgKind {
    Positional,
    Option,
    Flag,
    Flatten,
}

#[derive(Clone, Copy, Debug)]
pub struct ArgSpec {
    pub name: &'static str,
    pub help: &'static str,
    pub short: Option<char>,
    pub long: Option<&'static str>,
    /// Hidden long aliases accepted by parsing but not shown in help/completion.
    pub aliases: &'static [&'static str],
    /// Long aliases accepted by parsing and exposed in help/completion.
    pub visible_aliases: &'static [&'static str],
    pub value_name: &'static str,
    pub required: bool,
    pub global: bool,
    /// A statically truthful default representation. Dynamic/default expressions are omitted.
    pub default: Option<&'static str>,
    pub kind: ArgKind,
    pub action: ArgAction,
    /// Accept values that begin with `-` for this option.
    pub allow_hyphen_values: bool,
    pub values: &'static [ValueSpec],
    pub children: &'static [ArgSpec],
}

impl ArgSpec {
    /// Field defaults for struct-update syntax.
    ///
    /// Generated code builds every spec as `ArgSpec { name, .. ArgSpec::DEFAULT }` so that adding
    /// a field to this struct is not a breaking change for downstream crates.
    pub const DEFAULT: Self = Self {
        name: "",
        help: "",
        short: None,
        long: None,
        aliases: &[],
        visible_aliases: &[],
        value_name: "",
        required: false,
        global: false,
        default: None,
        kind: ArgKind::Positional,
        action: ArgAction::Set,
        allow_hyphen_values: false,
        values: &[],
        children: &[],
    };

    pub const fn positional(
        name: &'static str,
        help: &'static str,
        value_name: &'static str,
        required: bool,
        values: &'static [ValueSpec],
    ) -> Self {
        Self {
            name,
            help,
            value_name,
            required,
            values,
            ..Self::DEFAULT
        }
    }

    /// Whether this argument takes a separate value token.
    pub const fn takes_value(&self) -> bool {
        matches!(self.kind, ArgKind::Option)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CommandSpec {
    pub name: &'static str,
    pub about: &'static str,
    /// Hidden aliases accepted by parsing but not shown in help/completion.
    pub aliases: &'static [&'static str],
    /// Aliases accepted by parsing and exposed in help/completion.
    pub visible_aliases: &'static [&'static str],
    pub args: &'static [ArgSpec],
    pub subcommands: &'static [CommandSpec],
    /// Marks a `#[command(flatten)]` group rather than a command of its own.
    ///
    /// A flattened entry contributes no name of its own: its [`subcommands`](Self::subcommands)
    /// are spliced into the parent's command list wherever commands are looked up, listed, or
    /// completed. `name`, `about`, and `args` are unused on a flattened entry.
    ///
    /// Splicing happens at walk time rather than in the generated const, because concatenating
    /// `&'static [CommandSpec]` of statically unknown length is not expressible in a const
    /// initializer. This mirrors how [`ArgKind::Flatten`] already works for arguments.
    pub flatten: bool,
}

impl CommandSpec {
    /// Field defaults for struct-update syntax. See [`ArgSpec::DEFAULT`].
    pub const DEFAULT: Self = Self {
        name: "",
        about: "",
        aliases: &[],
        visible_aliases: &[],
        args: &[],
        subcommands: &[],
        flatten: false,
    };

    /// Whether `name` selects this command, including via any alias.
    pub fn matches(&self, name: &str) -> bool {
        !self.flatten
            && (self.name == name
                || self.aliases.contains(&name)
                || self.visible_aliases.contains(&name))
    }
}

/// Maximum depth of nested `#[command(flatten)]` groups that command walks descend into.
pub const MAX_COMMAND_FLATTEN_DEPTH: usize = 8;

/// Flattens `#[command(flatten)]` groups into a single left-to-right pass over commands.
///
/// Yields only real commands: flattened entries are transparently descended into and never
/// produced themselves. Nesting deeper than [`MAX_COMMAND_FLATTEN_DEPTH`] is skipped rather
/// than truncating the rest of the list, matching the argument-side behavior.
pub struct CommandIter {
    stack: heapless::Vec<(&'static [CommandSpec], usize), MAX_COMMAND_FLATTEN_DEPTH>,
}

impl CommandIter {
    pub fn new(commands: &'static [CommandSpec]) -> Self {
        let mut stack = heapless::Vec::new();
        let _ = stack.push((commands, 0));
        Self { stack }
    }
}

impl Iterator for CommandIter {
    type Item = &'static CommandSpec;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let (commands, index) = *self.stack.last()?;
            if index >= commands.len() {
                self.stack.pop();
                continue;
            }
            if let Some(top) = self.stack.last_mut() {
                top.1 = index + 1;
            }
            let command = &commands[index];
            if command.flatten {
                let _ = self.stack.push((command.subcommands, 0));
                continue;
            }
            return Some(command);
        }
    }
}

/// Look up a command by name or alias, descending through flattened groups.
pub fn find_command(commands: &'static [CommandSpec], name: &str) -> Option<&'static CommandSpec> {
    CommandIter::new(commands).find(|command| command.matches(name))
}

#[derive(Clone, Copy, Debug)]
pub struct RootSpec {
    pub name: &'static str,
    pub about: &'static str,
    pub version: Option<&'static str>,
    pub args: &'static [ArgSpec],
    pub commands: &'static [CommandSpec],
}

impl RootSpec {
    /// Field defaults for struct-update syntax. See [`ArgSpec::DEFAULT`].
    pub const DEFAULT: Self = Self {
        name: "",
        about: "",
        version: None,
        args: &[],
        commands: &[],
    };
}
