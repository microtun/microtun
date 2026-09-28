use clap::{Parser, Subcommand};

use crate::commands::{console, serial, tracker, tunnel};

#[derive(Debug, Parser)]
#[command(
    name = "microtun",
    version,
    about = "Microtun host tools",
    arg_required_else_help = true,
    propagate_version = true
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Run a microtun tunnel on a Linux TUN interface.
    #[command(alias = "run")]
    Tunnel(tunnel::Args),

    /// Serve the Peers API and tracker tunnel endpoint.
    Tracker(tracker::Args),

    /// Open an interactive Telnet/serial console with YMODEM support.
    Console(console::Args),

    /// Expose a remote serial endpoint as a Linux character device.
    Serial(serial::Args),
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::{Cli, Command};

    #[test]
    fn exposes_all_host_tools_as_subcommands() {
        let command = Cli::command();
        let names = command
            .get_subcommands()
            .map(|subcommand| subcommand.get_name())
            .collect::<Vec<_>>();

        assert_eq!(names, vec!["tunnel", "tracker", "console", "serial"]);
    }

    #[test]
    fn run_alias_selects_tunnel() {
        let cli = Cli::try_parse_from(["microtun", "run", "device.toml"]).unwrap();
        assert!(matches!(cli.command, Command::Tunnel(_)));
    }
}
