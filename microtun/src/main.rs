use std::process::ExitCode;

use clap::Parser;

mod cli;
mod commands;
mod logging;

#[tokio::main]
async fn main() -> ExitCode {
    logging::install_panic_hook();

    match cli::Cli::parse().command {
        cli::Command::Tunnel(args) => commands::tunnel::execute(args).await,
        cli::Command::Tracker(args) => commands::tracker::execute(args).await,
        cli::Command::Console(args) => commands::console::execute(args).await,
        cli::Command::Serial(args) => commands::serial::execute(args).await,
    }
}
