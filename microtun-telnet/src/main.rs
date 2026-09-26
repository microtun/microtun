use std::{
    io::{self, IsTerminal},
    process::ExitCode,
    time::Duration,
};

use clap::Parser;

mod keymap;
mod telnet;
mod tui;
mod upload;

use telnet::TelnetClient;

const DEFAULT_TELNET_PORT: u16 = 23;

#[derive(Parser)]
#[command(
    name = "microtun-telnet",
    version,
    about = "Interactive Telnet and serial-console client with YMODEM",
    arg_required_else_help = true
)]
struct Cli {
    /// Device IP address or hostname.
    #[arg(value_name = "TARGET")]
    target: String,

    /// TCP port. Defaults to 23.
    #[arg(short, long, default_value_t = DEFAULT_TELNET_PORT)]
    port: u16,

    /// Telnet connect/read and YMODEM transfer timeout in seconds.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..))]
    timeout: u64,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("microtun-telnet requires an interactive terminal".to_owned());
    }

    let timeout = Duration::from_secs(cli.timeout);

    eprintln!("connecting to {} on port {}", cli.target, cli.port);
    let client = TelnetClient::connect(&cli.target, cli.port, timeout).await?;
    tui::run_session(client, &cli.target, cli.port).await
}
