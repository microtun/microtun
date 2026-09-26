use std::{process::ExitCode, time::Duration};

use clap::Parser;

#[cfg(target_os = "linux")]
mod cuse;
#[cfg(target_os = "linux")]
mod serial;

const DEFAULT_SERIAL_PORT: u16 = 2217;

#[derive(Parser)]
#[command(
    name = "microtun-serial",
    version,
    about = "Expose a serial server as a Linux character device",
    arg_required_else_help = true
)]
struct Cli {
    /// Device IP address or hostname.
    #[arg(value_name = "TARGET")]
    target: String,

    /// Local character-device name. The device is created as /dev/NAME.
    #[arg(short = 'n', long, value_name = "NAME", default_value = "microtun0")]
    name: String,

    /// Serial TCP port. Defaults to 2217.
    #[arg(short, long, default_value_t = DEFAULT_SERIAL_PORT)]
    port: u16,

    /// Connect and serial negotiation timeout in seconds.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..))]
    timeout: u64,

    /// Print serial confirmations, modem state, and line state changes.
    #[arg(short, long)]
    verbose: bool,
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
    #[cfg(target_os = "linux")]
    {
        eprintln!(
            "connecting to {} on port {} (serial-device mode)",
            cli.target, cli.port
        );
        return serial::run_device(
            &cli.target,
            cli.port,
            Duration::from_secs(cli.timeout),
            &cli.name,
            cli.verbose,
        )
        .await;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = cli;
        Err("microtun-serial requires Linux CUSE support".to_owned())
    }
}
